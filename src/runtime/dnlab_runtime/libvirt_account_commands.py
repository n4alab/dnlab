"""Tracked account command helper; execution requires an injected gated runner.

A runner must arm a non-mutating worker, qualify its original process record,
and execute only after release. No default subprocess runner or host inspector
is supplied, so importing/constructing this helper cannot create host accounts.
"""
from copy import deepcopy
import json
import re

from .libvirt_provisioning import account_marker
from .manifest import Conflict, canonical, fingerprint


def command_plan(request,binaries):
    if (set(request)!={'intent_id','nonce','spec_sha256','kind','expected'}
            or request['kind'] not in ('group','account')
            or not re.fullmatch(r'[0-9a-f]{32}',request['nonce'])
            or not re.fullmatch(r'[0-9a-f]{64}',request['spec_sha256'])):
        raise Conflict('qualified account command request required')
    expected=request['expected'];kind=request['kind']
    fields={'name','gid'} if kind=='group' else {'name','uid','gid','home','shell','locked','comment'}
    if (set(expected)!=fields or not re.fullmatch(r'[a-z_][a-z0-9_-]{0,31}',expected['name'])
            or expected['name']=='root' or type(expected['gid']) is not int or not 0<expected['gid']<2**31):
        raise Conflict('dedicated account/group command identity required')
    role='groupadd' if kind=='group' else 'useradd'
    binary=binaries[role]
    if set(binary)!={'path','sha256'} or binary['path']!='/usr/sbin/'+role or not re.fullmatch(r'[0-9a-f]{64}',binary['sha256']):
        raise Conflict('original account executable proof required')
    if kind=='group':argv=[binary['path'],'--system','--gid',str(expected['gid']),'--',expected['name']]
    else:
        if (type(expected['uid']) is not int or not 0<expected['uid']<2**31
                or not re.fullmatch(r'/[A-Za-z0-9_./-]+',expected['home'])
                or '..' in expected['home'].split('/') or expected['shell']!='/usr/sbin/nologin'
                or expected['locked'] is not True
                or expected['comment']!=account_marker(request['intent_id'],request['nonce'])):
            raise Conflict('locked noninteractive account command required')
        argv=[binary['path'],'--system','--uid',str(expected['uid']),'--gid',str(expected['gid']),
            '--home-dir',expected['home'],'--no-create-home','--no-user-group','--no-log-init',
            '--groups','','--shell',expected['shell'],'--password','!',
            '--comment',expected['comment'],'--',expected['name']]
    return dict(request_sha256=fingerprint(request),binary=deepcopy(binary),argv=argv,
        environment={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','HOME':'/','LANG':'C','LC_ALL':'C'})


def reference_proof(reference,command):
    if (not isinstance(reference,dict) or set(reference)!={'token','command_sha256','process_record'}
            or not re.fullmatch(r'[0-9a-f]{32}',reference['token'])
            or reference['command_sha256']!=fingerprint(command)):
        raise Conflict('original armed account worker reference differs')
    process=reference['process_record']
    if (not isinstance(process,dict) or set(process)!={'boot_id','pid','start_ticks','uid','gid','executable_sha256','namespace_sha256'}
            or not isinstance(process['boot_id'],str) or not process['boot_id']
            or any(type(process[k]) is not int or process[k]<=0 for k in ('pid','start_ticks'))
            or type(process['uid']) is not int or process['uid']!=0
            or type(process['gid']) is not int or process['gid']!=0
            or any(not re.fullmatch(r'[0-9a-f]{64}',process[k]) for k in ('executable_sha256','namespace_sha256'))):
        raise Conflict('complete original privileged worker process proof required')


class AccountCommandHelper:
    def __init__(self,journal,*,binaries,runner,inspect,preflight):
        self.journal,self.binaries,self.runner=journal,deepcopy(binaries),runner
        self.inspect,self.preflight=inspect,preflight
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_account_commands '
                '(request_sha256 TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _read(self,request):
        key=fingerprint(request)
        with self.journal.lock:
            row=self.journal.db.execute('SELECT * FROM libvirt_account_commands WHERE request_sha256=?',(key,)).fetchone()
        if row is None:return None
        value=json.loads(row['payload'])
        if (fingerprint(value)!=row['fingerprint'] or value['request']!=request
                or value['command']!=command_plan(request,self.binaries)
                or value['phase'] not in ('arming_requested','armed','release_requested','completed')):
            raise Conflict('original account command journal differs')
        if value['reference'] is not None:reference_proof(value['reference'],value['command'])
        return value

    def _save(self,value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_account_commands SET payload=?,fingerprint=? WHERE request_sha256=?',
                (canonical(value),fingerprint(value),fingerprint(value['request'])))

    def _check(self,value):
        observed=self.preflight(deepcopy(value['command']))
        if observed!=value['preflight']:raise Conflict('account command preflight changed')

    def _outcome(self,value):
        reference=value['reference']
        if reference is None:return None
        reference_proof(reference,value['command'])
        if self.runner.verify(deepcopy(reference),deepcopy(value['command'])) is not True:
            raise Conflict('original account worker verification failed')
        result=self.runner.outcome(deepcopy(reference))
        if result is None:return None
        if (not isinstance(result,dict) or set(result)!={'reference','exit_code','stdout','stderr'}
                or result['reference']!=reference or type(result['exit_code']) is not int
                or any(not isinstance(result[k],str) or len(result[k].encode())>65536 for k in ('stdout','stderr'))):
            raise Conflict('original account command outcome differs')
        return result

    def preflight_completion(self,request):
        """Qualify committed worker evidence without recursive host preflight."""
        with self.journal.execution_lock:
            value=self._read(request)
            if value is None or value['phase'] not in ('release_requested','completed'):return None
            read=getattr(self.runner,'completed_outcome',None)
            if not callable(read):raise Conflict('readonly original worker completion reader required')
            result=read(deepcopy(value['reference']))
            if result is None:return None
            if (not isinstance(result,dict) or set(result)!={'reference','exit_code','stdout','stderr'}
                    or result['reference']!=value['reference'] or type(result['exit_code']) is not int
                    or result['exit_code']!=0
                    or any(not isinstance(result[k],str) or len(result[k].encode())>65536 for k in ('stdout','stderr'))
                    or value['phase']=='completed' and result!=value['outcome']):
                raise Conflict('readonly original account completion differs')
            return dict(request_sha256=fingerprint(request),exit_code=0,identity=deepcopy(request['expected']))

    def completion(self,request):
        with self.journal.execution_lock:
            value=self._read(request)
            if value is None or value['phase'] not in ('release_requested','completed'):return None
            self._check(value)
            result=self._outcome(value)
            if result is None or result['exit_code']!=0:return None
            if value['phase']=='completed' and result!=value['outcome']:
                raise Conflict('original account command completion replaced')
            if self.inspect(deepcopy(request))!=request['expected']:
                raise Conflict('completed account command resource differs')
            self._check(value)
            return dict(request_sha256=fingerprint(request),exit_code=0,identity=deepcopy(request['expected']))

    def create(self,request):
        with self.journal.execution_lock:
            if self._read(request) is not None:raise Conflict('account command already tracked; no automatic execution retry')
            command=command_plan(request,self.binaries)
            observed=self.preflight(deepcopy(command))
            if (not isinstance(observed,dict) or set(observed)!={'qualified','command_sha256','context_sha256','inputs_sha256'}
                    or observed['qualified'] is not True or observed['command_sha256']!=fingerprint(command)
                    or any(not re.fullmatch(r'[0-9a-f]{64}',observed[k]) for k in ('context_sha256','inputs_sha256'))):
                raise Conflict('qualified account executable/context/config preflight required')
            if self.inspect(deepcopy(request)) is not None:raise Conflict('account command target occupied')
            value=dict(request=deepcopy(request),command=command,preflight=deepcopy(observed),
                phase='arming_requested',reference=None,outcome=None)
            with self.journal.transaction():
                self.journal.db.execute('INSERT INTO libvirt_account_commands VALUES(?,?,?)',
                    (fingerprint(request),canonical(value),fingerprint(value)))
            self._check(value)
            reference=self.runner.arm(deepcopy(command))
            reference_proof(reference,command)
            value.update(reference=deepcopy(reference),phase='armed');self._save(value)
            self._check(value)
            if self.inspect(deepcopy(request)) is not None:raise Conflict('account target changed before release')
            value['phase']='release_requested';self._save(value)
            # Recheck after the release intent is durable. No uncertain release
            # is ever repeated; only the original runner outcome may complete it.
            self._check(value)
            if self.inspect(deepcopy(request)) is not None:raise Conflict('account target changed at release boundary')
            if self.runner.verify(deepcopy(reference),deepcopy(command)) is not True:
                raise Conflict('original account worker verification failed')
            self.runner.release(deepcopy(reference))
            result=self._outcome(value)
            if result is None:raise Conflict('account command outcome pending; execution is not repeated')
            if result['exit_code']!=0:raise Conflict('account command failed; original output retained by runner')
            if self.inspect(deepcopy(request))!=request['expected']:raise Conflict('created account identity differs')
            value.update(phase='completed',outcome=result);self._save(value)
            return self.completion(request)
