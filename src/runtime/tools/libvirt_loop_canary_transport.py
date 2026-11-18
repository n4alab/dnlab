"""Original-process protocol for the isolated loop-only canary.

The native launcher, pinned interpreter/source FDs and frame I/O are explicit
providers. Import/tests never spawn. A child waits for a qualified release before
SDK dispatch, then waits for EOF after its report. The parent owns the original
Popen/pidfd observer until exit. No signals, reconnect or second launch on retry.
"""
from copy import deepcopy
import json

from dnlab_runtime.libvirt_account_runner import ready_line, collect_output
from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_template import digest, fields, require
from libvirt_event_loop_canary import run as run_loop


def serve(request, runtime, sdk, *, preflight, read_frame, write_frame, runner=run_loop):
    """Bootstrap for a dedicated original child; no process is started here."""
    fields(request,('nonce','command'),'loop-only request')
    request_sha256=fingerprint(request)
    write_frame(dict(ready=request['nonce'],request_sha256=request_sha256))
    release=read_frame()
    require(release==dict(release=request['nonce'],request_sha256=request_sha256),
            'original parent release required before any loop SDK action')
    result=runner(runtime,sdk,preflight=preflight)
    write_frame(dict(result=result,epoch=runtime.check(),request_sha256=request_sha256))
    require(read_frame() is None, 'original parent EOF required after loop report')
    return 0


class LoopCanaryParent:
    def __init__(self,journal,*,observer,spawn,preflight,read_frame=ready_line,read_output=collect_output):
        require(all(callable(fn) for fn in (spawn,preflight,read_frame,read_output)), 'qualified canary launcher and preflight required')
        self.journal,self.observer,self.spawn,self.preflight,self.read_frame=journal,observer,spawn,preflight,read_frame
        self.read_output=read_output
        self.output_state=dict(stdout=b'',stderr=b'',eof=set());self.output_receipt=None
        self.process,self.reference,self.request=None,None,None
        with journal.transaction():
            journal.db.execute('CREATE TABLE IF NOT EXISTS libvirt_loop_canary_parents '
                '(id TEXT PRIMARY KEY,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    def _save(self,value):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE libvirt_loop_canary_parents SET payload=?,fingerprint=? WHERE id=?',
                (canonical(value),fingerprint(value),value['id']))

    def _read(self):
        require(self.request is not None, 'original parent instance and waiter required')
        row=self.journal.db.execute('SELECT * FROM libvirt_loop_canary_parents WHERE id=?',(self.request['nonce'],)).fetchone()
        require(row is not None, 'original canary parent intent missing')
        value=json.loads(row['payload'])
        require(value['request']==self.request and row['fingerprint']==fingerprint(value), 'original parent journal differs')
        return value

    def _check(self):
        require(self.preflight(deepcopy(self.request))==fingerprint(self.request), 'original launcher/source scope differs')

    def _verify(self):
        self._check()
        require(self.process is not None and self.reference is not None
                and self.observer.verify(self.reference,self.process,self.request['command'],'armed') is True,
                'original live canary process required')

    def _exit(self,value):
        """Original waiter only; preserve a pending handle on timeout."""
        require(self.process is not None and self.reference is not None and self.process.stdin.closed,
                'original EOF and process waiter required for exit observation')
        self._check()
        status=self.process.wait(timeout=10)
        require(type(status) is int and self.observer.exit(self.process,self.reference) is True,
                'original canary pidfd exit proof required')
        if self.output_receipt is None:self.output_receipt=self.read_output(self.process,self.output_state)
        require(self.output_receipt is not None and self.output_receipt['exit_code']==status,
                'original bounded child output incomplete')
        value.update(exit_code=status,cleanup_verified=True,output=deepcopy(self.output_receipt))
        if self.output_receipt['stdout']:
            value['error']=dict(type='ProtocolError',message='unexpected child output after final report')
        if value['report'] is not None and value['error'] is None and status==0:
            value.update(phase='completed',qualified=True)
        else:value.update(phase='failed',qualified=False)
        self._save(value)
        for stream in (self.process.stdout,self.process.stderr):stream.close()
        self.observer.retire(self.reference)
        return deepcopy(value)

    def run(self,request):
        with self.journal.execution_lock:
            require(self.request is None, 'original parent attempt cannot be replaced')
            return self._run(request)

    def _run(self,request):
        fields(request,('nonce','command'),'loop-only parent request')
        require(isinstance(request['nonce'],str) and len(request['nonce'])==32
                and all(c in '0123456789abcdef' for c in request['nonce']), 'original canary nonce required')
        command=request['command']
        fields(command,('binary','argv','environment'),'fixed canary command')
        fields(command['binary'],('path','sha256'),'original canary interpreter')
        require(digest(command['binary']['sha256']) and command['binary']['path'].startswith('/')
                and type(command['argv']) is list and command['argv'][:4]==[command['binary']['path'],'-B','-I','-S']
                and all(isinstance(v,str) and '\0' not in v for v in command['argv'])
                and command['environment']==dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LANG='C',LC_ALL='C',LIBVIRT_AUTOSTART='0'),
                'isolated fixed interpreter invocation required')
        self.request=deepcopy(request);self._check()
        value=dict(id=request['nonce'],request=deepcopy(request),phase='prepared',reference=None,
               report=None,qualified=False,cleanup_verified=False,exit_code=None,error=None,output=None)
        with self.journal.transaction():
            require(self.journal.db.execute('SELECT 1 FROM libvirt_loop_canary_parents').fetchone() is None,
                    'parent journal is one-shot; no replacement launch')
            self.journal.db.execute('INSERT INTO libvirt_loop_canary_parents VALUES(?,?,?)',
                (value['id'],canonical(value),fingerprint(value)))
        primary=None
        try:
            value['phase']='launch_requested';self._save(value);self._check()
            self.process=self.spawn(deepcopy(command))
            require(list(self.process.args)==command['argv'], 'original launched argv differs')
            record=self.observer.capture(self.process)
            require(record['pid']==self.process.pid and record['executable_sha256']==command['binary']['sha256'],
                    'original canary interpreter/process differs')
            self.reference=dict(token=request['nonce'],command_sha256=fingerprint(command),process_record=record)
            self.observer.bind(self.reference,self.process,command)
            value.update(phase='armed',reference=deepcopy(self.reference));self._save(value);self._verify()
            ready=self.read_frame(self.process)
            require(ready==dict(ready=request['nonce'],request_sha256=fingerprint(request)), 'original child readiness differs')
            value['phase']='release_requested';self._save(value);self._verify()
            frame=canonical(dict(release=request['nonce'],request_sha256=fingerprint(request)))+'\n'
            self.process.stdin.write(frame.encode());self.process.stdin.flush()
            value['phase']='released';self._save(value)
            report=self.read_frame(self.process)
            fields(report,('result','epoch','request_sha256'),'loop child report')
            result=report['result']
            require(report['request_sha256']==fingerprint(request) and result['phase']=='awaiting_process_exit'
                    and result['qualified'] is True and result['cleanup_verified'] is False
                    and result['requires_original_process_exit'] is True and result['gate_allowed'] is False
                    and result['epoch_sha256']==fingerprint(report['epoch'])
                    and report['epoch']['snapshot']['record']==record, 'original loop result/process differs')
            self._verify();value.update(phase='eof_requested',report=deepcopy(report));self._save(value);self._verify()
            self.process.stdin.close()
            return self._exit(value)
        except BaseException as error:
            primary=error;value.update(phase='pending',qualified=False,error=dict(type=type(error).__name__,message=str(error)))
            self._save(value)
            raise
        finally:
            # No signal and no fallback process. EOF is the only child control
            # after an error. A timeout retains the waiter/pidfd for recover_exit.
            errors=[]
            if self.process is not None:
                if not self.process.stdin.closed:
                    try:self.process.stdin.close()
                    except Exception as error:errors.append(error)
                if not value['cleanup_verified'] and self.reference is not None and self.process.stdin.closed:
                    try:self._exit(value)
                    except Exception as error:errors.append(error)
                # A pending original waiter retains its streams and pidfd so
                # recover_exit can collect the original diagnostics, not a new process.
            if errors:
                value.update(phase='pending',qualified=False,cleanup_verified=False,
                             cleanup_errors=[dict(type=type(e).__name__,message=str(e)) for e in errors])
                self._save(value)
                if primary is not None:
                    for error in errors:primary.add_note('canary cleanup also failed: '+str(error))
                else:raise errors[0]

    def recover_exit(self):
        with self.journal.execution_lock:
            value=self._read()
            require(value['phase']=='pending' and not value['cleanup_verified'], 'original pending exit required')
            return self._exit(value)
