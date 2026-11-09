"""Fixture output assets bound to the original jumphost root and account."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import select
import stat

from management_service_diagnostics import private_json


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':')).encode()


class JumphostRoot:
    def __init__(self,worker):
        self.worker=worker
        self.owner,self.value=self.qualify()

    def qualify(self):
        w=self.worker;r=w.read()
        if r.get('phase')!='active' or r.get('inventory_operation'):
            raise RuntimeError('original active jumphost required for CLI')
        w.infrastructure(r);w.verify_extensions(r)
        with w.namespace(r) as fd:w.verify_attachment(r,fd)
        value=w.container(r);s=value['State']
        start=(Path('/proc')/str(s['Pid'])/'stat').read_text().rsplit(')',1)[1].split()[19]
        proof={k:deepcopy(r[k]) for k in ('container_id','nonce','config','image','context','namespace')}
        proof['process']={'pid':s['Pid'],'started_at':s['StartedAt'],'start':start,
                          'namespace':[r['namespace']['device'],r['namespace']['inode']]}
        return proof,value

    def observe(self):
        proof,value=self.qualify()
        if proof!=self.owner:raise RuntimeError('original jumphost root generation differs')
        ids=value.get('ExecIDs')
        return {'owner':deepcopy(proof),'exec_ids':[] if ids is None else ids}

    @contextmanager
    def open(self):
        self.observe();pid=self.owner['process']['pid'];pidfd=os.pidfd_open(pid);root=None
        try:
            poll=select.poll();poll.register(pidfd,select.POLLIN)
            if poll.poll(0):raise RuntimeError('original jumphost process exited')
            root=os.open('/proc/'+str(pid)+'/root',os.O_RDONLY|os.O_DIRECTORY)
            self.observe()
            if poll.poll(0):raise RuntimeError('original jumphost exited while opening root')
            yield root
            self.observe()
            if poll.poll(0):raise RuntimeError('original jumphost exited during asset operation')
        finally:
            if root is not None:os.close(root)
            os.close(pidfd)


@contextmanager
def directory(root,path):
    fd=os.dup(root)
    try:
        for part in Path(path).parts:
            if part in ('/',''):continue
            if part in ('.','..'):raise RuntimeError('CLI asset path differs')
            child=os.open(part,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW,dir_fd=fd)
            os.close(fd);fd=child;info=os.fstat(fd)
            if info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('CLI asset directory ownership differs')
        yield fd
    finally:os.close(fd)


def read_file(root,path,limit=1048576,*,append_only=False):
    with directory(root,Path(path).parent) as parent:
        fd=os.open(Path(path).name,os.O_RDONLY|os.O_NOFOLLOW,dir_fd=parent)
        with os.fdopen(fd,'rb') as stream:
            info=os.fstat(stream.fileno());raw=stream.read(limit+1);after=os.fstat(stream.fileno())
        identity=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,stat.S_IMODE(s.st_mode),s.st_nlink)
        if (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or len(raw)>limit
                or identity(info)!=identity(after) or after.st_size>limit
                or (after.st_size<info.st_size if append_only else
                    (info.st_size,info.st_mtime_ns,info.st_ctime_ns)!=(after.st_size,after.st_mtime_ns,after.st_ctime_ns))):
            raise RuntimeError('CLI asset read incomplete or changed')
        return info,raw


class Assets:
    def __init__(self,path,root,nonce,action,node,command,marker,*,readonly=False):
        self.path,self.root=Path(path),root
        if (not re.fullmatch('[0-9a-f]{32}',str(nonce)) or action not in ('connect','log')
                or not re.fullmatch('[A-Za-z0-9_.-]{1,128}',str(node))
                or not isinstance(command,bytes) or not command or len(command)>4096
                or not isinstance(marker,bytes) or not marker or marker in command):
            raise ValueError('original CLI asset intent required')
        owner=root.observe()['owner']
        with root.open() as fd:account=self.account(fd)
        intent={'owner':owner,'nonce':nonce,'action':action,'node':node,'command_hex':command.hex(),
                'marker_hex':marker.hex(),'output':'/run/dnlab-cli-'+nonce+'.jsonl','account':account}
        if self.path.exists():
            self.record=json.loads(self.path.read_text())
            if any(self.record.get(k)!=v for k,v in intent.items()):
                raise RuntimeError('original CLI asset intent differs')
        else:
            if readonly:raise RuntimeError('original CLI asset journal missing; recovery pending')
            self.record={**intent,'identity':None};private_json(self.path,self.record)

    def account(self,fd):
        info,raw=read_file(fd,'/etc/passwd',65536)
        if info.st_uid!=0 or info.st_mode&0o022:raise RuntimeError('CLI account file ownership differs')
        users=[line.split(':') for line in raw.decode().splitlines() if line.startswith('labuser:')]
        if (len(users)!=1 or len(users[0])!=7 or not users[0][2].isdigit() or not users[0][3].isdigit()
                or int(users[0][2])<=0 or int(users[0][3])<=0):
            raise RuntimeError('qualified non-root labuser account required')
        for source,target in (('vd','/usr/local/bin/vd'),('vd-relay-client','/usr/local/bin/vd-relay-client')):
            info,content=read_file(fd,target,131072)
            expected=(Path(__file__).resolve().parents[2]/'multinode/jumphost'/source).read_bytes()
            if (info.st_uid!=0 or info.st_gid!=0 or stat.S_IMODE(info.st_mode)!=0o755 or content!=expected):
                raise RuntimeError('candidate CLI asset differs from qualified source')
        return {'uid':int(users[0][2]),'gid':int(users[0][3]),'entry':users[0]}

    def birth(self):
        original={k:v for k,v in self.record.items() if k!='identity'}
        return encoded({'nonce':self.record['nonce'],'kind':'asset_birth',
                        'value':{'intent_sha256':hashlib.sha256(encoded(original)).hexdigest()}})+b'\n'

    def check(self,info,raw):
        r=self.record;identity=[info.st_dev,info.st_ino,info.st_uid,info.st_gid]
        if (stat.S_IMODE(info.st_mode)!=0o600 or identity[2:]!=[r['account']['uid'],r['account']['gid']]
                or not raw.startswith(self.birth()) or r['identity'] is not None and identity!=r['identity']):
            raise RuntimeError('original CLI output asset differs')
        return identity

    def prepare(self,*,readonly=False):
        r=self.record
        if readonly and r['identity'] is None:
            raise RuntimeError('original CLI asset birth unresolved; recovery pending')
        with self.root.open() as root:
            if self.root.observe()['owner']!=r['owner'] or self.account(root)!=r['account']:
                raise RuntimeError('CLI root or account changed')
            if r['identity'] is None:
                with directory(root,'/run') as parent:
                    try:fd=os.open(Path(r['output']).name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600,dir_fd=parent)
                    except FileExistsError:pass
                    else:
                        with os.fdopen(fd,'wb') as stream:
                            stream.write(self.birth());stream.flush()
                            os.fchown(stream.fileno(),r['account']['uid'],r['account']['gid']);os.fsync(stream.fileno())
                        os.fsync(parent)
                info,raw=read_file(root,r['output'])
                identity=self.check(info,raw)
                if raw!=self.birth():raise RuntimeError('unbound CLI output already contains execution evidence')
                r['identity']=identity;private_json(self.path,r)
            info,raw=read_file(root,r['output'],append_only=True);self.check(info,raw)
        return self.profile()

    def profile(self):
        if self.record['identity'] is None:raise RuntimeError('original CLI output birth not qualified')
        return {**{k:deepcopy(self.record[k]) for k in ('nonce','output','identity','action','node','command_hex','marker_hex')},
                'cli':'/usr/local/bin/vd','timeout':15}

    def observe(self,*,readonly=False):
        self.prepare(readonly=readonly)
        return self.root.observe()

    def result(self,execution,status,*,readonly=False):
        self.prepare(readonly=readonly);r=self.record
        if (execution['owner']!=r['owner'] or execution['nonce']!=r['nonce'] or status['Running']
                or status['ExitCode']!=0):raise RuntimeError('original CLI exec not successfully exited')
        with self.root.open() as root:info,raw=read_file(root,r['output']);self.check(info,raw)
        if not raw.endswith(b'\n'):raise RuntimeError('CLI output journal is incomplete')
        events=[json.loads(line) for line in raw.splitlines()]
        body=events[1:]
        if (len(body)<3 or [v.get('kind') for v in body[:2]]!=['wrapper_birth','client_birth']
                or body[-1].get('kind')!='completed'
                or any(set(v)!={'nonce','kind','value'} or v['nonce']!=r['nonce'] for v in body)
                or any(v['kind']!='progress' for v in body[2:-1])):
            raise RuntimeError('CLI progress history differs')
        for event in body[:2]:
            birth=event['value']
            if (type(birth.get('pid')) is not int or birth['pid']<=0
                    or not str(birth.get('start','')).isdigit()
                    or birth.get('namespace')!=r['owner']['process']['namespace']):
                raise RuntimeError('CLI process namespace proof differs')
        result=body[-1]['value'];output=bytes.fromhex(result.get('output_hex',''))
        previous={'stdout_bytes':0,'stderr_bytes':0,'marker_seen':False,'input_closed':False,'exit_code':None}
        saw_open_marker=False
        for event in body[2:-1]:
            row=event['value']
            if (not isinstance(row,dict) or set(row)!=set(previous)
                    or any(type(row[k]) is not int or row[k]<previous[k] for k in ('stdout_bytes','stderr_bytes'))
                    or row['stdout_bytes']+row['stderr_bytes']>131072
                    or any(type(row[k]) is not bool or previous[k] and not row[k] for k in ('marker_seen','input_closed'))
                    or row['input_closed'] and not saw_open_marker
                    or row['exit_code'] is not None and type(row['exit_code']) is not int):
                raise RuntimeError('CLI progress sequence differs')
            if row['marker_seen'] and not row['input_closed']:saw_open_marker=True
            previous=row
        if (set(result)!={'nonce','exit_verified','exit_code','marker_seen_before_input_close','output_hex'}
                or not saw_open_marker or not previous['input_closed'] or previous['exit_code']!=0
                or previous['stdout_bytes']!=len(output) or previous['stderr_bytes']!=0
                or result.get('nonce')!=r['nonce'] or result.get('exit_verified') is not True
                or type(result.get('exit_code')) is not int or result['exit_code']!=0
                or result.get('marker_seen_before_input_close') is not True
                or bytes.fromhex(r['marker_hex']) not in output or output.startswith(b'ERR ')):
            raise RuntimeError('CLI response and exit proof differ')
        captured={'raw_hex':raw.hex(),'sha256':hashlib.sha256(raw).hexdigest(),
                  'identity':deepcopy(r['identity']),'nonce':r['nonce']}
        path=self.path.with_suffix('.output.json')
        if path.exists():
            if json.loads(path.read_text())!=captured:raise RuntimeError('original captured CLI journal differs')
        else:
            if readonly:raise RuntimeError('original captured CLI journal missing; recovery pending')
            private_json(path,captured)
        return {**deepcopy(result),'journal_sha256':captured['sha256']}
