"""Owned packet execution in a qualified probe container.

Create/exec identities are durable before start. The child waits for a qualified
permit, appends fsynced progress, and cannot be restarted after an uncertain start.
"""
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import time

try:
    JumphostError
except NameError:
    from .jumphost_host import JumphostError,canonical,digest
    from .management_packet_receipt import validate as validate_packet_result,validate_progress,expected_progress


CLIENT = r'''
import hashlib,json,os,stat,sys,time
SOURCE=__SOURCE__
PROFILE=__PROFILE__
NONCE=__NONCE__
REQUEST=__REQUEST__
fd=os.open('/run/dnlab-probe.jsonl',os.O_RDWR|os.O_APPEND|os.O_NOFOLLOW)
info=os.fstat(fd)
if (not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or stat.S_IMODE(info.st_mode)!=0o600
    or info.st_nlink!=1 or [info.st_dev,info.st_ino]!=[int(sys.argv[2]),int(sys.argv[3])]
    or sys.argv[1]!=NONCE):raise RuntimeError('probe output generation differs')
def emit(kind,value):
    raw=(json.dumps({'nonce':NONCE,'request':REQUEST,'kind':kind,'value':value},sort_keys=True,separators=(',',':'))+'\n').encode()
    if len(raw)>32768:raise RuntimeError('probe evidence too large')
    view=memoryview(raw)
    while view:
        count=os.write(fd,view)
        if not count:raise RuntimeError('probe evidence write made no progress')
        view=view[count:]
    os.fsync(fd)
try:
    ns=os.stat('/proc/self/ns/net')
    birth={'pid':os.getpid(),'start':open('/proc/self/stat').read().rsplit(')',1)[1].split()[19],
           'namespace':{'device':ns.st_dev,'inode':ns.st_ino}}
    emit('birth',birth)
    deadline=time.monotonic()+60
    while True:
        raw=os.pread(fd,131073,0)
        if len(raw)>131072:raise RuntimeError('probe evidence limit exceeded')
        records=[json.loads(line) for line in raw.splitlines() if line]
        if any(row.get('nonce')!=NONCE or row.get('request')!=REQUEST for row in records):raise RuntimeError('probe evidence binding differs')
        permits=[row for row in records if row['kind']=='permit']
        if permits:
            if len(permits)!=1 or permits[0]['value']!=birth:raise RuntimeError('probe permit generation differs')
            break
        if time.monotonic()>=deadline:raise RuntimeError('probe permit unresolved')
        time.sleep(.05)
    scope={'__name__':'_packet_client'};exec(SOURCE,scope)
    result=scope['run'](PROFILE,progress=lambda stage,value:emit('progress',{'stage':stage,'result':value}))
    emit('completed',result)
except Exception as error:
    emit('failed',{'type':type(error).__name__,'message':str(error)[:1000]})
    sys.exit(1)
finally:os.close(fd)
'''


def probe_binds(actual,expected):
    if actual is None:actual=[]
    return isinstance(actual,list) and all(isinstance(v,str) for v in actual) and len(actual)==len(expected) and set(actual)==set(expected)


def file_identity(info):
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid() or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1:
        raise JumphostError('probe execution asset ownership differs')
    return {'device':info.st_dev,'inode':info.st_ino}


def sync_parent(path):
    fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
    try:os.fsync(fd)
    finally:os.close(fd)


def prepare_assets(worker,record,packet_source):
    if ':' in str(worker.directory):raise JumphostError('probe asset path cannot contain colon')
    op=record.get('packet_execution')
    if op is None:
        if record.get('packet_phase'):
            raise JumphostError('legacy packet execution requires qualified recovery')
        nonce=digest(['probe-exec-v1',worker.key,record['nonce']])[:32]
        source=CLIENT.replace('__SOURCE__',repr(packet_source)).replace('__PROFILE__',repr(worker.request['packet_profile']))
        source=source.replace('__NONCE__',repr(nonce)).replace('__REQUEST__',repr(digest(worker.request)))
        op={'nonce':nonce,'source':source,'files':{},'create_attempted':False,'start_attempted':False,'id':None,
            'phase':'intent','exit_verified':False,'observations':[],'create_calls':0,'start_calls':0}
        record['packet_execution']=op;worker.save(record)
    for name,content in (('program',op['source'].encode()),('output',b'')):
        path=worker.directory/(worker.key+'-'+record['nonce']+'.probe-'+name)
        try:fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
        except FileExistsError:
            fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:
                identity=file_identity(os.fstat(stream.fileno()));raw=stream.read(131073)
            if name in op['files']:
                if identity!=op['files'][name]['identity']:raise JumphostError('probe execution asset generation replaced')
            elif raw!=content:raise JumphostError('unbound probe execution asset differs')
            if name=='program' and raw!=content:raise JumphostError('probe execution code differs')
        else:
            with os.fdopen(fd,'wb') as stream:
                stream.write(content);stream.flush();os.fsync(stream.fileno());identity=file_identity(os.fstat(stream.fileno()))
            sync_parent(worker.directory)
        if name not in op['files']:
            op['files'][name]={'path':str(path),'identity':identity};worker.save(record)
    return op


def execution_identity(record):
    op=record.get('packet_execution')
    if not op or not op['id']:return None
    output=op['files']['output']['identity']
    command=['python3','-I','/opt/dnlab-probe.py',op['nonce'],str(output['device']),str(output['inode'])]
    return {'id':op['id'],'nonce':op['nonce'],'container_id':record['container_id'],'command_sha256':digest(command)}


class Execution:
    WAIT_SECONDS=45
    def __init__(self,worker,record):
        self.w=worker;self.r=record;self.op=record.get('packet_execution')
        if not self.op:raise JumphostError('original packet exec intent required')
        expected=digest(['probe-exec-v1',worker.key,record['nonce']])[:32]
        if self.op['nonce']!=expected:raise JumphostError('packet exec nonce differs')
        output=self.op['files']['output']['identity']
        self.command=['python3','-I','/opt/dnlab-probe.py',self.op['nonce'],str(output['device']),str(output['inode'])]

    def identity(self):
        return execution_identity(self.r)

    def assets(self):
        for name,row in self.op['files'].items():
            expected=self.w.directory/(self.w.key+'-'+self.r['nonce']+'.probe-'+name)
            if row['path']!=str(expected):raise JumphostError('packet exec asset path differs')
            fd=os.open(expected,os.O_RDONLY|os.O_NOFOLLOW)
            with os.fdopen(fd,'rb') as stream:
                if file_identity(os.fstat(stream.fileno()))!=row['identity']:raise JumphostError('packet exec asset replaced')
                data=stream.read(131073)
            if len(data)>131072 or name=='program' and data!=self.op['source'].encode():raise JumphostError('packet exec asset content differs')

    def original(self,*,endpoint=True):
        self.w.infrastructure(self.r);value=self.w.container(self.r)
        self.assets()
        if not value or not value['State']['Running']:raise JumphostError('original active probe required for exec')
        with self.w.namespace(self.r) as fd:
            if endpoint:self.w.packet_endpoint(self.r,fd)
        ids=value.get('ExecIDs');ids=[] if ids is None else ids
        if not isinstance(ids,list) or any(not isinstance(v,str) or not re.fullmatch('[0-9a-f]{64}',v) for v in ids):
            raise JumphostError('invalid probe exec inventory')
        return ids

    def inspect(self,identity):
        value=self.w.docker.call('GET','/exec/'+identity+'/json',missing=True)
        if value is None:raise JumphostError('original packet exec missing; recovery retained')
        config={'tty':False,'entrypoint':self.command[0],'arguments':self.command[1:],'privileged':False,'user':'0'}
        if (value.get('ID')!=identity or value.get('ContainerID')!=self.r['container_id'] or value.get('ProcessConfig')!=config
                or any(value.get(k) is not False for k in ('OpenStdin','OpenStdout','OpenStderr'))
                or type(value.get('Running')) is not bool or type(value.get('Pid')) is not int
                or value['Pid']<0 or value.get('ExitCode') is not None and type(value['ExitCode']) is not int):
            raise JumphostError('packet exec ownership/configuration differs')
        return value

    def inventory(self,*,endpoint=True):
        ids=self.original(endpoint=endpoint)
        for identity in ids:self.inspect(identity)
        if self.op['id'] and set(ids)-{self.op['id']}:raise JumphostError('additional packet exec requires recovery')
        return ids

    def prepare(self):
        ids=self.inventory()
        if self.op['id']:
            self.inspect(self.op['id']);return self.identity()
        if ids:
            if not self.op['create_attempted'] or len(ids)!=1:raise JumphostError('unbound packet exec inventory differs')
            current=self.inspect(ids[0])
            if current['Running'] or current.get('ExitCode') is not None or current['Pid']!=0:
                raise JumphostError('unbound packet exec has already run')
            identity=ids[0]
        else:
            if self.op['create_attempted']:raise JumphostError('packet exec create unresolved; no second create')
            self.op['create_attempted']=True;self.op['create_calls']+=1;self.w.save(self.r);self.inventory()
            payload={'Cmd':self.command,'User':'0','AttachStdin':False,'AttachStdout':False,'AttachStderr':False,'Tty':False,'Privileged':False}
            value=self.w.docker.call('POST','/containers/'+self.r['container_id']+'/exec',payload)
            identity=value.get('Id') if isinstance(value,dict) else None
            if not isinstance(identity,str) or not re.fullmatch('[0-9a-f]{64}',identity):raise JumphostError('packet exec create result uncertain')
        self.op['id']=identity;self.op['phase']='created';self.w.save(self.r)
        self.inventory();self.inspect(identity);return self.identity()

    def progress(self):
        self.assets();row=self.op['files']['output']
        fd=os.open(row['path'],os.O_RDONLY|os.O_NOFOLLOW)
        with os.fdopen(fd,'rb') as stream:
            if file_identity(os.fstat(stream.fileno()))!=row['identity']:raise JumphostError('packet exec output replaced')
            raw=stream.read(131073)
        if len(raw)>131072:raise JumphostError('packet exec output limit exceeded')
        records=[];offset=0;seen=set();stages={};terminal=False
        for line in raw.splitlines(keepends=True):
            if not line.endswith(b'\n'):break
            try:value=json.loads(line)
            except (ValueError,UnicodeDecodeError):break
            if (not isinstance(value,dict) or set(value)!={'nonce','request','kind','value'} or value['nonce']!=self.op['nonce']
                    or value['request']!=digest(self.w.request) or value['kind'] not in ('birth','permit','progress','completed','failed')
                    or terminal):raise JumphostError('packet exec progress binding differs')
            kind=value['kind'];payload=value['value']
            if kind=='progress':
                if 'permit' not in seen or not isinstance(payload,dict) or set(payload)!={'stage','result'}:
                    raise JumphostError('packet exec progress lacks permit')
                stage=payload['stage']
                if stage in stages:raise JumphostError('duplicate packet exec progress')
                validate_progress(self.w.request['packet_profile'],stage,payload['result'])
                if stage=='ipv4.ack' and 'ipv4.offer' not in stages or stage.startswith('ipv6.') and 'ipv4.ack' not in stages:
                    raise JumphostError('packet progress order differs')
                if stage=='ipv6.reply' and ('ipv6.advertise' not in stages or stages['ipv6.advertise']['server_id']!=payload['result']['server_id']):
                    raise JumphostError('packet progress DHCPv6 server differs')
                stages[stage]=payload['result']
            else:
                if kind in seen or kind=='birth' and records or kind=='permit' and seen!={'birth'}:
                    raise JumphostError('packet exec evidence sequence differs')
                seen.add(kind)
                if kind in ('completed','failed'):terminal=True
            records.append(value);offset+=len(line)
        complete=raw[:offset]
        previous=self.op.get('observations',[])
        if records[:len(previous)]!=previous:raise JumphostError('packet exec progress history changed')
        if records!=previous or self.op.get('partial_tail','')!=raw[len(complete):].hex():
            self.op['observations']=records;self.op['partial_tail']=raw[len(complete):].hex();self.w.save(self.r)
        return records,raw[len(complete):]

    def permit(self,current):
        rows,tail=self.progress()
        births=[v['value'] for v in rows if v['kind']=='birth'];permits=[v['value'] for v in rows if v['kind']=='permit']
        if tail:return
        if not births:return
        if len(births)!=1 or len(permits)>1:raise JumphostError('ambiguous packet exec birth/permit')
        birth=births[0]
        if (not isinstance(birth,dict) or set(birth)!={'pid','start','namespace'} or type(birth['pid']) is not int or birth['pid']<=0
                or not isinstance(birth['start'],str) or not birth['start'].isdigit() or birth['namespace']!=self.r['namespace']):
            raise JumphostError('packet exec process generation differs')
        if permits:
            if permits[0]!=birth:raise JumphostError('packet exec permit differs')
            return
        if not current['Running']:raise JumphostError('packet exec exited before permit')
        if current['Pid']<=0:return
        pid=current['Pid'];self.w.packet_process(current,birth)
        process=dict(birth,host_pid=pid,exec_id=self.op['id'])
        if self.op.get('process') is not None and self.op['process']!=process:raise JumphostError('packet exec process proof replaced')
        self.op['process']=deepcopy(process);self.op['permit_intent']=deepcopy(birth);self.w.save(self.r);self.inventory()
        fresh=self.inspect(self.op['id'])
        if not fresh['Running'] or fresh['Pid']!=pid:raise JumphostError('packet exec changed before permit')
        row={'nonce':self.op['nonce'],'request':digest(self.w.request),'kind':'permit','value':birth}
        fd=os.open(self.op['files']['output']['path'],os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
        try:
            if file_identity(os.fstat(fd))!=self.op['files']['output']['identity']:raise JumphostError('packet exec permit output replaced')
            raw=(canonical(row)+'\n').encode();written=os.write(fd,raw)
            if written!=len(raw):raise JumphostError('packet exec permit write incomplete')
            os.fsync(fd)
        finally:os.close(fd)
        self.progress()

    def observe_exit(self,*,endpoint=False):
        self.inventory(endpoint=endpoint)
        if not self.op['id']:
            if self.op['create_attempted']:raise JumphostError('packet exec create unresolved before cleanup')
            return None
        current=self.inspect(self.op['id']);rows,tail=self.progress()
        if not self.op['start_attempted']:
            if current['Running'] or current.get('ExitCode') is not None or rows or tail:
                raise JumphostError('packet exec ran without start intent')
            return None
        if current['Running']:
            if self.op.get('process') and current['Pid']!=self.op['process']['host_pid']:raise JumphostError('packet exec PID replaced')
            return current
        if current.get('ExitCode') is None:raise JumphostError('packet exec start unresolved; no second start')
        terminal=[v for v in rows if v['kind'] in ('completed','failed')]
        if len(terminal)>1 or terminal and rows[-1]!=terminal[0]:raise JumphostError('packet exec terminal history differs')
        self.op['exit_verified']=True;self.op['exit_code']=current['ExitCode'];self.op['phase']='exited';self.w.save(self.r)
        if current['ExitCode']==0 and not tail and terminal and terminal[0]['kind']=='completed':
            result=terminal[0]['value'];validate_packet_result(self.w.request['packet_profile'],result)
            stages={v['value']['stage']:v['value']['result'] for v in rows if v['kind']=='progress'}
            expected=expected_progress(self.w.request['packet_profile'],result)
            if stages!=expected:raise JumphostError('packet exec final result differs from progress')
            self.r['packet_result']=result;self.r['packet_phase']='completed'
        else:
            self.r['packet_phase']='failed'
            self.op['error']=terminal[0]['value'] if terminal and terminal[0]['kind']=='failed' else {'type':'ExecutionFailed','message':'packet exec exited without complete result'}
        self.w.save(self.r);return current

    def start(self):
        """Start once and qualify the permit without waiting for peer traffic."""
        self.inventory();current=self.inspect(self.op['id'])
        if not self.op['start_attempted']:
            if current['Running'] or current.get('ExitCode') is not None or self.progress()[0]:raise JumphostError('packet exec pre-start differs')
            self.op['start_attempted']=True;self.op['start_calls']+=1;self.op['phase']='starting';self.r['packet_phase']='applying';self.w.save(self.r)
            self.inventory();self.w.docker.call('POST','/exec/'+self.op['id']+'/start',{'Detach':True,'Tty':False})
        deadline=time.monotonic()+10
        while True:
            current=self.observe_exit(endpoint=True)
            if self.op['exit_verified']:
                if self.r.get('packet_phase')!='completed':raise JumphostError('packet exec failed; evidence retained')
                return self.r
            if current:self.permit(current)
            if any(row['kind']=='permit' for row in self.op['observations']):return self.r
            if time.monotonic()>=deadline:raise JumphostError('packet exec permit unresolved; recovery retained')
            time.sleep(.05)

    def run(self):
        self.start()
        deadline=time.monotonic()+self.WAIT_SECONDS
        while True:
            current=self.observe_exit(endpoint=True)
            if self.op['exit_verified']:
                if self.r.get('packet_phase')!='completed':raise JumphostError('packet exec failed; evidence retained')
                return self.r
            if current:self.permit(current)
            if time.monotonic()>=deadline:raise JumphostError('packet exec remains running; recovery retained')
            time.sleep(.05)

    def cleanup(self):
        if not self.op['create_attempted']:
            self.assets();value=self.w.container(self.r)
            if value and value.get('ExecIDs') not in (None,[]):raise JumphostError('unqualified exec before cleanup')
            return
        if not self.op['id']:
            ids=self.inventory(endpoint=False)
            if len(ids)!=1:raise JumphostError('packet exec create unresolved before cleanup')
            current=self.inspect(ids[0])
            if current['Running'] or current.get('ExitCode') is not None or current['Pid']!=0:raise JumphostError('unbound packet exec already ran')
            self.op['id']=ids[0];self.op['phase']='created';self.w.save(self.r)
        value=self.w.container(self.r)
        if self.op['exit_verified'] and (value is None or not value['State']['Running']):
            self.assets()
            if value and value.get('ExecIDs'):raise JumphostError('stopped probe still has unqualified execs')
            return
        current=self.observe_exit()
        if current and current['Running']:raise JumphostError('packet exec still running; cleanup pending')
