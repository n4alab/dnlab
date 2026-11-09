"""Fixture-only synchronous AF_PACKET observations; no capture subprocesses."""
from contextlib import ExitStack, contextmanager
import ipaddress
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import sys
import time


def relevant(frame, addresses):
    if len(frame)<14:return False
    kind=int.from_bytes(frame[12:14],'big')
    if kind==0x806:
        return len(frame)>=42 and any(str(ipaddress.IPv4Address(bytes(frame[a:b]))) in addresses for a,b in ((28,32),(38,42)))
    if kind==0x800 and len(frame)>=34:
        return any(str(ipaddress.IPv4Address(bytes(frame[a:b]))) in addresses for a,b in ((26,30),(30,34)))
    if kind==0x86dd and len(frame)>=54:
        return any(str(ipaddress.IPv6Address(bytes(frame[a:b]))) in addresses for a,b in ((22,38),(38,54)))
    return False


def save(path,value):
    fd,tmp=tempfile.mkstemp(dir=path.parent,prefix='.dns-path-')
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600);json.dump(value,stream,indent=2)
            stream.flush();os.fsync(stream.fileno())
        os.replace(tmp,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(tmp):os.unlink(tmp)


class Capture:
    MAX_FRAMES=128
    MAX_SCANNED=20000
    def __init__(self,addresses):
        self.addresses=set(addresses);self.points=[];self.sockets=[]

    def open(self,fd,name,label):
        original=os.open('/proc/self/ns/net',os.O_RDONLY);sock=None
        try:
            os.setns(fd,0)
            index=socket.if_nametoindex(name)
            sock=socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(3))
            sock.setsockopt(263,8,1);sock.bind((name,0));sock.setblocking(False)
            if socket.if_nametoindex(name)!=index:raise RuntimeError('capture interface changed')
            info=os.fstat(fd)
            row={'label':label,'interface':name,'ifindex':index,'namespace':{'device':info.st_dev,'inode':info.st_ino},
                 'scanned':0,'matched':0,'frames':[],'scan_limit':False}
            self.points.append(row);self.sockets.append((sock,row));sock=None
        finally:
            try:os.setns(original,0)
            finally:
                os.close(original)
                if sock is not None:sock.close()

    def drain(self):
        for sock,row in self.sockets:
            for _ in range(min(4096,self.MAX_SCANNED-row['scanned'])):
                try:frame,ancillary,flags,address=sock.recvmsg(65535,128)
                except BlockingIOError:break
                row['scanned']+=1
                if not relevant(frame,self.addresses):continue
                row['matched']+=1
                if len(row['frames'])<self.MAX_FRAMES:
                    row['frames'].append({'time_ns':time.monotonic_ns(),'packet_type':address[2],
                        'length':len(frame),'prefix_hex':frame[:512].hex(),'flags':flags,
                        'auxdata':[data.hex() for level,kind,data in ancillary if level==263 and kind==8]})
            row['scan_limit']=row['scanned']>=self.MAX_SCANNED

    def close(self):
        for sock,_ in self.sockets:sock.close()
        self.sockets=[]


def snapshot(fd=None):
    rows=[]
    commands=[['ip','-j','-d','address','show']]
    for version in ('-4','-6'):
        commands += [['ip',version,'-j','route','show','table','all'],['ip',version,'-j','rule','show'],['ip',version,'-j','neigh','show']]
    commands += [['iptables-save','-c'],['ip6tables-save','-c']]
    for command in commands:
        argv=(['nsenter','--net=/proc/self/fd/'+str(fd),'--'] if fd is not None else [])+command
        try:
            result=subprocess.run(argv,capture_output=True,text=True,timeout=8,pass_fds=() if fd is None else (fd,))
            rows.append({'command':command,'exit_code':result.returncode,'stdout':result.stdout[:262144],'stderr':result.stderr[:4096],
                         'truncated':len(result.stdout)>262144})
        except Exception as error:rows.append({'command':command,'error':str(error)})
    return rows



def dns_observation(worker,record):
    value=worker.container(record)
    if not value or value.get('Id')!=record.get('container_id'):
        raise RuntimeError('diagnostic DNS original container differs')
    state=value.get('State',{})
    pid=state.get('Pid');started=state.get('StartedAt')
    if state.get('Running') is not True or type(pid) is not int or pid<=0 or not isinstance(started,str) or not started:
        raise RuntimeError('diagnostic DNS original process not running')
    fields=(Path('/proc')/str(pid)/'stat').read_text().rsplit(')',1)[1].split()
    if fields[0]=='Z':raise RuntimeError('diagnostic DNS process exited')
    info=os.stat('/proc/'+str(pid)+'/ns/net')
    return {'container_id':value['Id'],'nonce':record['nonce'],'pid':pid,'started_at':started,
            'process_start':fields[19],'namespace':{'device':info.st_dev,'inode':info.st_ino}}


def verify_dns_namespace(worker,record,fd,expected):
    observed=dns_observation(worker,record);info=os.fstat(fd)
    if observed!=expected or observed['namespace']!={'device':info.st_dev,'inode':info.st_ino}:
        raise RuntimeError('diagnostic DNS process or namespace changed')


@contextmanager
def dns_namespace(worker,record):
    # DNS has no durable namespace field. Observe its original guarded generation
    # without capture=True or any journal write; retain the pinned FD in this worker.
    expected=dns_observation(worker,record);fd=worker.open_ns(expected['pid'])
    try:
        verify_dns_namespace(worker,record,fd,expected)
        yield fd,expected
        verify_dns_namespace(worker,record,fd,expected)
    finally:os.close(fd)


def install(Execution,JumpWorker,DNSWorker,root):
    original_run=Execution.run;original_observe=Execution.observe_exit
    def run(self):
        root_path=Path(root);path=root_path/'dns-path.json'
        report={'phase':'qualifying','request':self.w.request,'execution':self.identity(),'points':[]}
        capture=Capture([]);stack=ExitStack();active=False
        def drain():
            try:capture.drain()
            except Exception as error:report.setdefault('capture_errors',[]).append(str(error))
        def observe(instance,*args,**kwargs):
            drain()
            try:return original_observe(instance,*args,**kwargs)
            finally:drain()
        try:
            self.original()
            profile=self.w.request['packet_profile'];lab=self.w.request['lab']
            jw=JumpWorker(lab,directory=str(root_path/'jump'),management_directory=str(root_path/'management'))
            dw=DNSWorker(lab,directory=str(root_path/'dns'))
            jr=jw.read();dr=dw.read()
            jw.infrastructure(jr);jw.verify_extensions(jr);dw.infrastructure(dr)
            pf=stack.enter_context(self.w.namespace(self.r));self.w.packet_endpoint(self.r,pf)
            jf=stack.enter_context(jw.namespace(jr));jw.verify_attachment(jr,jf)
            df,dns_proof=stack.enter_context(dns_namespace(dw,dr))
            attachment=jr if jr['config']['attachment']['segment']==self.w.request['segment'] else jr['management_attachments'][self.w.request['segment']]
            interface=attachment['config']['attachment']['interface']
            addresses=set(profile['addresses'].values())|set(profile['resolvers'].values())|{profile['server_ip'],jr['config']['ip'],dr['config']['ip']}
            capture.addresses={str(v) for v in addresses if v}
            report['births']={name:{k:record[k] for k in ('container_id','nonce','namespace','started_at')} for name,record in [('probe',self.r),('jumphost',jr)]}
            report['births']['dns']=dns_proof
            points=[(pf,'probe0','client'),(jf,interface,'jumphost-management'),(jf,'eth0','jumphost-wan'),(df,'eth0','dns')]
            for fd,name,label in points:
                if not self.w.find(name,fd):raise RuntimeError('diagnostic interface missing')
                capture.open(fd,name,label)
            report['points']=capture.points
            namespaces=[('host',None),('client',pf),('jumphost',jf),('dns',df)]
            report['before']={name:snapshot(fd) for name,fd in namespaces}
            report['phase']='capturing';save(path,report)
            verify_dns_namespace(dw,dr,df,dns_proof)
            Execution.observe_exit=observe;active=True
            try:
                result=original_run(self);report['original_result']='returned';return result
            except Exception as error:
                report['original_error']={'type':type(error).__name__,'message':str(error)};raise
            finally:
                drain();report['after']={name:snapshot(fd) for name,fd in namespaces};drain()
                report['phase']='observed'
                # All original guards remain authoritative; readonly verification only.
                try:
                    self.original();jw.infrastructure(jr);jw.verify_extensions(jr);jw.container(jr);dw.infrastructure(dr);verify_dns_namespace(dw,dr,df,dns_proof)
                    report['post_identity']='verified'
                except Exception as error:report['post_identity_error']=str(error)
        except Exception as error:
            report.setdefault('diagnostic_or_original_error',{'type':type(error).__name__,'message':str(error)});raise
        finally:
            if active:Execution.observe_exit=original_observe
            original_error=sys.exc_info()[1]
            try:
                capture.close();stack.close();save(path,report)
            except Exception as error:
                if original_error is None:raise
                print('diagnostic finalization failed: '+str(error),file=sys.stderr)
    Execution.run=run
