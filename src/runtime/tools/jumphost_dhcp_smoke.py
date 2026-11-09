#!/usr/bin/env python3
"""Opt-in DHCP asset/reload gate on original jumphost and isolated lab VRFs."""
import argparse
import copy
import hashlib
import json
import os
import stat
from pathlib import Path
import subprocess
import sys
import time
import uuid

from jumphost_identity_smoke import run, execute
from dnlab_runtime.backend import Docker
from dnlab_multinode.services import jumphost

PROBE = r"""import socket,struct,random,json,time
mac=bytes.fromhex('020000123456');xid=random.getrandbits(32)
s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1);s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',68));s.settimeout(1)
p=struct.pack('!BBBBIHH4s4s4s4s16s64s128s',1,1,6,0,xid,0,0x8000,b'\0'*4,b'\0'*4,b'\0'*4,b'\0'*4,mac+b'\0'*10,b'\0'*64,b'\0'*128)+b'\x63\x82\x53\x63'+b'\x35\x01\x01\x37\x03\x01\x03\x06\xff'
for attempt in range(8):
 s.sendto(p,('255.255.255.255',67));until=time.monotonic()+1
 while time.monotonic()<until:
  try:data,addr=s.recvfrom(4096)
  except socket.timeout:break
  if len(data)<240 or data[0]!=2 or struct.unpack('!I',data[4:8])[0]!=xid:continue
  opts={};i=240
  while i<len(data):
   code=data[i];i+=1
   if code==255:break
   if code==0:continue
   length=data[i];i+=1;opts[code]=data[i:i+length];i+=length
  if opts.get(53)!=b'\x02':continue
  dns=opts.get(6,b'');dns=[socket.inet_ntoa(dns[i:i+4]) for i in range(0,len(dns),4)]
  print(json.dumps({'offered':socket.inet_ntoa(data[16:20]),'server':addr[0],'dns':dns}));raise SystemExit
raise RuntimeError('no qualified DHCP offer')
"""


PIDFILE_PROBE = r"""import json,os,pwd,grp,stat
out={'path':'/run/dnlab-dnsmasq.pid'};path=out['path']
def error(exc):return {'error_type':type(exc).__name__,'error':str(exc)}
def signature(st):
 return {'uid':st.st_uid,'gid':st.st_gid,'mode':oct(stat.S_IMODE(st.st_mode)),'regular':stat.S_ISREG(st.st_mode),'symlink':stat.S_ISLNK(st.st_mode),'device':st.st_dev,'inode':st.st_ino,'nlink':st.st_nlink}
for label,follow in [('lstat',False),('stat',True)]:
 try:out[label]=signature(os.stat(path,follow_symlinks=follow))
 except Exception as exc:out[label]=error(exc)
try:
 fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
 with os.fdopen(fd) as stream:
  out['fstat']=signature(os.fstat(stream.fileno()));out['pid_text']=stream.read(128)
 pid=int(out['pid_text'].strip());root='/proc/'+str(pid);process={'pid':pid}
 for label,suffix,decoder in [('cmdline','/cmdline',lambda s:s.replace('\0',' ').strip()),('status','/status',lambda s:'\n'.join(v for v in s.splitlines() if v.split(':',1)[0] in ('Name','State','Pid','PPid','Uid','Gid','NSpid','CapEff','NoNewPrivs'))),('starttime','/stat',lambda s:s.rsplit(')',1)[1].split()[19])]:
  try:process[label]=decoder(open(root+suffix).read())
  except Exception as exc:process[label]=error(exc)
 for label,suffix in [('exe','/exe'),('pid_namespace','/ns/pid'),('net_namespace','/ns/net')]:
  try:process[label]=os.readlink(root+suffix)
  except Exception as exc:process[label]=error(exc)
 out['process']=process
except Exception as exc:out['pid_read_error']=error(exc)
for label,uid in [('pidfile_owner',out.get('lstat',{}).get('uid'))]:
 try:
  user=pwd.getpwuid(uid);out[label]={'name':user.pw_name,'uid':user.pw_uid,'gid':user.pw_gid}
 except Exception as exc:out[label]=error(exc)
print(json.dumps(out,sort_keys=True))
"""


def content(ip='198.19.231.11', dns='192.0.2.53'):
    return ('port=0\ninterface=eth1\nbind-dynamic\ndhcp-authoritative\npid-file=/run/dnlab-dnsmasq.pid\n'
            'dhcp-range=set:mgmt,198.19.231.0,static,12h\n'
            'dhcp-option=tag:mgmt,option:router,198.19.231.254\n'
            f'dhcp-option=tag:mgmt,option:dns-server,{dns}\n'
            f'dhcp-host=02:00:00:12:34:56,{ip}\n')


def diagnose(root, docker, client, test, record, report):
    from contextlib import ExitStack
    from dnlab_runtime.backend import Linux
    captures=[];snapshots={}
    def command(argv, fds=(), timeout=8):
        value=subprocess.run(argv,capture_output=True,text=True,timeout=timeout,pass_fds=fds)
        return {'argv':argv,'rc':value.returncode,'stdout':value.stdout,'stderr':value.stderr}
    def dump(stage,client_fd,server_fd):
        results={}
        for side,fd in [('client',client_fd),('server',server_fd)]:
            prefix=['nsenter','--net=/proc/self/fd/'+str(fd)]
            for label,args in [('addresses',['ip','-j','addr']),('links',['ip','-j','-d','link']),
                               ('routes',['ip','-j','route','show','table','all']),
                               ('broadcast_route',['ip','route','get','255.255.255.255'])]:
                results[side+'-'+label]=command(prefix+args,(fd,))
        for label,args in [('host-iptables',['iptables-save','-c']),('host-ip6tables',['ip6tables-save','-c']),
                           ('host-links',['ip','-j','-d','link']),('host-bridge',['bridge','-j','-d','link','show']),
                           ('bridge-netfilter',['sysctl','net.bridge.bridge-nf-call-iptables','net.bridge.bridge-nf-call-ip6tables'])]:
            results[label]=command(args)
        server=test.container(record)
        results['server-iptables']=command(['docker','exec',server['Id'],'iptables-save','-c'])
        (root/('dhcp-diagnostic-'+stage+'.json')).write_text(json.dumps(results,indent=2)+'\n')
        snapshots[stage]=results
    with ExitStack() as stack:
        server_fd=stack.enter_context(test.namespace(record))
        initial=client();client_fd=os.open('/proc/'+str(initial['State']['Pid'])+'/ns/net',os.O_RDONLY)
        stack.callback(os.close,client_fd)
        current=client()
        if current['State']['Pid']!=initial['State']['Pid'] or current['State']['StartedAt']!=initial['State']['StartedAt']:
            raise RuntimeError('diagnostic client namespace generation changed')
        dump('before',client_fd,server_fd)
        client_links=json.loads(snapshots['before']['client-links']['stdout'])
        eth=next(v for v in client_links if v['ifname']=='eth0')
        host_links=json.loads(snapshots['before']['host-links']['stdout'])
        peer=next(v for v in host_links if v['ifindex']==eth['link_index'])
        if peer.get('link_index')!=eth['ifindex']:raise RuntimeError('diagnostic client peer not reciprocal')
        targets=[('client',client_fd,'eth0'),('server',server_fd,'eth1'),('host-peer',None,peer['ifname'])]
        for label,fd,interface in targets:
            prefix=['nsenter','--net=/proc/self/fd/'+str(fd)] if fd is not None else []
            argv=prefix+['timeout','11','tcpdump','-p','-i',interface,'-e','-nn','-vvv','udp','and','(port 67 or port 68)']
            proc=subprocess.Popen(argv,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,pass_fds=(fd,) if fd is not None else ())
            captures.append((label,proc))
            def stop_capture(process):
                if process.poll() is None:
                    process.terminate();process.communicate(timeout=3)
            stack.callback(stop_capture,proc)
        # Read-only capture sockets settle before the exact original probe.
        time.sleep(.3)
        outcome=command(['docker','exec',current['Id'],'python3','-c',PROBE],timeout=12)
        (root/'dhcp-diagnostic-probe.json').write_text(json.dumps(outcome,indent=2)+'\n')
        dump('after',client_fd,server_fd)
        observed={}
        for label,proc in captures:
            try:stdout,stderr=proc.communicate(timeout=14)
            except subprocess.TimeoutExpired:
                proc.terminate();stdout,stderr=proc.communicate(timeout=3)
            (root/('dhcp-diagnostic-'+label+'-packets.txt')).write_text(stdout+stderr)
            observed[label]={'rc':proc.returncode,'stdout':stdout,'stderr':stderr}
        (root/'dhcp-diagnostic-peer.json').write_text(json.dumps({'client':eth,'host_peer':peer},indent=2)+'\n')
        report['dhcp_diagnostic']={'probe_rc':outcome['rc'],'probe_stdout':outcome['stdout'],'probe_stderr':outcome['stderr'],
            'captures':observed,'snapshot_files':['dhcp-diagnostic-before.json','dhcp-diagnostic-after.json'],
            'runtime_and_plugin_unchanged':True,'refresh_attempted':False}
        report['checks'].append('diagnostic only: client/server/reciprocal host peer captures and read-only endpoint/routes/firewall snapshots')


def service_gate(root, configs, workers, report, diagnostic_only=False, pidfile_diagnostic=False, log_diagnostic=False):
    docker=Docker();control,test=workers;before=control.operate('read')
    image='sha256:70729b46c69b4f1e97c4822c1af3df53a1476cf5ddc6c087c0c10bc3a5678c2f'
    image_record=docker.request('GET','/images/'+image+'/json')
    assert image_record['Id']==image and not image_record.get('Config',{}).get('Volumes')
    record=test.operate('read');network=record['management_network']['network']
    labels=dict(image_record['Config'].get('Labels') or {},**{'org.dnlab.dhcp.fixture':uuid.uuid4().hex})
    name='drsp-dhcp-'+uuid.uuid4().hex[:10]
    code="import pathlib,signal,time;signal.signal(signal.SIGTERM,lambda *a:exit(0));pathlib.Path('/tmp/ready').write_text('ready');time.sleep(300)"
    cfg={'Image':image,'Labels':labels,'Entrypoint':['python3','-c'],'Cmd':[code],
         'HostConfig':{'NetworkMode':network['Id']},'NetworkingConfig':{'EndpointsConfig':{network['Name']:{}}}}
    birth={'name':name,'config':cfg,'id':None}
    def save():
        temporary=root/'.dhcp-client-intent'
        with temporary.open('w') as stream:json.dump(birth,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,root/'dhcp-client-intent.json')
        fd=os.open(root,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def client():
        v=docker.inspect(birth['id'] or name)
        if v:
            assert v['Image']==image and v['Config']['Labels']==labels and v['Name']=='/'+name
            assert v['Config']['Entrypoint']==cfg['Entrypoint'] and v['Config']['Cmd']==cfg['Cmd']
            assert v['HostConfig']['NetworkMode']==network['Id']
            if birth['id']:assert v['Id']==birth['id']
            else:birth['id']=v['Id'];save()
        return v
    def offer():
        v=client();assert v and v['State']['Running']
        result=subprocess.run(['docker','exec',v['Id'],'python3','-c',PROBE],text=True,capture_output=True,timeout=12)
        if result.returncode:raise RuntimeError('DHCP client failed: '+result.stderr[-1000:])
        return json.loads(result.stdout)
    try:
        assert docker.inspect(name) is None
        save();birth['id']=docker.create(name,cfg)['Id'];save();client();docker.start(birth['id'])
        docker.exec_checked(birth['id'],['python3','-c',"import pathlib,time;[(time.sleep(.1)) for _ in range(30) if not pathlib.Path('/tmp/ready').exists()];assert pathlib.Path('/tmp/ready').exists()"])
        if diagnostic_only:
            diagnose(root,docker,client,test,record,report)
            return
        server=test.container(record)
        for suffix,cid in [('server',server['Id']),('client',birth['id'])]:
            for label,args in [('links',['ip','-j','addr']),('routes',['ip','-j','route']),('entrypoint',['cat','/entrypoint.sh'])]:
                result=subprocess.run(['docker','exec',cid]+args,capture_output=True,text=True,timeout=5)
                (root/('dhcp-'+suffix+'-'+label+'.txt')).write_text(result.stdout+result.stderr)
        capture=subprocess.Popen(['docker','exec',server['Id'],'timeout','10','tcpdump','-p','-i','eth1','-e','-nn','-vvv','udp','and','(port 67 or port 68)'],stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True)
        try:
            original=offer()
        finally:
            stdout,stderr=capture.communicate(timeout=12)
            (root/'dhcp-server-packets.txt').write_text(stdout+stderr)
        assert original['offered']=='198.19.231.11' and original['dns']==['192.0.2.53'],original
        before_container=test.container(record)
        report['dhcp']={'initial':original,'before_id':before_container['Id'],'before_started_at':before_container['State']['StartedAt']}
        if pidfile_diagnostic:
            observed=subprocess.run(['docker','exec',before_container['Id'],'python3','-c',PIDFILE_PROBE],capture_output=True,text=True,timeout=5)
            snapshot={'rc':observed.returncode,'stdout':observed.stdout,'stderr':observed.stderr}
            if observed.returncode==0:snapshot['parsed']=json.loads(observed.stdout)
            (root/'dhcp-pidfile-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
            try:
                snapshot['unchanged_guard_result']=test.dhcp_service(record)
            except RuntimeError as error:
                snapshot['unchanged_guard_error']={'type':type(error).__name__,'message':str(error)}
            (root/'dhcp-pidfile-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
            report['pidfile_diagnostic']={'snapshot':'dhcp-pidfile-snapshot.json','refresh_attempted':False}
            report['checks'].append('read-only PID file lstat/stat/fstat and process identity before cleanup; unchanged guard observation')
            return
        service=test.dhcp_service(record);report['dhcp']['service']=service
        if log_diagnostic:
            from dnlab_multinode.services.jumphost_host import DHCPHostService
            snapshot={'path':'/run/dnlab-dhcp.log','service':service,'refresh_attempted':False}
            with test.namespace(record) as network_fd:
                with DHCPHostService(test,record,network_fd) as scope:
                    scope.observe(service)
                    def signature(info):
                        return {'uid':info.st_uid,'gid':info.st_gid,'mode':oct(stat.S_IMODE(info.st_mode)),
                                'mode_bits':stat.S_IMODE(info.st_mode),'regular':stat.S_ISREG(info.st_mode),
                                'symlink':stat.S_ISLNK(info.st_mode),'device':info.st_dev,'inode':info.st_ino,
                                'nlink':info.st_nlink,'size':info.st_size}
                    for label,follow in [('lstat',False),('stat',True)]:
                        snapshot[label]=signature(os.stat('dnlab-dhcp.log',dir_fd=scope.run_dir,follow_symlinks=follow))
                    log=scope.open('dnlab-dhcp.log',parent=scope.run_dir)
                    info=os.fstat(log);snapshot['fstat']=signature(info)
                    snapshot['previous_generic_expected']={'regular':True,'allowed_uids':[0,service['profile']['uid']],
                                          'forbidden_mode_bits':'0o22'}
                    snapshot['comparison']={'regular_matches':stat.S_ISREG(info.st_mode),
                        'uid_matches':info.st_uid in (0,service['profile']['uid']),
                        'mode_matches':not bool(info.st_mode & 0o022)}
                    snapshot['previous_generic_predicate_accepts']=all(snapshot['comparison'].values())
                    snapshot['qualified_profile_proof']=service['log']
                    snapshot['content']=os.pread(log,1024*1024,0).decode(errors='replace')
                    scope.observe(service)
            (root/'dhcp-log-identity-snapshot.json').write_text(json.dumps(snapshot,indent=2)+'\n')
            report['log_diagnostic']={'snapshot':'dhcp-log-identity-snapshot.json',
                'comparison':snapshot['comparison'],'refresh_attempted':False}
            report['checks'].append('read-only log lstat/stat/fstat through pinned original container root; historical generic predicate versus current qualified profile; no HUP')
            return
        request={'container':configs[1]['name'],'generation':configs[1]['generation'],
                 'request_id':uuid.uuid4().hex,'content':content('198.19.231.12','192.0.2.54')}
        armed=True;original_service=test.dhcp_service
        def lost_ack(record,action='inspect',expected=None):
            nonlocal armed
            result=original_service(record,action,expected)
            if armed and action=='reload':
                armed=False;raise RuntimeError('injected lost DHCP reload acknowledgement')
            return result
        test.dhcp_service=lost_ack
        try:test.operate('dhcp-refresh',request)
        except RuntimeError as error:
            if str(error)!='injected lost DHCP reload acknowledgement':raise
        else:raise RuntimeError('DHCP lost response not exercised')
        assert test.read()['phase']=='recovery_required'
        test.dhcp_service=original_service
        test.run=execute;after=test.operate('recover');changed=offer()
        assert changed['offered']=='198.19.231.12' and changed['dns']==['192.0.2.54'],changed
        assert test.container(after)['State']['StartedAt']==before_container['State']['StartedAt']
        assert test.dhcp_service(after)==service
        assert control.operate('read')==before
        assert test.operate('dhcp-refresh',request)['phase']=='active'
        class Transport:
            def run_input(self,command,payload,timeout):
                import shlex
                result=subprocess.run(shlex.split(command),input=payload,text=True,capture_output=True,timeout=timeout)
                if result.returncode:raise RuntimeError('DHCP standalone worker: '+result.stderr[-1500:])
                return result.stdout
        request2=dict(request,request_id=uuid.uuid4().hex,content=content('198.19.231.13','192.0.2.55'))
        assert jumphost._guard(Transport(),test.lab,'dhcp-refresh',request2)['phase']=='active'
        final=offer();assert final['offered']=='198.19.231.13' and final['dns']==['192.0.2.55'],final
        assert test.dhcp_service(test.read())==service and control.operate('read')==before
        report['dhcp'].update(after_recovery=changed,after_standalone=final,request_id=request['request_id'])
        report['checks'].append('DHCP offers and DNS options update through dynamic files; qualified pidfd HUP/log acknowledgement; lost response recovery; process/container/control unchanged; standalone invocation')
    except Exception:
        if 'original_service' in locals():test.dhcp_service=original_service
        test.run=execute
        value=test.container(test.read())
        if value:
            logs=subprocess.run(['docker','exec',value['Id'],'cat','/run/dnlab-dhcp.log'],capture_output=True,text=True)
            (root/'dhcp-service-log.txt').write_text(logs.stdout+logs.stderr)
        raise
    finally:
        if 'original_service' in locals():test.dhcp_service=original_service
        test.run=execute
        v=client()
        if v and v['State']['Running']:
            docker.signal(v['Id'],'TERM');deadline=time.monotonic()+15
            while True:
                v=client()
                if not v or not v['State']['Running']:break
                if time.monotonic()>deadline:raise RuntimeError('DHCP client shutdown timeout')
                time.sleep(.1)
        if v:docker.remove(v['Id'])
        assert client() is None
        report['dhcp_client_cleanup_verified']=True


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True)
    parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--diagnostic-only',action='store_true');parser.add_argument('--pidfile-diagnostic',action='store_true');parser.add_argument('--log-diagnostic',action='store_true');args=parser.parse_args()
    if sum((args.diagnostic_only,args.pidfile_diagnostic,args.log_diagnostic))>1:parser.error('choose one diagnostic mode')
    callback=lambda *values:service_gate(*values,diagnostic_only=args.diagnostic_only,pidfile_diagnostic=args.pidfile_diagnostic,log_diagnostic=args.log_diagnostic)
    result=run(args.image,args.plugin_sha256,args.output,dhcp_config=content,service_gate=callback,full_management=True)
    if args.diagnostic_only or args.pidfile_diagnostic or args.log_diagnostic:
        path=Path(result)/'report.json';value=json.loads(path.read_text());value['status']='diagnosed';value['scope']='diagnostic only; no DHCP refresh or functional pass claimed';path.write_text(json.dumps(value,indent=2)+'\n')
    print(result)
