#!/usr/bin/env python3
"""Opt-in, isolated relay lifecycle/console/log qualification on one host."""
import argparse
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import math
import os
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import time
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from smoke import Service
from cleanup_compatibility import require_qualified_cleanup
from management_barrier_smoke import Local
from management_service_diagnostics import private_json,exception_chain
from http_workload_fixture import Workload
from dnlab_runtime.backend import Docker
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_multinode.services.runtime_operations import OperationStore,OperationDriver,digest
from dnlab_multinode.services import runtime_relay as relays
from dnlab_multinode.services.relay_host import Worker
from dnlab_multinode.utils.naming import micro_vd_container_name,runtime_relay_container_name


class RelayHost:
    """Run only the guard's stdin bootstrap, with its explicit deadline."""
    def run_input(self,command,payload,timeout=60):
        if shlex.split(command)!=['python3','-c',relays._WORKER_BOOTSTRAP]:
            raise ValueError('unexpected relay fixture command')
        if (type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0
                or not isinstance(payload,str)):
            raise ValueError('invalid relay fixture request or timeout')
        result=subprocess.run([sys.executable,'-c',relays._WORKER_BOOTSTRAP],
                              input=payload,text=True,capture_output=True,timeout=timeout)
        if result.returncode:
            raise RuntimeError('relay fixture worker rejected: '+result.stderr.strip())
        return result.stdout


def workload_program(nonce):
    if not isinstance(nonce,str) or len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce):
        raise ValueError('original workload nonce required')
    return "import signal,time\nrunning=True\ndef stop(*args):\n global running\n running=False\nsignal.signal(signal.SIGTERM,stop)\nsignal.signal(signal.SIGINT,stop)\nprint('relay-log-'+"+repr(nonce)+",flush=True)\nwhile running:time.sleep(.05)\n"


class ConsoleWorkload(Workload):
    def __init__(self,root,lab,node,image,target,runtime,store,*,gate_context=None):
        self.path=Path(root)/(node+'-workload.json');self.runtime=runtime;self.store=store;self.api=Docker()
        self.driver=OperationDriver(store,lambda actual:runtime if actual==target else self.wrong_target())
        existing=self.path.exists()
        self.record=json.loads(self.path.read_text()) if existing else {
            'phase':'planned','lab':lab,'node':node,'image':image,'target':target,'nonce':uuid.uuid4().hex,
            'journal_id':runtime.expected_journal_id,'cleanup_verified':False}
        expected={'lab':lab,'node':node,'image':image,'target':target,'journal_id':runtime.expected_journal_id}
        if any(self.record.get(key)!=value for key,value in expected.items()):
            raise RuntimeError('console workload original intent differs')
        nonce=self.record['nonce']
        self.spec={'kind':'linux','image':image,'container_name':micro_vd_container_name(lab,node),
                   'command':['python3','-u','-c',workload_program(nonce)],'stop_timeout':5}
        self.start={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'relay-start-'+node+'-'+nonce,
                    'expected_revision':0,'action':'start','spec':self.spec}
        if existing and (self.record.get('spec')!=self.spec or self.record.get('start')!=self.start):
            raise RuntimeError('console workload source or original request differs')
        from native_scope_registration import bind_gate_context
        bind_gate_context(self.record,gate_context,existing=existing)
        if not existing:
            self.record.update(spec=self.spec,start=self.start)
            self.save()

    def ensure(self):
        if self.api.request('GET','/images/'+self.record['image']+'/json')['Id']!=self.record['image']:
            raise RuntimeError('pinned console workload image required')
        self.drive(self.start)
        view=self.runtime.inspect_node(self.record['lab'],self.record['node'])
        if view['operation'] is not None or view['committed_state']!='running' or view['container_state']!='running':
            raise RuntimeError('original console workload not running')
        self.record.update(container_id=view['container_id'],revision=view['revision'],workload=view['workload'],phase='running');self.save()
        deadline=time.monotonic()+15
        while True:
            self.verify()
            logs=subprocess.run(['docker','logs','--tail','10',view['container_id']],capture_output=True,timeout=5)
            if logs.returncode:raise RuntimeError('original console workload logs unavailable')
            if ('relay-log-'+self.record['nonce']).encode() in logs.stdout:break
            if time.monotonic()>=deadline:raise RuntimeError('console workload log readiness timed out')
            time.sleep(.05)
        return view


def receive(sock,accept,*,timeout=15,limit=131072,observe=None):
    data=b'';deadline=time.monotonic()+timeout
    while True:
        if accept(data):return data
        remaining=deadline-time.monotonic()
        if remaining<=0:raise RuntimeError('relay response timed out')
        sock.settimeout(min(remaining,1))
        try:chunk=sock.recv(min(4096,limit-len(data)))
        except socket.timeout:continue
        if not chunk:
            if accept(data):return data
            raise RuntimeError('relay response ended before expected proof')
        data+=chunk
        if observe is not None:observe(data)
        if len(data)>=limit:raise RuntimeError('relay response exceeded bound')


def console_command(nonce):
    workload_program(nonce)  # Same strict nonce contract.
    marker=('relay-console-'+nonce).encode()
    command=("printf '%s%s\\n' 'relay-console-' '"+nonce+"'; exit\n").encode()
    if marker in command:raise RuntimeError('console proof must not match terminal echo')
    return command,marker


def probe(bind,port,key,container,nonce,output,expected_id=None):
    if expected_id is not None and (not isinstance(expected_id,str) or len(expected_id)!=64
                                   or any(c not in '0123456789abcdef' for c in expected_id)):
        raise ValueError('original console workload ID required')
    evidence={'container':container,'nonce':nonce,'action':'log','received_hex':''}
    def observe(data):
        evidence['received_hex']=data.hex();private_json(output,evidence,[key])
    private_json(output,evidence,[key])
    with socket.create_connection((bind,port),timeout=5) as sock:
        request=('LOG_ID '+key+' '+container+' '+expected_id if expected_id else 'LOG '+key+' '+container)
        sock.sendall((request+' all 0\n').encode())
        data=receive(sock,lambda value:('relay-log-'+nonce).encode() in value,observe=observe)
        if not data.startswith(b'OK\n'):raise RuntimeError('relay log acknowledgement differs')
    evidence.update(action='console-response',received_hex='',request_and_input_coalesced=True);private_json(output,evidence,[key])
    with socket.create_connection((bind,port),timeout=5) as sock:
        request=('CONNECT_ID '+key+' '+container+' '+expected_id if expected_id else 'CONNECT '+key+' '+container)
        command,marker=console_command(nonce)
        sock.sendall((request+'\n').encode()+command)
        def accepted(value):
            if value.startswith(b'ERR '):raise RuntimeError('relay console rejected')
            return marker in value
        receive(sock,accepted,observe=observe)
    return {'log_nonce_verified':True,'console_nonce_verified':True,'console_echo_excluded':True,
            'console_early_input_verified':True}


def deny(bind,port,key,container):
    with socket.create_connection((bind,port),timeout=5) as sock:
        sock.sendall(('LOG '+key+' '+container+' 1 0\n').encode())
        data=receive(sock,lambda value:b'\n' in value)
    if data!=b'ERR unauthorized\n':raise RuntimeError('relay authorization rejection differs')


def process_proof(pid):
    root=Path('/proc')/str(pid);fields=(root/'stat').read_text().rsplit(')',1)[1].split()
    if fields[0]=='Z':raise RuntimeError('relay process exited')
    return {'pid':pid,'start':fields[19],'network_namespace':(root/'ns/net').stat().st_ino}


def socket_fds(pid):
    result=set()
    for fd in (Path('/proc')/str(pid)/'fd').iterdir():
        try:value=os.readlink(fd)
        except FileNotFoundError:continue
        if value.startswith('socket:['):result.add(value[8:-1])
    return result


def listener_proof(api,cid,port,output):
    deadline=time.monotonic()+15;observations=[]
    while True:
        v=api.request('GET','/containers/'+cid+'/json');pid=v['State']['Pid']
        if v['Id']!=cid or not v['State']['Running'] or pid<=0:raise RuntimeError('original relay process unavailable')
        before=process_proof(pid);fds_before=socket_fds(pid);candidates=[]
        for family in ('tcp','tcp6'):
            for line in (Path('/proc')/str(pid)/'net'/family).read_text().splitlines()[1:]:
                row=line.split();address,number=row[1].split(':')
                if row[3]=='0A' and int(number,16)==port:
                    candidates.append({'family':family,'address':address,'inode':row[9]})
        after=process_proof(pid);fds_after=socket_fds(pid)
        current=api.request('GET','/containers/'+cid+'/json')
        same=(before==after and current['Id']==cid and current['State']['Running'] and current['State']['Pid']==pid
              and current['State']['StartedAt']==v['State']['StartedAt']
              and before['network_namespace']==Path('/proc/self/ns/net').stat().st_ino)
        observations.append({'process':before,'same_generation':same,'candidates':candidates,
                             'owned_before':sorted(fds_before),'owned_after':sorted(fds_after)})
        private_json(output,observations)
        if not same:raise RuntimeError('relay process/namespace changed during listener observation')
        if candidates:
            if len(candidates)!=1 or candidates[0]['family']!='tcp' or candidates[0]['address']!='0100007F':
                raise RuntimeError('relay listener conflicts with exact loopback bind')
            inode=candidates[0]['inode']
            if inode in fds_before and inode in fds_after:return {**before,'socket_inode':inode,'bind_ip':'127.0.0.1','port':port}
            if inode not in fds_after:raise RuntimeError('relay listener belongs to another process')
        if time.monotonic()>=deadline:raise RuntimeError('qualified relay listener not ready')
        time.sleep(.05)


def protected(api):
    value={'containers':{},'networks':{}}
    for row in api.request('GET','/containers/json?all=1'):
        c=api.request('GET','/containers/'+row['Id']+'/json')
        value['containers'][row['Id']]={k:c[k] for k in ('Id','Name','Image')}
        value['containers'][row['Id']]['state']={k:c['State'][k] for k in ('Pid','StartedAt','Running')}
        value['containers'][row['Id']]['restart_count']=c['RestartCount']
    for row in api.request('GET','/networks'):
        n=api.request('GET','/networks/'+row['Id'])
        value['networks'][row['Id']]={k:n.get(k) for k in ('Name','Driver','IPAM','Options','Labels','Containers')}
    return value


def source_hashes():
    root=SOURCE.parent.parent
    paths=set((SOURCE/'dnlab_runtime').rglob('*.py'))
    paths.add(SOURCE.parent/'multinode/runtime-relay/relay.py')
    paths.update(SOURCE.parent/'multinode/dnlab_multinode/services'/name for name in
                 ('runtime_relay.py','relay_host.py','jumphost_host.py','jumphost.py','runtime_operations.py','custom_runtime.py','paths.py'))
    paths.update(Path(__file__).with_name(name) for name in
                 ('relay_console_smoke.py','http_workload_fixture.py','smoke.py','management_barrier_smoke.py','management_service_diagnostics.py'))
    return {str(p.relative_to(root)):hashlib.sha256(p.read_bytes()).hexdigest() for p in sorted(paths)}


def plugin_hashes():
    return {name:hashlib.sha256(Path(name).read_bytes()).hexdigest() if Path(name).is_file() else None for name in
            ('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py','/var/lib/dnlab-vrf-plugin/state.json')}


def container_diagnostic(record,value):
    """Configuration comparisons, without environment or command values."""
    if value is None:return {'present':False}
    result={'present':True,**{k:value.get(k) for k in ('Id','Name','Image')},
            'state':{k:value.get('State',{}).get(k) for k in ('Pid','Running','StartedAt')}}
    if record is None:return result
    c=record['config'];base=record['image'].get('Config',{})
    expected=dict(v.split('=',1) for v in base.get('Env') or [])
    expected.update(RELAY_BIND=c['bind_ip'],RELAY_PORT=str(c['port']),RELAY_API_KEY=c['api_key'],
                    RELAY_ALLOWED_CONTAINERS=' '.join(c['allowed']),RELAY_ALLOWED_PREFIX=c['prefix'])
    actual=value.get('Config',{});env=dict(v.split('=',1) for v in actual.get('Env') or [])
    labels=dict(base.get('Labels') or {})
    labels.update({'org.dnlab.relay.scope':digest(['relay-v1',c['lab'],c['host']]),
                   'org.dnlab.relay.nonce':record['nonce'],'org.dnlab.relay.config':digest(c)})
    result.update(expected_container_id=record.get('container_id'),expected_image_id=record['image']['Id'],
                  env_matches={k:env.get(k)==v for k,v in expected.items()},
                  env_count={'expected':len(expected),'actual':len(actual.get('Env') or [])},
                  unexpected_env_keys=sorted(set(env)-set(expected)),
                  labels_match=actual.get('Labels')==labels,
                  entrypoint_matches=actual.get('Entrypoint')==base.get('Entrypoint'),
                  command_matches=actual.get('Cmd')==base.get('Cmd'),
                  host={k:value.get('HostConfig',{}).get(k) for k in
                        ('NetworkMode','Privileged','Binds','CapAdd','PortBindings','RestartPolicy','PidMode','IpcMode')})
    return result


def failure_snapshot(root,api,config):
    snapshot={};record=None
    try:
        record=Worker(config['lab'],config['host'],directory=Path(root)/'relay').read()
        if record:snapshot['journal']={k:record.get(k) for k in ('phase','goal','nonce','container_id','error_type')}
    except Exception as error:snapshot['journal_observation_error']=type(error).__name__
    try:snapshot['container']=container_diagnostic(record,api.inspect(config['name']))
    except Exception as error:snapshot['container_observation_error']=type(error).__name__
    private_json(Path(root)/'failure-before-cleanup.json',snapshot,[config['api_key']])


def run(root,relay_image,workload_image):
    if relays.PATHS.docker_socket not in ('unix:///var/run/docker.sock','/var/run/docker.sock'):
        raise RuntimeError('this local fixture requires the standard Docker Unix provider')
    require_qualified_cleanup(Docker())
    root=Path(root);root.mkdir(parents=True,mode=0o700,exist_ok=False)
    api=Docker();baseline=protected(api);private_json(root/'protected-before.json',baseline)
    sources=source_hashes();plugins=plugin_hashes();boot=Path('/proc/sys/kernel/random/boot_id').read_text().strip()
    private_json(root/'preflight.json',{'source_hashes':sources,'plugin_hashes':plugins,'boot_id':boot,
                                      'relay_image':relay_image,'workload_image':workload_image})
    for image in (relay_image,workload_image):
        if api.request('GET','/images/'+image+'/json')['Id']!=image:raise RuntimeError('immutable image IDs required')
    labels=api.request('GET','/images/'+relay_image+'/json').get('Config',{}).get('Labels') or {}
    if 'qualified-container-id-v1' not in labels.get('io.dnlab.runtime-relay.capabilities','').split(','):
        raise RuntimeError('relay candidate lacks qualified container ID capability')
    lab='drsp-relay-'+uuid.uuid4().hex[:10];key=secrets.token_hex(32)
    with socket.socket() as free:free.bind(('127.0.0.1',0));port=free.getsockname()[1]
    config={'lab':lab,'host':'master','generation':uuid.uuid4().hex,'name':runtime_relay_container_name(lab),
            'image':relay_image,'bind_ip':'127.0.0.1','port':port,'api_key':key,
            'allowed':[micro_vd_container_name(lab,'vd1')],'prefix':'clab-dnlab-'+lab+'-','docker_socket':'/var/run/docker.sock'}
    private_json(root/'intent.json',{'config':config,'relay_attempted':False})
    previous=relays.PATHS;relays.PATHS=replace(previous,relay_journal_dir=str(root/'relay'))
    (root/'runtime').mkdir(mode=0o700);service=Service('native',root/'runtime',None,lab)
    workloads=[];store=None;relay_record=None;attempted=False
    report={'status':'running','scope':'one host; native Linux console/log relay; no GUI or NOS qualification','checks':[]}
    try:
        report['phase']='runtime-bootstrap'
        service.start();report['runtime_process']=process_proof(service.process.pid)
        private_json(root/'runtime-process.json',report['runtime_process'])
        runtime=RuntimeClient(Local(),socket_path=service.client.socket_path)
        runtime=runtime.bound_to(runtime.qualify_node(inspection=True)['journal_id'])
        target={'host':'master','socket_path':service.client.socket_path,'container_name':None}
        store=OperationStore(root/'coordinator')
        report['phase']='first-workload'
        first=ConsoleWorkload(root,lab,'vd1',workload_image,target,runtime,store);workloads.append(first);first.ensure()
        report['phase']='relay-preflight'
        relays._guard(RelayHost(),lab,'master','preflight',config)
        attempted=True;private_json(root/'intent.json',{'config':config,'relay_attempted':True})
        report['phase']='relay-create-start'
        relay_record=relays._guard(RelayHost(),lab,'master','ensure',config)
        private_json(root/'relay-birth.json',relay_record)
        report['phase']='listener-qualification'
        report['listener']=listener_proof(api,relay_record['container_id'],port,root/'listener-observations.json')
        report['phase']='first-console-log'
        first.verify();report['first']=probe('127.0.0.1',port,key,first.spec['container_name'],first.record['nonce'],root/'vd1-protocol.json',first.record['container_id']);first.verify()
        deny('127.0.0.1',port,'wrong-'+uuid.uuid4().hex,first.spec['container_name'])
        deny('127.0.0.1',port,key,micro_vd_container_name(lab+'-foreign','vd1'))
        report['authorization_rejections_verified']=True
        report['phase']='late-workload-spawn'
        second=ConsoleWorkload(root,lab,'vd2',workload_image,target,runtime,store);workloads.append(second);second.ensure()
        current=relays._guard(RelayHost(),lab,'master','ensure',config)
        if current['container_id']!=relay_record['container_id'] or current['nonce']!=relay_record['nonce']:
            raise RuntimeError('relay generation changed after late VD spawn')
        report['phase']='late-spawn-console-log'
        report['second']=probe('127.0.0.1',port,key,second.spec['container_name'],second.record['nonce'],root/'vd2-protocol.json',second.record['container_id'])
        first.verify();second.verify()
        report['listener_after']=listener_proof(api,relay_record['container_id'],port,root/'listener-after-observations.json')
        if report['listener_after']!=report['listener']:raise RuntimeError('relay process/listener changed during late spawn')
        report['checks'].append('original relay owns exact loopback listener; console and logs bind original nonces; bad key/foreign lab denied; late VD uses prefix without relay restart')
        report['status']='passed'
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error))
        private_json(root/'original-error.json',{'phase':report.get('phase','setup'),'causes':exception_chain(error)},[key])
        failure_snapshot(root,api,config)
    finally:
        errors=[];ids=[];cleanup_causes=[]
        def cleanup_error(role,error):
            errors.append(role+': '+str(error));cleanup_causes.append({'role':role,'causes':exception_chain(error)})
            private_json(root/'cleanup-errors.json',cleanup_causes,[key])
            failure_snapshot(root,api,config)
        try:
            worker=Worker(lab,'master',directory=root/'relay');saved=worker.read()
            if saved:
                if saved['config']!=config:raise RuntimeError('fixture relay intent differs')
                result=relays._guard(RelayHost(),lab,'master','delete',generation=config['generation'])
                if result['phase']!='cleaned':raise RuntimeError('relay cleanup pending')
                if result.get('container_id'):ids.append(result['container_id'])
                relays.verify_relay_cleaned(lab,'master',RelayHost(),config['generation'])
            elif attempted:raise RuntimeError('relay attempt outcome not qualified')
        except Exception as error:cleanup_error('relay',error)
        for workload in reversed(workloads):
            try:
                workload.cleanup()
                if workload.record.get('container_id'):ids.append(workload.record['container_id'])
            except Exception as error:cleanup_error('workload',error)
        try:service.stop()
        except Exception as error:cleanup_error('runtime',error)
        if store is not None:store.close()
        relays.PATHS=previous
        for cid in ids:
            if api.inspect(cid) is not None:errors.append('original container ID remains')
        after=protected(api);private_json(root/'protected-after.json',after)
        if baseline!=after:errors.append('protected resources or Docker inventory changed')
        if Path(service.client.socket_path).exists():errors.append('runtime socket remains')
        if source_hashes()!=sources:errors.append('fixture/runtime source changed')
        if plugin_hashes()!=plugins:errors.append('installed plugin changed')
        if Path('/proc/sys/kernel/random/boot_id').read_text().strip()!=boot:errors.append('host boot changed')
        report['cleanup']={'verified':not errors,'errors':errors,'original_ids':ids,'runtime_stopped':service.process is None,
                           'protected_containers':len(baseline['containers']),'protected_networks':len(baseline['networks'])}
        if errors:report['status']='failed'
        private_json(root/'report.json',report,[key]);print(json.dumps({'status':report['status'],'cleanup':report['cleanup']}),flush=True)
    if report['status']!='passed':raise RuntimeError('relay gate failed; see durable report')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output',required=True);parser.add_argument('--relay-image',required=True)
    parser.add_argument('--workload-image',required=True);parser.add_argument('--execute',action='store_true')
    args=parser.parse_args()
    if args.execute:run(args.output,args.relay_image,args.workload_image)
    else:print(json.dumps({'status':'plan-only','output':args.output,'execute_required':True}))
