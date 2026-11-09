#!/usr/bin/env python3
"""Native/image handoff and link API on isolated, labelled stock bridges."""
import argparse
import copy
import hashlib
import json
import multiprocessing
from pathlib import Path
import os
import re
import shlex
import signal
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import uuid

SOURCE=Path(__file__).resolve().parents[1];sys.path.insert(0,str(SOURCE))
from dnlab_runtime.backend import Backend,Linux,labels,LABEL
from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.endpoint_name_probe import CANARY_PROGRAM,READY_PROGRAM
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.management_authority import assignment
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase
from dnlab_runtime.stable_management import Handoff,StablePort
from dnlab_runtime.transport import Client,Server


class DiagnosticLinux(Linux):
    """Fixture-only tracing, retaining the primitive's failure semantics."""
    def __init__(self,path):self.path=path;self.phase=None;self.before_delete=None

    def command(self,args,pid=None):
        if self.before_delete is not None and args[:2]==['link','delete'] and pid is None:
            self.before_delete(args[2])
        return super().command(args,pid)

    def delete_link(self,expected):
        if self.before_delete is not None:self.before_delete(expected['ifname'])
        return super().delete_link(expected)

    def record(self,event):
        event={**event,'phase':self.phase,'pid':os.getpid(),'monotonic_ns':time.monotonic_ns()}
        fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        try:
            data=(json.dumps(event)+'\n').encode()
            while data:data=data[os.write(fd,data):]
            os.fsync(fd)
        finally:os.close(fd)

    def run(self,argv,*,pass_fds=()):
        if self.phase is None:return super().run(argv,pass_fds=pass_fds)
        command_id=uuid.uuid4().hex
        self.record({'event':'command-start','command_id':command_id,'argv':argv})
        try:
            result=subprocess.run(argv,capture_output=True,text=True,timeout=30,check=False,pass_fds=pass_fds)
        except Exception as error:
            self.record({'event':'command-exception','command_id':command_id,'argv':argv,
                         'exception':type(error).__name__,'detail':str(error)})
            raise
        self.record({'event':'command-result','command_id':command_id,'argv':argv,'exit_code':result.returncode,
                     'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode:raise RuntimeErrorBase(f'host primitive {argv[0]} failed with exit code {result.returncode}')
        return result.stdout


def run(image,crash_stage,*,endpoint_delete_race=False,runtime_image=None,image_handoff=False,ssh_transport=False):
    if image_handoff and runtime_image is None:raise ValueError('image handoff requires runtime image')
    if ssh_transport and runtime_image is None:raise ValueError('SSH transport requires runtime image')
    if runtime_image is not None and not re.fullmatch(r'sha256:[0-9a-f]{64}',runtime_image):
        raise ValueError('runtime image must be an immutable local image ID')
    token=uuid.uuid4().hex[:6];lab='drsp-mgmt-'+token
    root=Path(tempfile.mkdtemp(prefix='dnlab-management-link-'));root.chmod(0o700)
    diagnostics=DiagnosticLinux(root/'cleanup-events.jsonl')
    backend=Backend(linux=diagnostics);journal=Journal(root/'state');engine=Engine(journal,backend)
    networks=[];nodes={};api_stops={};server=None;thread=None;port=None;handoff=None;daemon_id=None;ssh_fixture=None;coordinator_store=None
    daemon_name='drsp-mgmt-daemon-'+token
    report={'status':'running','scope':'native Linux on owned stock bridges; no NOS/dnlab-vrf qualification','crash':crash_stage}
    if runtime_image:report['runtime_image']=runtime_image
    if image_handoff:report['image_handoff_diagnostics']='image-handoff-events.jsonl'
    client=Client(str(root/'socket'))
    def command(args):
        result=subprocess.run(args,text=True,capture_output=True,timeout=35)
        if diagnostics.phase is not None:
            diagnostics.record({'event':'fixture-command-result','argv':args,'exit_code':result.returncode,
                                'stdout':result.stdout,'stderr':result.stderr})
        if result.returncode:raise RuntimeError('fixture command failed: '+args[0]+' '+result.stderr.strip())
        return result.stdout.strip()
    def snapshot(phase):
        diagnostics.phase=phase
        result={'event':'snapshot','nodes':{},'networks':[]}
        for node,(request,spec,expected_id) in nodes.items():
            state={'expected_id':expected_id}
            try:
                container=backend.inspect(request,spec)
                state['container']=None if container is None else {k:container.get(k) for k in ('Id','State','NetworkSettings')}
                state['host_interfaces']={e['host_interface']:backend.linux.link(e['host_interface']) for e in spec.get('endpoints',[])}
                if container and container['State']['Running']:
                    with backend.namespace(request,spec,container) as ns:
                        state['guest_interfaces']={e['node_interface']:backend.linux.link(e['node_interface'],ns) for e in spec.get('endpoints',[])}
            except Exception as error:state['snapshot_error']=str(error)
            result['nodes'][node]=state
        for network in networks:
            try:
                current=backend.docker.request('GET','/networks/'+network['Id'],missing_ok=True)
                result['networks'].append({'expected_id':network['Id'],'current':current})
            except Exception as error:result['networks'].append({'expected_id':network['Id'],'snapshot_error':str(error)})
        diagnostics.record(result)
    def prepare_spec(node,management=None):
        nonce=uuid.uuid4().hex
        return {'kind':'linux','container_name':'drsp-mgmt-'+token+'-'+node,'image':image,
                'command':['python3','-u','-c',CANARY_PROGRAM,nonce,'0'],
                'endpoints':[{'host_interface':'drsp'+token+node,'node_interface':'eth1','mtu':1500}],
                **({'management':management} if management else {})}
    def ready(node):
        request,spec,identity=nodes[node]
        backend.docker.exec_checked(identity,['python3','-c',READY_PROGRAM,spec['command'][-2]])
    def identity(node):
        request,spec,_=nodes[node];container=backend.inspect(request,spec)
        with backend.namespace(request,spec,container) as ns:
            host=backend.linux.link(spec['endpoints'][0]['host_interface']);peer=backend.linux.link('eth1',ns)
        return {'Id':container['Id'],'StartedAt':container['State']['StartedAt'],'Pid':container['State']['Pid'],
                'host':{k:host.get(k) for k in ('ifname','ifindex','ifalias','address','link_index')},
                'peer':{k:peer.get(k) for k in ('ifname','ifindex','ifalias','address','link_index')}}
    def ping(node,target):
        request,spec,_=nodes[node];container=backend.inspect(request,spec)
        command(['nsenter','-t',str(container['State']['Pid']),'-n','ping','-c','1','-W','2',target])
    def provision(node,request,spec,network,mac):
        from dnlab_runtime.workload_generation import reserve,bind,committed
        creator='fixture-'+uuid.uuid4().hex
        birth=reserve(journal,request,spec,creator)
        config={'Image':image,'Cmd':spec['command'],'Labels':{**labels(request,spec),'io.dnlab.spike':token,
                         LABEL+'.creator':creator,LABEL+'.birth':birth['nonce']},
                'HostConfig':{'NetworkMode':network['Name'],'RestartPolicy':{'Name':'no'}},
                'NetworkingConfig':{'EndpointsConfig':{network['Name']:{'IPAMConfig':{'IPv4Address':spec['management']['ipv4']},
                    'MacAddress':mac,'DriverOpts':{'com.docker.network.endpoint.ifname':'dnmu0'}}}}}
        container=backend.docker.create(spec['container_name'],config);nodes[node]=(request,spec,container['Id'])
        bind(journal,request,spec,creator,container['Id'])
        backend.docker.start(container['Id']);ready(node)
        backend.ensure_endpoint(request,spec,spec['endpoints'][0]);backend.verify(request,spec)
        with journal.transaction():
            committed(journal,{'lab':request['lab_id'],'node':request['node_id']},spec,'running',1)
            journal.db.execute('INSERT INTO nodes VALUES(?,?,?,?,?)',(request['lab_id'],request['node_id'],1,json.dumps(spec),'running'))
    def foreign_refused(actor,operation_id):
        for call in (lambda:actor.get(operation_id),lambda:actor.execute(operation_id),lambda:actor.rollback(operation_id)):
            try:call()
            except Conflict:pass
            else:raise RuntimeError('foreign management operation accepted')
    def link_operation(client,payload):
        value=client.request('POST','/v1/link-operations',payload);deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            current=client.request('GET','/v1/link-operations/'+value['id'])
            if current['phase']=='completed':return current
            if current['phase'] in ('failed','cancelled','recovery_required'):raise RuntimeError('link operation '+current['phase']+': '+current['error'])
            time.sleep(.05)
        raise RuntimeError('native link operation timeout')
    def daemon_inspect():
        value=backend.docker.inspect(daemon_id)
        if value is None:return None
        if (value['Id']!=daemon_id or value['Name']!='/'+daemon_name or value['Image']!=runtime_image
                or value['Config']['Labels']!={'io.dnlab.spike':token,'io.dnlab.management-gate':'daemon'}):
            raise Conflict('fixture daemon ownership changed')
        return value
    def daemon_stop():
        value=daemon_inspect()
        if value is None:return
        if value['State']['Running']:
            backend.docker.signal(daemon_id,'SIGKILL')
            deadline=time.monotonic()+15
            while daemon_inspect()['State']['Running']:
                if time.monotonic()>=deadline:raise RuntimeError('fixture daemon stop timeout')
                time.sleep(.05)
    def daemon_start(client):
        assert daemon_inspect() is not None
        backend.docker.start(daemon_id);deadline=time.monotonic()+20
        while True:
            try:
                client.request('GET','/v1/capabilities');return
            except (OSError,RuntimeErrorBase):
                value=daemon_inspect()
                if value is None or not value['State']['Running'] or time.monotonic()>=deadline:
                    raise RuntimeError('fixture daemon API readiness failed')
                time.sleep(.05)
    def create_daemon():
        nonlocal daemon_id
        daemon_id=command(['docker','create','--name',daemon_name,'--privileged','--network','host','--pid','host',
            '--label','io.dnlab.spike='+token,'--label','io.dnlab.management-gate=daemon',
            '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
            '--mount',f'type=bind,src={root},dst={root}',
            '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={root}/host-boot-id,readonly',
            '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={root}/host-boot-id',runtime_image,
            '--socket',str(root/'socket'),'serve','--state-dir',str(root/'state')])
        daemon_start(client)
        audit_code="import importlib,hashlib,json; from pathlib import Path; names=['backend','management_authority','execution','stable_management','transport','kernel_endpoint']; print(json.dumps({n:{'path':(p:=Path(importlib.import_module('dnlab_runtime.'+n).__file__)).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for n in names}))"
        audit=json.loads(command(['docker','exec','--workdir','/',daemon_id,'python3','-c',audit_code]))
        for name,entry in audit.items():
            assert '/site-packages/dnlab_runtime/' in entry['path']
            assert entry['sha256']==hashlib.sha256((SOURCE/'dnlab_runtime'/(name+'.py')).read_bytes()).hexdigest()
        report['image_installed_modules']=audit
    def image_action(actor,action,**options):
        assert daemon_inspect()['State']['Running']
        config={'state_dir':str(root/'state'),'events':str(root/'image-handoff-events.jsonl'),
                'request':actor.request,'spec':actor.spec,'mac':actor.port.mac,'spike_owner':token,'action':action,**options}
        program=Path(__file__).with_name('management_image_handoff_worker.py').read_text()
        result=subprocess.run(['docker','exec','-i','--workdir','/',daemon_id,'python3','-c',program],
                              input=json.dumps(config),text=True,capture_output=True,timeout=75)
        diagnostics.record({'event':'image-handoff-exec','action':action,'exit_code':result.returncode,
                            'stdout':result.stdout,'stderr':result.stderr})
        if options.get('crash'):
            assert result.returncode==137 and daemon_inspect()['State']['Running'],result.stderr
            return
        value=json.loads(result.stdout)
        if not value['ok']:
            if value['error_type']=='Conflict':raise Conflict(value['error'])
            raise RuntimeErrorBase(value['error'])
        assert result.returncode==0,result.stderr
        return value['result']
    def submit_move(actor,key,target,address,revision):
        if image_handoff:return image_action(actor,'submit',request_id=key,target_name=target,target_ip=address,revision=revision)
        return actor.submit(key,target,address,expected_node_revision=revision)
    def execute_move(actor,operation_id,**options):
        if image_handoff:return image_action(actor,'execute',operation_id=operation_id,**options)
        return actor.execute(operation_id)
    try:
        base=64+(int(token[:2],16)%40)*2
        for i,color in enumerate(('blue','red','blue-two','red-two')):
            name='drsp-mgmt-'+token+'-'+color
            identity_net=command(['docker','network','create','--driver','bridge','--subnet',f'198.18.{base+i}.0/24','--label','io.dnlab.spike='+token,name])
            networks.append(backend.docker.network(identity_net))
        main_request={'lab_id':lab,'node_id':'a'}
        main_spec=prepare_spec('a',{'network':networks[0]['Name'],'ipv4':f'198.18.{base}.2'})
        mac='02:da:'+':'.join(token[i:i+2] for i in (0,2,4))+':01'
        backend.docker.require_endpoint_name_support()
        provision('a',main_request,main_spec,networks[0],mac)
        other_request={'lab_id':lab+'-two','node_id':'a'}
        other_spec=prepare_spec('c',{'network':networks[2]['Name'],'ipv4':f'198.18.{base+2}.2'})
        other_mac=mac[:-2]+'02'
        provision('c',other_request,other_spec,networks[2],other_mac)
        control_request={'lab_id':lab,'node_id':'b'};control_spec=prepare_spec('b')
        operation=journal.submit({'schema_version':1,'lab_id':lab,'node_id':'b','request_id':'start-b','action':'start','expected_revision':0,'spec':control_spec})
        result=engine.execute(operation['id']);assert result['phase']=='completed',result
        container=backend.inspect(control_request,control_spec);nodes['b']=(control_request,control_spec,container['Id']);ready('b')
        for i,node in enumerate(('a','b'),1):
            request,spec,_=nodes[node];container=backend.inspect(request,spec)
            with backend.namespace(request,spec,container) as ns:backend.linux.command(['address','add',f'192.0.2.{i}/24','dev','eth1'],ns)
        port=StablePort(backend,main_request,main_spec,mac)
        handoff=Handoff(journal,backend,main_request,main_spec,port,spike_owner=token)
        port.prepare(handoff.capture(networks[0]))
        other_port=StablePort(backend,other_request,other_spec,other_mac)
        second=Handoff(journal,backend,other_request,other_spec,other_port,spike_owner=token)
        other_port.prepare(second.capture(networks[2]))
        before={node:identity(node) for node in nodes};stable=port.snapshot();other_stable=other_port.snapshot()
        if image_handoff:create_daemon()
        first_operation=submit_move(handoff,'move',networks[1]['Name'],f'198.18.{base+1}.2',1)
        second_operation=submit_move(second,'move',networks[3]['Name'],f'198.18.{base+3}.2',1)
        assert first_operation['id']!=second_operation['id']
        foreign_refused(handoff,second_operation['id']);foreign_refused(second,first_operation['id'])
        def child():
            child_journal=Journal(root/'state');child_backend=Backend();Engine(child_journal,child_backend)
            child_port=StablePort(child_backend,main_request,main_spec,mac)
            worker=Handoff(child_journal,child_backend,main_request,main_spec,child_port,spike_owner=token)
            original=worker.phase
            if crash_stage=='during':
                def interrupt(action,table,column,*args):
                    if action==sqlite3.SQLITE_UPDATE and table=='nodes' and column=='revision':os.kill(os.getpid(),signal.SIGKILL)
                    return sqlite3.SQLITE_OK
                child_journal.db.set_authorizer(interrupt)
            def phase(identifier,value,error=''):
                if value=='completed' and crash_stage=='before':os.kill(os.getpid(),signal.SIGKILL)
                original(identifier,value,error)
                if value=='completed' and crash_stage=='after':os.kill(os.getpid(),signal.SIGKILL)
            worker.phase=phase;worker.execute(worker.by_request('move')['id'])
        if image_handoff:
            execute_move(handoff,first_operation['id'],crash=crash_stage)
        else:
            process=multiprocessing.get_context('fork').Process(target=child);process.start();process.join(45)
            if process.is_alive():process.kill();process.join();raise RuntimeError('owned handoff worker timeout')
            assert process.exitcode==-signal.SIGKILL
        report['after_crash_assignment']=assignment(journal,lab,'a')['phase']
        assert report['after_crash_assignment']==('stable' if crash_stage=='after' else 'pending')
        assert second.get(second_operation['id'])==second_operation and other_port.snapshot()==other_stable
        journal.close();journal=Journal(root/'state');engine=Engine(journal,backend)
        handoff=Handoff(journal,backend,main_request,main_spec,port,spike_owner=token)
        second=Handoff(journal,backend,other_request,other_spec,other_port,spike_owner=token)
        assert execute_move(handoff,first_operation['id'])['phase']=='completed'
        assert journal.node(lab,'a')['revision']==2 and journal.node(lab,'a')['spec']==main_spec
        assert port.snapshot()==stable and all(identity(node)==before[node] for node in nodes)
        backend.verify(main_request,main_spec);ping('a',networks[1]['IPAM']['Config'][0]['Gateway'])
        first_assignment=assignment(journal,lab,'a')
        assert second.by_request('move')==second_operation
        assert execute_move(second,second_operation['id'])['phase']=='completed'
        assert submit_move(second,'move',networks[3]['Name'],f'198.18.{base+3}.2',1)['id']==second_operation['id']
        assert assignment(journal,lab,'a')==first_assignment and port.snapshot()==stable
        assert journal.node(other_request['lab_id'],'a')['revision']==2 and other_port.snapshot()==other_stable
        backend.verify(other_request,other_spec);ping('c',networks[3]['IPAM']['Config'][0]['Gateway'])
        foreign_refused(handoff,second_operation['id']);foreign_refused(second,first_operation['id'])
        report['same_request_id_independent_labs']=True
        report['foreign_operation_access_and_recovery_refused']=True
        report['other_lab_pending_move_preserved_across_crash']=True
        if runtime_image:
            if daemon_id is None:create_daemon()
        else:
            server=Server(str(root/'socket'),engine);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
        payload={'schema_version':1,'kind':'bridge','lab_id':lab,'link_id':'l0','action':'create','request_id':'after-move',
                 'endpoints':[{'node_id':node,'host_interface':nodes[node][1]['endpoints'][0]['host_interface'],
                               'expected_node_revision':2 if node=='a' else 1} for node in ('a','b')],'spec':{'mtu':1500}}
        link_operation(client,payload);ping('a','192.0.2.2')
        if runtime_image:
            daemon_stop();daemon_start(client)
            retry=copy.deepcopy(payload);retry['request_id']='image-restart-link-retry'
            link_operation(client,retry);ping('a','192.0.2.2')
            report['image_daemon_restart_preserves_assignment_and_link']=True
        assert all(identity(node)==before[node] for node in nodes) and port.snapshot()==stable
        current=client.request('GET','/v1/nodes/'+lab+'/a');assert current['management']['connection']['network_name']==networks[1]['Name']
        stale=copy.deepcopy(payload);stale['request_id']='stale';stale['endpoints'][0]['expected_node_revision']=1
        try:client.request('POST','/v1/link-operations',stale)
        except RuntimeErrorBase:pass
        else:raise RuntimeError('stale node revision accepted')
        ping('a','192.0.2.2')
        returning=submit_move(handoff,'return',networks[0]['Name'],f'198.18.{base}.3',2)
        pending=copy.deepcopy(payload);pending['request_id']='blocked-during-move'
        try:client.request('POST','/v1/link-operations',pending)
        except RuntimeErrorBase:pass
        else:raise RuntimeError('data operation accepted while management pending')
        ping('a','192.0.2.2')
        assert execute_move(handoff,returning['id'])['phase']=='completed'
        assert journal.node(lab,'a')['revision']==3 and port.snapshot()==stable
        assert all(identity(node)==before[node] for node in nodes)
        backend.verify(main_request,main_spec);ping('a','192.0.2.2');ping('a',networks[0]['IPAM']['Config'][0]['Gateway'])
        revision=3
        if image_handoff:
            rollback=submit_move(handoff,'rollback-image',networks[1]['Name'],f'198.18.{base+1}.3',3)
            assert execute_move(handoff,rollback['id'],fail_target_bind=True)['phase']=='rolled_back'
            revision=4
            assert journal.node(lab,'a')['revision']==revision and port.snapshot()==stable
            assert assignment(journal,lab,'a')['connection']['network_name']==networks[0]['Name']
            assert all(identity(node)==before[node] for node in nodes)
            ping('a','192.0.2.2');ping('a',networks[0]['IPAM']['Config'][0]['Gateway'])
            for actor,foreign in ((handoff,second_operation['id']),(second,first_operation['id'])):
                for action in ('get','execute','rollback'):
                    try:image_action(actor,action,operation_id=foreign)
                    except Conflict:pass
                    else:raise RuntimeError('foreign image handoff access accepted')
            report['handoff_submit_execute_replay_rollback_inside_image']=True
        payload['endpoints'][0]['expected_node_revision']=revision
        repeated=copy.deepcopy(payload);repeated['request_id']='retry-after-return'
        link_operation(client,repeated);ping('a','192.0.2.2')
        report['active_data_link_survives_second_move']=True
        report['pending_move_blocks_new_link_operations']=True
        deletion={k:v for k,v in payload.items() if k!='spec'};deletion.update(action='delete',request_id='delete')
        link_operation(client,deletion)
        if runtime_image:
            sys.path.insert(0,str(SOURCE.parent/'multinode'))
            from dnlab_multinode.services.custom_runtime import RuntimeClient
            class LocalStdinCLI:
                commands=[];stdin_calls=0
                def run(self,command):return self.execute(command,None)
                def run_input(self,command,payload):
                    self.stdin_calls+=1
                    assert 'fixture-stdin-value' not in command
                    return self.execute(command,payload)
                def execute(self,command,payload):
                    self.commands.append(command)
                    result=subprocess.run(shlex.split(command),input=payload,text=True,capture_output=True,timeout=30)
                    if result.returncode:raise RuntimeError('fixture runtime CLI failed: '+result.stderr.strip())
                    return result.stdout
            cli=LocalStdinCLI()
            if ssh_transport:
                from ssh_loopback_fixture import LoopbackSSH
                prefix=['docker','exec','-i',daemon_name,'dnlab-runtime','--socket',str(root/'socket')]
                ssh_fixture=LoopbackSSH(root,prefix,daemon_inspect);cli=ssh_fixture
            adapter=RuntimeClient(cli,socket_path=str(root/'socket'),container_name=daemon_name)
            extra_spec=prepare_spec('d')
            extra_spec['env']={'DNLAB_RUNTIME_FIXTURE_VALUE':'fixture-stdin-value'}
            raw={'schema_version':1,'lab_id':lab,'node_id':'d','request_id':'image-spawn-d',
                 'action':'start','expected_revision':0,'spec':extra_spec}
            planned=adapter.plan_node(raw)
            assert planned['mutations_performed'] is False and planned['affected_nodes']==['d']
            with journal.execution_lock:
                if ssh_fixture is not None:
                    from dnlab_multinode.services.ssh import SSHError
                    ssh_fixture.drop_next_submit_ack=True
                    try:adapter.submit_node(raw)
                    except SSHError:pass
                    else:raise RuntimeError('fixture submit acknowledgement was not dropped')
                    ssh_fixture.reconnect();extra=adapter.find_node_request(raw)
                    assert extra is not None and extra['phase']=='queued'
                    report['request_lookup_recovers_lost_submit_ack']=True
                else:extra=adapter.submit_node(raw)
                assert adapter.submit_node(raw)['id']==extra['id']
                time.sleep(.3)
                assert adapter.node_operation(extra['id'])['phase']=='queued'
                if ssh_fixture is not None:
                    ssh_fixture.reconnect()
                    assert adapter.node_operation(extra['id'])['phase']=='queued'
                    report['SSH_reconnect_preserves_accepted_operation']=True
            deadline=time.monotonic()+30
            while True:
                state=adapter.node_operation(extra['id'])
                value=backend.inspect(raw,extra_spec)
                if value:
                    assert value['Config']['Labels'].get('org.dnlab.runtime.creator')==extra['id']
                    nodes['d']=(raw,extra_spec,value['Id'])
                if state['phase'] in ('completed','failed','cancelled','recovery_required'):break
                if time.monotonic()>=deadline:raise RuntimeError('image daemon did not resume queued operation')
                time.sleep(.05)
            assert state['phase']=='completed',state
            assert adapter.wait_node(extra['id'])['phase']=='completed'
            ready('d');report['image_worker_waits_for_host_execution_gate_then_resumes']=True
            with backend.namespace(raw,extra_spec,value):
                stopping=adapter.submit_node({'schema_version':1,'lab_id':lab,'node_id':'d',
                    'request_id':'image-stop-d','action':'stop','expected_revision':1})
                deadline=time.monotonic()+30
                while True:
                    stopped=adapter.node_operation(stopping['id'])
                    if stopped['phase'] in ('completed','failed','cancelled','recovery_required'):break
                    if time.monotonic()>=deadline:raise RuntimeError('image endpoint cleanup timeout')
                    time.sleep(.05)
                assert stopped['phase']=='completed',stopped
                api_stops['d']=stopping['id']
                assert backend.inspect(raw,extra_spec) is None and backend.linux.link(extra_spec['endpoints'][0]['host_interface']) is None
            report['image_native_stop_deletes_endpoint_with_namespace_pinned']=True
            cancel_spec=prepare_spec('e');cancel_raw={**raw,'node_id':'e','request_id':'image-cancel-e','spec':cancel_spec}
            with journal.execution_lock:
                cancelled=adapter.submit_node(cancel_raw)
                assert adapter.node_operation(cancelled['id'],action='cancel')['cancel_requested'] is True
            deadline=time.monotonic()+30
            while True:
                cancelled_state=adapter.node_operation(cancelled['id'])
                value=backend.inspect(cancel_raw,cancel_spec)
                if value:
                    assert value['Config']['Labels'].get('org.dnlab.runtime.creator')==cancelled['id']
                    nodes['e']=(cancel_raw,cancel_spec,value['Id'])
                if cancelled_state['phase'] in ('completed','failed','cancelled','recovery_required'):break
                if time.monotonic()>=deadline:raise RuntimeError('queued cancellation did not finish')
                time.sleep(.05)
            assert cancelled_state['phase']=='cancelled' and backend.inspect(cancel_raw,cancel_spec) is None
            assert backend.linux.link(cancel_spec['endpoints'][0]['host_interface']) is None
            assert cli.stdin_calls>=5 and all('fixture-stdin-value' not in c for c in cli.commands)
            report['opt_in_lifecycle_adapter_plan_stdin_dedupe_cancel']=True
            sealed_spec=prepare_spec('f');sealed_raw={**raw,'node_id':'f','request_id':'image-pre-cancel-f','spec':sealed_spec}
            assert adapter.find_node_request(sealed_raw) is None
            sealed=adapter.cancel_node_request(sealed_raw);assert sealed['phase']=='cancelled'
            daemon_stop();daemon_start(client)
            assert adapter.find_node_request(sealed_raw)['id']==sealed['id']
            delayed=adapter.submit_node(sealed_raw)
            value=backend.inspect(sealed_raw,sealed_spec)
            if value:
                assert value['Config']['Labels'].get('org.dnlab.runtime.creator')==delayed['id']
                nodes['f']=(sealed_raw,sealed_spec,value['Id'])
            assert delayed['id']==sealed['id'] and delayed['phase']=='cancelled'
            assert value is None and backend.linux.link(sealed_spec['endpoints'][0]['host_interface']) is None
            assert journal.node(lab,'f') is None
            report['pre_cancel_seals_delayed_submit_across_daemon_restart']=True
            from dnlab_multinode.services.runtime_operations import OperationStore,OperationDriver
            target={'host':'fixture-local','socket_path':str(root/'socket'),'container_name':daemon_name}
            factory=lambda target:RuntimeClient(cli,socket_path=target['socket_path'],container_name=target['container_name'])
            coordinator_store=OperationStore(root/'coordinator');driver=OperationDriver(coordinator_store,factory)
            ledger_spec=prepare_spec('g');ledger_spec['env']={'DNLAB_RUNTIME_FIXTURE_VALUE':'fixture-stdin-value'}
            ledger_raw={**raw,'node_id':'g','request_id':'ledger-cancel-g','spec':ledger_spec}
            driver.prepare(ledger_raw,target)
            with journal.execution_lock:
                if ssh_fixture is not None:
                    ssh_fixture.drop_next_submit_ack=True
                    try:driver.advance(lab,'ledger-cancel-g')
                    except SSHError:pass
                    else:raise RuntimeError('coordinator fixture acknowledgement was not dropped')
                    assert coordinator_store.get(lab,'ledger-cancel-g')['operation_id']==''
                    ssh_fixture.reconnect()
                coordinator_store.request_cancel(lab,'ledger-cancel-g')
                coordinator_store.close();coordinator_store=OperationStore(root/'coordinator')
                driver=OperationDriver(coordinator_store,factory)
                observed=driver.advance(lab,'ledger-cancel-g')
                assert observed['cancel_requested'] and observed['operation_id']
            deadline=time.monotonic()+30
            while observed['phase'] not in ('completed','cancelled','failed','recovery_required'):
                observed=driver.advance(lab,'ledger-cancel-g')
                if time.monotonic()>=deadline:raise RuntimeError('coordinator cancellation timeout')
                time.sleep(.05)
            assert observed['phase']=='cancelled' and backend.inspect(ledger_raw,ledger_spec) is None
            assert 'fixture-stdin-value' not in json.dumps(observed)
            report['coordinator_intent_reopen_and_cancel']=True
            if ssh_fixture is not None:report['coordinator_lost_ack_recovered_by_request']=True
            ledger_start_spec=prepare_spec('h')
            ledger_start={**raw,'node_id':'h','request_id':'ledger-start-h','spec':ledger_start_spec}
            driver.prepare(ledger_start,target);deadline=time.monotonic()+30
            while True:
                observed=driver.advance(lab,'ledger-start-h')
                value=backend.inspect(ledger_start,ledger_start_spec)
                if value:
                    assert value['Config']['Labels'].get('org.dnlab.runtime.creator')==observed['operation_id']
                    nodes['h']=(ledger_start,ledger_start_spec,value['Id'])
                if observed['phase'] in ('completed','cancelled','failed','recovery_required'):break
                if time.monotonic()>=deadline:raise RuntimeError('coordinator native start timeout')
                time.sleep(.05)
            assert observed['phase']=='completed';ready('h')
            ledger_stop={'schema_version':1,'lab_id':lab,'node_id':'h','request_id':'ledger-stop-h','action':'stop','expected_revision':1}
            with backend.namespace(ledger_start,ledger_start_spec,value):
                driver.prepare(ledger_stop,target);deadline=time.monotonic()+30
                while True:
                    observed=driver.advance(lab,'ledger-stop-h')
                    if observed['phase'] in ('completed','cancelled','failed','recovery_required'):break
                    if time.monotonic()>=deadline:raise RuntimeError('coordinator native stop timeout')
                    time.sleep(.05)
                assert observed['phase']=='completed'
                api_stops['h']=observed['operation_id']
            assert coordinator_store.pending()==[] and backend.inspect(ledger_start,ledger_start_spec) is None
            report['coordinator_native_start_stop_durable_receipts']=True
            (root/'coordinator-receipts.json').write_text(json.dumps([coordinator_store.get(lab,key)
                for key in ('ledger-cancel-g','ledger-start-h','ledger-stop-h')],indent=2)+'\n')
            if ssh_fixture is not None:report['lifecycle_transport']='real SSH over loopback with production run/run_input'
        report.update(status='passed',data_link_api_after_move=True,data_traffic=True,management_gateway=True,
                      workload_and_data_identities_preserved=True,stable_management_port_preserved=True,node_revision=revision,
                      stale_revision_refused=True)
    except Exception as error:
        report['status']='failed';report['error']=str(error)
        try:report['node_states']={node:journal.node(lab,node) for node in nodes};report['management']=assignment(journal,lab,'a')
        except Exception as diagnostic:report['diagnostic_error']=str(diagnostic)
        raise
    finally:
        try:
            report['cleanup_diagnostics']='cleanup-events.jsonl'
            snapshot('before-server-shutdown')
            if coordinator_store is not None:coordinator_store.close()
            if ssh_fixture is not None:
                try:ssh_fixture.close();report['SSH_fixture_closed']=True
                except Exception as error:report['SSH_fixture_closed']=False;report['SSH_cleanup_error']=str(error)
            if server:server.shutdown();server.server_close();thread.join(5)
            if daemon_id:
                daemon_stop();backend.docker.remove(daemon_id)
                assert backend.docker.inspect(daemon_id) is None
            snapshot('before-bridge-cleanup')
            manager=engine.links.bridge_manager;key=BridgeIdentity(lab,'l0')
            if manager.row(key.digest):manager.delete(key)
            snapshot('after-bridge-cleanup')
            for node,(request,spec,identity_id) in reversed(list(nodes.items())):
                value=backend.inspect(request,spec)
                if value is None and node in api_stops:
                    assert journal.get(api_stops[node])['phase']=='completed'
                    assert journal.node(request['lab_id'],request['node_id'])['state']=='stopped'
                    assert all(backend.linux.link(e['host_interface']) is None for e in spec.get('endpoints',[]))
                    continue
                assert value and value['Id']==identity_id
                snapshot('before-stop-'+node)
                anchor=None
                if endpoint_delete_race and node=='c':
                    anchor=backend.namespace(request,spec,value);anchor.__enter__()
                    def release_namespace(host):
                        nonlocal anchor
                        assert host==spec['endpoints'][0]['host_interface']
                        diagnostics.before_delete=None
                        anchor.__exit__(None,None,None);anchor=None
                        deadline=time.monotonic()+10
                        while backend.linux.link(host) is not None:
                            if time.monotonic()>=deadline:raise RuntimeError('fixture namespace teardown did not remove the qualified veth')
                            time.sleep(.01)
                        diagnostics.record({'event':'forced-endpoint-disappearance','host_interface':host})
                        report['forced_endpoint_disappearance']=True
                    diagnostics.before_delete=release_namespace
                try:
                    backend.stop(request,spec,force=True)
                    snapshot('after-stop-before-endpoint-delete-'+node)
                    backend.delete_endpoints(request,spec)
                finally:
                    diagnostics.before_delete=None
                    if anchor is not None:anchor.__exit__(None,None,None)
                snapshot('after-endpoint-delete-before-remove-'+node)
                backend.remove(request,spec)
                snapshot('after-remove-'+node)
            for network in reversed(networks):
                snapshot('before-network-remove-'+network['Name'])
                value=backend.docker.network(network['Id'])
                assert value['Id']==network['Id'] and value['Labels']=={'io.dnlab.spike':token} and not value['Containers']
                command(['docker','network','rm',value['Id']])
            live_network_ids=set(command(['docker','network','ls','--no-trunc','--format','{{.ID}}']).splitlines())
            report['cleanup_verified']=(all(backend.docker.inspect(spec['container_name']) is None for _,spec,_ in nodes.values())
                and not (live_network_ids & {network['Id'] for network in networks})
                and all(backend.linux.link(spec['endpoints'][0]['host_interface']) is None for _,spec,_ in nodes.values())
                and backend.linux.link(key.kernel_name) is None
                and (daemon_id is None or backend.docker.inspect(daemon_id) is None)
                and (ssh_fixture is None or report.get('SSH_fixture_closed') is True))
            if endpoint_delete_race:assert report.get('forced_endpoint_disappearance') is True
            snapshot('after-cleanup-verification')
            journal.close()
        except Exception as error:
            report['cleanup_verified']=False;report['cleanup_error']=str(error);report['cleanup_failed_phase']=diagnostics.phase
            try:snapshot('cleanup-failure')
            except Exception as diagnostic:report['cleanup_diagnostic_error']=str(diagnostic)
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report.get('cleanup_verified')}))
    if not report.get('cleanup_verified'):raise RuntimeError('native fixture cleanup incomplete')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');parser.add_argument('--image',required=True);parser.add_argument('--crash',choices=('before','during','after'),required=True);parser.add_argument('--endpoint-delete-race',action='store_true');parser.add_argument('--runtime-image');parser.add_argument('--image-handoff',action='store_true');parser.add_argument('--ssh-transport',action='store_true');args=parser.parse_args()
    if not args.execute:parser.error('explicit --execute required')
    run(args.image,args.crash,endpoint_delete_race=args.endpoint_delete_race,runtime_image=args.runtime_image,image_handoff=args.image_handoff,ssh_transport=args.ssh_transport)
