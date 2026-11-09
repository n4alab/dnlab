"""Owned native fixture for coordinated shutdown, tracked cleanup and recovery."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time

from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_multinode.controllers.runtime_node import RuntimeNodeController
from dnlab_multinode.services.runtime_operations import OperationDriver,OperationStore
from dnlab_multinode.services.ssh import SSHError
from dnlab_runtime.manifest import Conflict
from ssh_loopback_fixture import LoopbackSSH
from link_api_smoke import docker
from vxlan_smoke import command

SOURCE=Path(__file__).resolve().parents[1]


def probe(*,root,report,state,lab,daemon,anchor,api,backend,requests,specs,runtime_image,client,
          service_start,service_stop,native_ping,workers):
    def guard():
        value=api.inspect(daemon['id'])
        if (not value or value['Name']!='/'+daemon['name'] or value['Image']!=runtime_image
                or value['Config']['Labels'].get('io.dnlab.spike')!=lab):raise Conflict('stop fixture daemon owner differs')
        return value

    def wait(callback):
        deadline=time.monotonic()+30
        while True:
            result=callback()
            if result:return result
            if time.monotonic()>=deadline:raise RuntimeError('coordinated stop fixture observation timeout')
            time.sleep(.05)

    def crash_daemon():
        guard();api.signal(daemon['id'],'SIGKILL')
        wait(lambda:not guard()['State']['Running'])
        service_start()

    names=['stop_protocol','engine','journal','link_engine','bridge','vxlan','kernel_endpoint','transport','tc_ownership','backend','workload_generation','inspection','lab_closure']
    script="import importlib,hashlib,json; from pathlib import Path; names="+repr(names)+"; print(json.dumps({n:{'path':(p:=Path(importlib.import_module('dnlab_runtime.'+n).__file__)).as_posix(),'sha256':hashlib.sha256(p.read_bytes()).hexdigest()} for n in names}))"
    audit=json.loads(docker('exec','--workdir','/',daemon['id'],'python3','-c',script))
    for name,value in audit.items():
        assert '/site-packages/dnlab_runtime/' in value['path']
        assert value['sha256']==hashlib.sha256((SOURCE/'dnlab_runtime'/(name+'.py')).read_bytes()).hexdigest()
    report['coordinated_stop_installed_modules']=audit
    prefix=['docker','exec','-i',daemon['name'],'dnlab-runtime','--socket',client.socket_path]
    ssh=LoopbackSSH(root,prefix,guard);store=None
    try:
        target={'host':'fixture-local','socket_path':client.socket_path,'container_name':daemon['name']}
        factory=lambda target:RuntimeClient(ssh.ssh,socket_path=target['socket_path'],container_name=target['container_name'])
        store=OperationStore(root/'coordinated-intents');driver=OperationDriver(store,factory)
        request={'schema_version':1,'lab_id':lab,'node_id':'vd1','request_id':'coordinated-stop',
                 'expected_revision':1,'action':'stop','stop_mode':'coordinated'}
        peer=backend.verify(requests['vd2'],specs['vd2']);original=backend.verify(requests['vd1'],specs['vd1'])
        RuntimeNodeController(store,factory).prepare_local_stop(request,target,participating_hosts=['fixture-local'])
        controller_source=SOURCE.parent/'multinode/dnlab_multinode/controllers/runtime_node.py'
        report['coordinated_stop_controller_sha256']=hashlib.sha256(controller_source.read_bytes()).hexdigest()

        def observed(phase):
            value=driver.advance(lab,request['request_id'])
            if value['phase']=='failed':raise RuntimeError('stop fixture operation failed')
            return value if value['phase']==phase else None

        result=wait(lambda:observed('recovery_required'))
        assert result['receipt']['stop_stage']=='shutdown_requested'
        assert backend.verify(requests['vd1'],specs['vd1'])['Id']==original['Id']
        report['coordinated_stop_timeout_ping']=native_ping()
        report['coordinated_stop_timeout_preserves_link']=True

        # Execute the explicit forced recovery in an owned image worker and
        # SIGKILL that worker after process exit, before recording exit_verified.
        service_stop()
        worker_code='''import os,signal,sys
from pathlib import Path
from dnlab_runtime.journal import Journal
from dnlab_runtime.backend import Backend,Docker
from dnlab_runtime.engine import Engine
j=Journal(Path(sys.argv[1]));b=Backend(Docker());e=Engine(j,b)
j.queue_recovery(sys.argv[2],force=True)
original=b.stop
def stop(*args,**kwargs):
 original(*args,**kwargs)
 os.kill(os.getpid(),signal.SIGKILL)
b.stop=stop
e.execute(sys.argv[2])
'''
        name=daemon['name']+'-exit-worker'
        identity=docker('create','--name',name,'--label','io.dnlab.spike='+lab,
            '--privileged','--workdir','/','--network','container:'+anchor['id'],'--pid','host',
            '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock',
            '--mount',f'type=bind,src={root},dst={root}',
            '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={root}/host-boot-id,readonly',
            '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={root}/host-boot-id','--entrypoint','python3',runtime_image,
            '-c',worker_code,str(state),result['operation_id'])
        workers.append({'id':identity,'name':name});api.start(identity)
        code=docker('wait',identity)
        assert code=='137', 'forced recovery worker did not stop at the intended SIGKILL checkpoint'
        value=backend.inspect(requests['vd1'],specs['vd1'])
        assert value and value['Id']==original['Id'] and not value['State']['Running']
        service_start()
        result=wait(lambda:observed('awaiting_link_cleanup'))
        assert result['receipt']['shutdown_verified'] and result['receipt']['recovery_force']
        inspected=factory(target).bound_to(store.get(lab,request['request_id'])['journal_id']).inspect_node(lab,'vd1')
        assert inspected['operation']['id']==result['operation_id'] and inspected['container_state']=='stopped'
        assert inspected['committed_state']=='running' and inspected['guest_readiness']=='unknown'
        report['ssh_bound_node_inspection']=inspected
        report['coordinated_stop_exit_worker_SIGKILL_recovered']=True
        crash_daemon()
        result=wait(lambda:observed('awaiting_link_cleanup'))
        assert backend.verify(requests['vd2'],specs['vd2'])['Id']==peer['Id']
        assert backend.inspect(requests['vd1'],specs['vd1'])['Id']==original['Id']
        report['coordinated_stop_parked_daemon_SIGKILL_recovered']=True

        # Crash the coordinator after its durable cleanup intent, before SSH.
        store.close();store=None
        prepare_code='''import os,signal,sys
sys.path.insert(0,sys.argv[1])
from dnlab_multinode.services.runtime_operations import OperationStore
s=OperationStore(sys.argv[2]);s.request_stop_stage(sys.argv[3],sys.argv[4],'cleanup')
os.kill(os.getpid(),signal.SIGKILL)
'''
        process=subprocess.Popen([sys.executable,'-c',prepare_code,str(SOURCE.parent/'multinode'),
            str(root/'coordinated-intents'),lab,request['request_id']],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            out,err=process.communicate(timeout=15)
        except subprocess.TimeoutExpired:
            process.kill();process.communicate();raise
        assert process.returncode==-signal.SIGKILL,err.decode()
        store=OperationStore(root/'coordinated-intents');driver=OperationDriver(store,factory)
        assert store.get(lab,request['request_id'])['stop_requested_stage']=='cleanup'
        report['coordinated_stop_coordinator_SIGKILL_intent_reopened']=True
        ssh.drop_next_stage_ack=True
        try:driver.advance(lab,request['request_id'])
        except SSHError:pass
        else:raise RuntimeError('stop stage ACK was not dropped')
        ssh.reconnect();store.close();store=OperationStore(root/'coordinated-intents');driver=OperationDriver(store,factory)
        result=wait(lambda:observed('awaiting_finalization'))
        report['coordinated_stop_lost_cleanup_ACK_recovered']=True
        crash_daemon();result=wait(lambda:observed('awaiting_finalization'))
        assert backend.verify(requests['vd2'],specs['vd2'])['Id']==peer['Id']
        RuntimeNodeController(store,factory).advance_local_stop(lab,request['request_id'],participating_hosts=['fixture-local'])
        assert store.get(lab,request['request_id'])['stop_requested_stage']=='finalize'
        report['coordinated_stop_controller_finalization']=True
        result=wait(lambda:observed('completed'))
        assert result['receipt']['stop_stage']=='finished' and store.pending()==[]
        assert backend.inspect(requests['vd1'],specs['vd1']) is None
        assert backend.verify(requests['vd2'],specs['vd2'])['Id']==peer['Id']
        assert guard()['State']['Running']
        report['coordinated_stop_final_receipt']=store.get(lab,request['request_id'])
        report['real_ssh_qualified']=True
        report['checks'].extend(['SIGTERM timeout preserves connected workload and traffic',
            'explicit forced recovery survives actual worker SIGKILL after exit',
            'parked phases survive daemon SIGKILL', 'coordinator SIGKILL after cleanup intent',
            'lost cleanup ACK retries same operation', 'finalization preserves other VD'])
    finally:
        if store is not None:store.close()
        ssh.close();report['coordinated_stop_SSH_closed']=True
        (root/'coordinated-stop-ssh-events.json').write_text(json.dumps(ssh.events,indent=2)+'\n')
