"""Image/SSH closure gate with native linked VDs, crash and lost receipts."""
from dataclasses import replace
import shlex
import time

from dnlab_multinode.models.state import DeploymentState,NodeRuntimeState
from dnlab_multinode.services import lab_cleanup as cleanup,runtime_cleanup as guard,state as state_svc,runtime_lab_closure as closure
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_multinode.services.runtime_operations import OperationStore,OperationDriver,RuntimeOperationError
from dnlab_multinode.controllers.runtime_node import RuntimeNodeController
from dnlab_multinode.services.ssh import SSHError
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase
from ssh_loopback_fixture import LoopbackSSH
from vxlan_smoke import command
from link_api_smoke import docker


def probe(*,root,report,lab,daemon,api,client,backend,requests,specs,extra_workloads,service_start):
    owned_lab=lab+'-cleanup';token=lab.rsplit('-',1)[-1]
    target={'host':'fixture-local','socket_path':client.socket_path,'container_name':daemon['name']}
    peer=backend.verify(requests['vd2'],specs['vd2'])['Id']
    starts={};bindings={};stop_requests={};container_ids={}
    def daemon_guard():
        value=api.inspect(daemon['id'])
        if not value or value['Name']!='/'+daemon['name'] or value['Config']['Labels'].get('io.dnlab.spike')!=lab:
            raise Conflict('daemon cleanup fixture owner changed')
        return value
    prefix=['docker','exec','-i',daemon['name'],'dnlab-runtime','--socket',client.socket_path]
    ssh=LoopbackSSH(root,prefix,daemon_guard)
    class Inventory:
        host='127.0.0.1'
        def connect(self):pass
        def close(self):pass
        def run(self,text):return ssh.run(text)
        def run_input(self,text,payload):return ssh.run_input(text,payload)
        def run_no_check(self,text,timeout=30):
            args=shlex.split(text)
            if not (args[:3] in (['docker','ps','-a'],['docker','container','ls']) or args[:2]==['docker','inspect']):
                raise AssertionError('fixture rejects generic mutation: '+text)
            value=command(args,check=False)
            return value.returncode,value.stdout,value.stderr
    inventory=Inventory();store=None;previous=guard.PATHS
    def wait(callback):
        deadline=time.monotonic()+30
        while time.monotonic()<deadline:
            value=callback()
            if value:return value
            time.sleep(.1)
        raise RuntimeError('daemon cleanup fixture timeout')
    try:
        guard.PATHS=replace(previous,runtime_operations_dir=str(root/'daemon-cleanup-intents'))
        store=OperationStore(guard.operation_directory(root))
        factory=lambda t:RuntimeClient(inventory,socket_path=t['socket_path'],container_name=t['container_name'])
        driver=OperationDriver(store,factory)
        for index in (1,2):
            node='cleanup-vd'+str(index)
            spec={**specs['vd2'],'container_name':'drsp-cleanup-'+token+'-'+str(index),
                  'endpoints':[{'host_interface':'drsp'+token+('c' if index==1 else 'd'),'node_interface':'eth1','mtu':1450}]}
            start={**requests['vd2'],'lab_id':owned_lab,'node_id':node,'request_id':'cleanup-start'+str(index),'spec':spec}
            starts[node]=start;extra_workloads.append(({'lab_id':owned_lab,'node_id':node},spec['container_name']))
            driver.prepare(start,target)
            wait(lambda:driver.advance(owned_lab,start['request_id'])['phase']=='completed')
            bound=factory(target).bound_to(store.get(owned_lab,start['request_id'])['journal_id'])
            cid=bound.inspect_node(owned_lab,node)['container_id'];container_ids[node]=cid
            wait(lambda:'READY-' in docker('logs',cid))
            bindings[node]=guard.make_binding(store,owned_lab,node,start['request_id'],bound.inspect_node(owned_lab,node),stop_request_id='cleanup-stop'+str(index))
        link={'schema_version':1,'kind':'bridge','lab_id':owned_lab,'link_id':'cleanup-link','action':'create','request_id':'cleanup-link',
            'endpoints':[{'node_id':node,'host_interface':start['spec']['endpoints'][0]['host_interface'],'expected_node_revision':1} for node,start in starts.items()],
            'spec':{'mtu':1450}}
        accepted=client.request('POST','/v1/link-operations',link)
        wait(lambda:client.request('GET','/v1/link-operations/'+accepted['id'])['phase']=='completed')
        controller=RuntimeNodeController(store,factory)
        # Persist complete teardown intent before the first stop reserves peers.
        for index,node in enumerate(starts,1):
            request={'schema_version':1,'lab_id':owned_lab,'node_id':node,'request_id':'cleanup-stop'+str(index),
                     'expected_revision':1,'action':'stop','stop_mode':'coordinated'}
            stop_requests[node]=request
            controller.prepare_local_stop(request,target,participating_hosts=['fixture-local'])
        first,second=list(starts)
        wait(lambda:driver.advance(owned_lab,stop_requests[first]['request_id'])['phase']=='awaiting_link_cleanup')
        state=DeploymentState(lab_name=owned_lab,topology_file=str(root/'cleanup.yml'),teardown_requested=True)
        state.node_runtime={node:NodeRuntimeState(node=node,host='fixture-local',container=start['spec']['container_name'],state='stopping',runtime_binding=bindings[node]) for node,start in starts.items()}
        state_svc.save_state(state,root);ticks=[]
        def tick():
            plan=cleanup.LabCleanupPlan(lab=owned_lab)
            cleanup._execute_plans({owned_lab:plan},{'fixture-local':inventory},own_clients=False,states={owned_lab:state},state_directory=root)
            ticks.append({'protected':plan.protected,'warnings':plan.warnings})
            report['daemon_cleanup_ticks']=ticks
            assert backend.verify(requests['vd2'],specs['vd2'])['Id']==peer
            return plan
        # Losing the close ACK must retain the original durable fence token.
        ssh.drop_next_closure_ack=True
        assert tick().protected
        saved=closure.get(store,owned_lab)
        assert saved['phase']=='closing' and saved['receipts']=={}
        ssh.reconnect();store.close();store=OperationStore(guard.operation_directory(root))
        driver=OperationDriver(store,factory)
        api.signal(daemon_guard()['Id'],'SIGKILL')
        wait(lambda:not daemon_guard()['State']['Running']);service_start()
        late={**starts[first],'request_id':'late-start','expected_revision':1}
        try:store.prepare(late,target,bindings[first]['journal_id'])
        except RuntimeOperationError:pass
        else:raise AssertionError('coordinator accepted start during closing')
        try:client.request('POST','/v1/operations',late)
        except RuntimeErrorBase as error:assert 'closing or closed' in str(error)
        else:raise AssertionError('runtime accepted delayed start after daemon crash')
        for _ in range(12):
            assert tick().protected  # Second VD still needs its explicit stop.
            if store.get(owned_lab,stop_requests[first]['request_id'])['phase']=='completed':break
            time.sleep(.1)
        else:raise AssertionError('first fenced stop did not finish')
        assert backend.verify({'lab_id':owned_lab,'node_id':second},starts[second]['spec'])['Id']==container_ids[second]
        wait(lambda:driver.advance(owned_lab,stop_requests[second]['request_id'])['phase']=='awaiting_link_cleanup')
        for _ in range(12):
            plan=tick()
            if not plan.protected:break
            time.sleep(.1)
        assert not plan.protected,ticks
        assert closure.get(store,owned_lab)['phase']=='closed'
        assert all(api.inspect(cid) is None for cid in container_ids.values())
        status=cleanup._finalize_requested_teardowns({owned_lab:state},root,None,clients={'fixture-local':inventory})
        assert status[owned_lab]=='pending teardown state finalized',status
        assert state_svc.load_state(owned_lab,root) is None
        # Reopen is explicit and idempotent across an unknown remote result.
        ssh.drop_next_closure_ack=True
        try:closure.reopen(store,owned_lab,saved['closure_id'],'explicit-reopen',factory,deployment_state_absent=True)
        except SSHError:pass
        else:raise AssertionError('reopen ACK was not dropped')
        assert closure.get(store,owned_lab)['phase']=='reopening'
        ssh.reconnect();store.close();store=OperationStore(guard.operation_directory(root));driver=OperationDriver(store,factory)
        reopened=closure.reopen(store,owned_lab,saved['closure_id'],'explicit-reopen',factory,deployment_state_absent=True)
        assert reopened['phase']=='open' and reopened['generation']==2
        stale={**starts[first],'request_id':'stale-after-reopen','expected_revision':2}
        for submit in (lambda:store.prepare(stale,target,bindings[first]['journal_id']),lambda:client.request('POST','/v1/operations',stale)):
            try:submit()
            except (RuntimeOperationError,RuntimeErrorBase):pass
            else:raise AssertionError('stale lab generation was accepted')
        fresh={**stale,'request_id':'fresh-after-reopen','lab_generation':2}
        driver.prepare(fresh,target);wait(lambda:driver.advance(owned_lab,fresh['request_id'])['phase']=='completed')
        current=bound.inspect_node(owned_lab,first)
        assert current['container_id']!=container_ids[first]
        wait(lambda:'READY-' in docker('logs',current['container_id']))
        stop={'schema_version':1,'lab_id':owned_lab,'node_id':first,'request_id':'finish-reopened-vd','expected_revision':3,'action':'stop','lab_generation':2}
        driver.prepare(stop,target);wait(lambda:driver.advance(owned_lab,stop['request_id'])['phase']=='completed')
        assert backend.verify(requests['vd2'],specs['vd2'])['Id']==peer
        from public_lifecycle_probe import probe as public_probe
        public_probe(root=root,report=report,lab=lab,store=store,factory=factory,target=target,inventory=inventory,client=client,
            backend=backend,requests=requests,specs=specs,extra_workloads=extra_workloads,wait=wait)
        report['daemon_cleanup']={'ticks':ticks,'status':status,'original_container_ids':container_ids,
            'peer_preserved':True,'state_finalized':True,'generic_mutations':False,'real_ssh':True,
            'closure_survived_daemon_SIGKILL':True,'lost_close_ACK_recovered':True,
            'qualified_link_children_finished':True,'late_starts_rejected':True,'explicit_reopen_generation':2,
            'lost_reopen_ACK_recovered':True,'stale_epoch_rejected':True,'new_epoch_start_stop':True}
        report['checks'].append('durable lab fence survives crash/ACK loss; qualified linked stops only; explicit epoch reopen')
    finally:
        guard.PATHS=previous
        if store is not None:store.close()
        ssh.close()
