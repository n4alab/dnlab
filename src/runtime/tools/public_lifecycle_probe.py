"""Real public API/controller gate over the owned loopback SSH image runtime."""
import asyncio
import hashlib
import json
from pathlib import Path

import yaml

from dnlab_multinode import api as public_api
from dnlab_multinode.controllers.node import NodeLifecycleController
from dnlab_multinode.models.state import DeploymentState,NodeRuntimeState,RuntimeLinkState
from dnlab_multinode.services import native_public,state as state_svc,lab_cleanup
from dnlab_multinode.services.runtime_cleanup import make_binding
from dnlab_multinode.services.runtime_operations import OperationDriver
from link_api_smoke import docker
from vxlan_smoke import command


def probe(*,root,report,lab,store,factory,target,inventory,client,backend,requests,specs,extra_workloads,wait):
    owned=lab+'-public';token=lab.rsplit('-',1)[-1];path=root/'public.yml';hosts=root/'public-hosts.yml'
    nodes=['api-vd1','api-vd2'];starts={};bindings={};initial={}
    control=backend.verify(requests['vd2'],specs['vd2'])['Id']
    hosts.write_text(yaml.safe_dump({'infrastructure':{'master':{'host':'127.0.0.1','ssh_user':'fixture','ssh_key':'/unused'},
        'workers':{'fixture-local':{'host':'127.0.0.1','ssh_user':'fixture','ssh_key':'/unused'}},'underlay_iface':'lo'},
        'jumphost':{'image':specs['vd2']['image'],'host_ip':'198.19.211.1/24'},
        'defaults':{'mgmt':{'ipv4_subnet':'198.19.212.0/24','ipv4_gw':'198.19.212.1'}}}))
    path.write_text(yaml.safe_dump({'name':owned,'topology':{'nodes':{node:{'kind':'linux','image':specs['vd2']['image']} for node in nodes},
        'links':[{'endpoints':[nodes[0]+':eth1',nodes[1]+':eth1']}]}}))
    driver=OperationDriver(store,factory)
    state=DeploymentState(lab_name=owned,topology_file=str(path),runtime_mode='custom')
    for index,node in enumerate(nodes):
        spec={**specs['vd2'],'container_name':'drsp-public-'+token+str(index),
            'endpoints':[{'host_interface':'drsp'+token+('e' if index==0 else 'f'),'node_interface':'eth1','mtu':1450}]}
        request={**requests['vd2'],'lab_id':owned,'node_id':node,'request_id':'initial-'+node,'spec':spec}
        starts[node]=request;extra_workloads.append(({'lab_id':owned,'node_id':node},spec['container_name']))
        driver.prepare(request,target);wait(lambda:driver.advance(owned,request['request_id'])['phase']=='completed')
        bound=factory(target).bound_to(store.get(owned,request['request_id'])['journal_id'])
        view=bound.inspect_node(owned,node);initial[node]=view['container_id']
        wait(lambda:'READY-' in docker('logs',view['container_id']))
        bindings[node]=make_binding(store,owned,node,request['request_id'],view)
        state.node_runtime[node]=NodeRuntimeState(node=node,kind='linux',host=target['host'],image=spec['image'],container=spec['container_name'],runtime_binding=bindings[node])
    state.runtime_links=[RuntimeLinkState(id='public-link',link_type='local',lab_name=owned,
        endpoint_a={'node':nodes[0],'iface':'eth1'},endpoint_b={'node':nodes[1],'iface':'eth1'},host_a=target['host'],host_b=target['host'])]
    state_svc.save_state(state,root)
    old=public_api.NodeLifecycleController
    def controller(*args,**kwargs):
        value=NodeLifecycleController(*args,**kwargs)
        value._native_clients_factory=lambda required:{target['host']:inventory}
        return value
    public_api.NodeLifecycleController=controller
    def payload(node,key):return {'topology_file':str(path),'hosts_file':str(hosts),'node':node,'request_id':key}
    def current():return state_svc.load_state(owned,root)
    def assert_control():assert backend.verify(requests['vd2'],specs['vd2'])['Id']==control
    def ip_and_ping():
        state=current()
        for index,node in enumerate(nodes):
            spec=starts[node]['spec'];container=backend.verify({'lab_id':owned,'node_id':node},spec)
            command(['nsenter',f'--net=/proc/{container["State"]["Pid"]}/ns/net','--','ip','address','replace',f'198.19.213.{index+1}/24','dev','eth1'])
        left=backend.verify({'lab_id':owned,'node_id':nodes[0]},starts[nodes[0]]['spec'])
        result=command(['nsenter',f'--net=/proc/{left["State"]["Pid"]}/ns/net','--','ping','-n','-I','eth1','-c','2','-W','1','198.19.213.2'],check=False)
        assert result.returncode==0,result.stdout+result.stderr
        return {'returncode':result.returncode,'stdout':result.stdout}
    async def actions():
        # Reconcile creates the declared local bridge through the native API.
        await public_api.lab_node_reconcile(public_api.NodeRequest(**payload(nodes[0],'reconcile-initial')))
        report['public_initial_ping']=ip_and_ping()
        listed=await public_api.lab_nodes(public_api.LabRequest(topology_file=str(path),hosts_file=str(hosts)))
        assert all(listed['nodes'][node]['runtime_status']['qualified'] for node in nodes)
        assert all(listed['nodes'][node]['runtime_status']['guest_readiness']=='unknown' for node in nodes)
        await public_api.lab_node_stop(public_api.NodeStopRequest(**payload(nodes[0],'api-stop')))
        assert current().node_runtime[nodes[0]].state=='stopped' and backend.inspect({'lab_id':owned,'node_id':nodes[0]},starts[nodes[0]]['spec']) is None
        assert current().node_runtime[nodes[1]].runtime_binding['container_id']==initial[nodes[1]]
        await public_api.lab_node_start(public_api.NodeRequest(**payload(nodes[0],'api-start')))
        after_start=current().node_runtime[nodes[0]].runtime_binding['container_id']
        assert after_start!=initial[nodes[0]]
        report['public_after_start_ping']=ip_and_ping();assert_control()
        await public_api.lab_node_restart(public_api.NodeRequest(**payload(nodes[0],'api-restart')))
        after_restart=current().node_runtime[nodes[0]].runtime_binding['container_id']
        assert after_restart!=after_start
        await public_api.lab_node_restart(public_api.NodeRequest(**payload(nodes[0],'api-restart')))
        assert current().node_runtime[nodes[0]].runtime_binding['container_id']==after_restart
        report['public_after_restart_ping']=ip_and_ping()
        await public_api.lab_node_remove(public_api.NodeStopRequest(**payload(nodes[0],'api-remove')))
        assert nodes[0] not in current().node_runtime and nodes[0] in current().retired_native_nodes
        await public_api.lab_node_start(public_api.NodeRequest(**payload(nodes[0],'api-readd')))
        assert current().node_runtime[nodes[0]].runtime_binding['generation']==4
        report['public_after_readd_ping']=ip_and_ping();assert_control()
        for node in nodes:await public_api.lab_node_stop(public_api.NodeStopRequest(**payload(node,'final-stop-'+node)))
    try:
        asyncio.run(actions())
        state=current();state.teardown_requested=True;state_svc.save_state(state,root)
        plan=lab_cleanup.LabCleanupPlan(lab=owned)
        lab_cleanup._execute_plans({owned:plan},{target['host']:inventory},own_clients=False,states={owned:state},state_directory=root)
        assert not plan.protected,plan.warnings
        status=lab_cleanup._finalize_requested_teardowns({owned:state},root,None,clients={target['host']:inventory})
        assert status[owned]=='pending teardown state finalized',status
        assert current() is None
        assert_control()
        report['public_native_api']={'qualified':True,'arbitrary_names':True,'ordinary_stop_verified':True,
            'new_generation_start':True,'restart_idempotent':True,'links_restored_after_start_restart':True,
            'removed_owner_tombstone':True,'readd_generation':4,'control_peer_unchanged':True,'state_finalized':True,
            'source_sha256':{name:hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in [
                '/opt/dnlab/src/multinode/dnlab_multinode/services/native_public.py',
                '/opt/dnlab/src/multinode/dnlab_multinode/controllers/node.py']}}
        report['checks'].append('public native API dispatch, qualified state, durable restart, link restoration, remove/readd and guarded finalization')
    finally:public_api.NodeLifecycleController=old
