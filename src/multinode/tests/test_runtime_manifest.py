"""Native compilation keeps scheduling, endpoint and WebUI access contracts."""
from copy import deepcopy
import pytest
from dnlab_multinode.models.topology import VDNode,Link,RealNet,RealNetLink
from dnlab_multinode.models.schedule import SchedulePlan,HostAssignment,CrossHostLink
from dnlab_multinode.services.runtime_manifest import compile_initial,NativeManifestError
from dnlab_multinode.services.runtime_links import build_runtime_links
from dnlab_multinode.utils.naming import micro_vd_container_name
IMAGE='sha256:'+'a'*64

@pytest.fixture
def inputs(topo_factory):
    nodes={name:VDNode(name=name,kind='linux',image=IMAGE,mgmt_ipv4='192.0.2.'+str(2+i),mgmt_mac='02:11:22:33:44:'+str(10+i)) for i,name in enumerate(('R1','R2','R3'))}
    links=[Link('R1','eth1','R2','eth1'),Link('R2','eth2','R3','eth1')]
    topo=topo_factory(name='demo',nodes=nodes,links=links,num_workers=1);topo.mgmt.network='mgmt';topo.mgmt.ipv4_subnet='192.0.2.0/24';topo.mgmt.ipv4_gw='192.0.2.1'
    topo.real_nets={'internet':RealNet('internet','198.51.100.1/24')};topo.real_net_links=[RealNetLink('internet','R3','eth2',host='worker1')]
    topo.webui_wishlist={'R1':[{'container_port':443,'scheme':'https','path':'/','label':'GUI','source':'catalog'}]}
    plan=SchedulePlan(lab_name='demo',assignments={'master':HostAssignment('master','10.0.0.10',['R1','R2']),'worker1':HostAssignment('worker1','10.0.0.11',['R3'])},local_links=links[:1],cross_host_links=[CrossHostLink(3000,'R2','eth2','R3','eth1','master','worker1')])
    options={'batch_id':'deploy','targets':{h:{'host':h,'socket_path':'/run/native.sock','container_name':'runtime'} for h in plan.assignments},'node_options':{'R1':{'command':['sleep','3600'],'stop_timeout':20}},'webui_allocations':{'R1':[{'container_port':443,'host_port':8456,'bind_ip':'127.0.0.1','proto':'tcp'}]}}
    return topo,plan,options

def test_compiles_existing_placement_network_mac_and_endpoint_names(inputs):
    topo,plan,options=inputs;before=deepcopy((topo,plan,options));value=compile_initial(topo,plan,**options)
    assert (topo,plan,options)==before
    members={v['request']['node_id']:v for v in value['members']}
    for node in topo.nodes:
        spec=members[node]['request']['spec'];assert members[node]['target']['host']==plan.host_for_vd(node)
        assert spec['container_name']==micro_vd_container_name(topo.name,node)
        assert spec['management']['mac']==topo.nodes[node].mgmt_mac and spec['management']['ipv4']==topo.nodes[node].mgmt_ipv4
        assert 'ports' not in spec
    assert value['webui_wishlist']==topo.webui_wishlist and value['webui_allocations']==options['webui_allocations']
    assert members['R1']['request']['spec']['command']==['sleep','3600']
    for link in build_runtime_links(topo,plan):
        for side in ('a','b'):
            edge=getattr(link,'endpoint_'+side)
            if 'node' in edge:assert {'host_interface':getattr(link,'host_endpoint_'+side),'node_interface':edge['iface']} in members[edge['node']]['request']['spec']['endpoints']
    assert [v['link_type'] for v in value['links']]==['same_host','cross_host','real_net']

def test_deterministic_requests_do_not_depend_on_mapping_order(inputs):
    topo,plan,options=inputs;first=compile_initial(topo,plan,**options)
    topo.nodes=dict(reversed(list(topo.nodes.items())));plan.assignments=dict(reversed(list(plan.assignments.items())))
    assert compile_initial(topo,plan,**options)==first


def test_explicit_host_and_container_targets_preserved_in_compilation(inputs):
    topo,plan,options=inputs
    container=compile_initial(topo,plan,**options)
    options['targets']['master']['container_name']=None
    before=deepcopy(options)
    mixed=compile_initial(topo,plan,**options)
    assert options==before and mixed['fingerprint']!=container['fingerprint']
    for member in mixed['members']:
        host=member['target']['host']
        assert member['target']==options['targets'][host]
        assert member['target']['container_name']==(None if host=='master' else 'runtime')


@pytest.mark.parametrize('value',['','../runtime','runtime name','-runtime',False,0,[],{},'a'*64])
def test_invalid_container_target_is_not_treated_as_host(inputs,value):
    topo,plan,options=inputs
    options['targets']['master']['container_name']=value
    with pytest.raises(NativeManifestError,match='invalid native runtime container'):
        compile_initial(topo,plan,**options)


def test_missing_container_target_is_not_implicit_host(inputs):
    topo,plan,options=inputs
    del options['targets']['master']['container_name']
    with pytest.raises(NativeManifestError,match='runtime target differs'):
        compile_initial(topo,plan,**options)

@pytest.mark.parametrize('problem',['missing','duplicate','unknown','host_key','target_host','target_missing','lab','missing_link','extra_link','cross_host','local_host','realnet_host','realnet_unknown','port_owner','mgmt_port'])
def test_inconsistent_footprint_refused(inputs,problem):
    topo,plan,options=inputs
    if problem=='missing':plan.assignments['master'].vd_names.remove('R2')
    if problem=='duplicate':plan.assignments['worker1'].vd_names.append('R1')
    if problem=='unknown':plan.assignments['master'].vd_names.append('foreign')
    if problem=='host_key':plan.assignments['master'].host_name='foreign'
    if problem=='target_host':options['targets']['master']['host']='worker1'
    if problem=='target_missing':options['targets'].pop('worker1')
    if problem=='lab':plan.lab_name='other'
    if problem=='missing_link':plan.cross_host_links.clear()
    if problem=='extra_link':plan.local_links.append(Link('R1','eth3','R2','eth3'))
    if problem=='cross_host':plan.cross_host_links[0].source_host='worker1'
    if problem=='local_host':plan.local_links[0].target='R3'
    if problem=='realnet_host':topo.real_net_links[0].host='master'
    if problem=='realnet_unknown':topo.real_net_links[0].real_net='foreign'
    if problem=='port_owner':topo.real_net_links.append(RealNetLink('internet','R3','eth1',host='worker1'))
    if problem=='mgmt_port':topo.real_net_links[0].iface='eth0'
    with pytest.raises(NativeManifestError):compile_initial(topo,plan,**options)

@pytest.mark.parametrize('field,value',[('kind','cisco_vios'),('extra',{'ports':['8456:443/tcp']}),('extra',{'binds':['/tmp/disk:/persist']}),('extra',{'cmd':'sleep 3600'}),('extra',{'privileged':True}),('mgmt_mac',''),('mgmt_mac','01:11:22:33:44:55'),('mgmt_ipv4',''),('env',{'BAD-VAR':'value'})])
def test_unqualified_attributes_and_missing_identities_refused(inputs,field,value):
    topo,plan,options=inputs;setattr(topo.nodes['R3'],field,value)
    with pytest.raises(NativeManifestError):compile_initial(topo,plan,**options)

def test_image_resolution_binds_original_reference(inputs):
    topo,plan,options=inputs;topo.nodes['R1'].image='local/linux:tag'
    with pytest.raises(NativeManifestError,match='immutable'):compile_initial(topo,plan,**options)
    options['resolved_images']={'R1':{'source':'local/linux:tag','image':IMAGE}}
    compiled=compile_initial(topo,plan,**options)
    assert compiled['members'][0]['request']['spec']['image']==IMAGE
    assert compiled['image_resolutions']['R1']=={'source':'local/linux:tag','image':IMAGE}
    options['resolved_images']['R1']['source']='another:tag'
    with pytest.raises(NativeManifestError,match='source differs'):compile_initial(topo,plan,**options)

def test_revisions_epochs_and_metadata_are_in_fingerprint(inputs):
    topo,plan,options=inputs;first=compile_initial(topo,plan,**options)
    second=compile_initial(topo,plan,**{**options,'revisions':{'R1':2},'lab_generation':3})
    assert second['members'][0]['request']['expected_revision']==2 and second['members'][0]['request']['lab_generation']==3
    assert second['fingerprint']!=first['fingerprint']
    topo.webui_wishlist['R1'][0]['path']='/changed'
    assert compile_initial(topo,plan,**options)['fingerprint']!=first['fingerprint']
