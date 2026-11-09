"""Additional L2 attachments retain the original jumphost birth identity."""
from copy import deepcopy
import ipaddress
import json

import pytest

from dnlab_multinode.services.jumphost_host import JumphostError,names,signature
from tests.test_jumphost_host import World,config


class MultiWorld(World):
    def __init__(self,cfg):
        super().__init__(cfg);self.extra_networks={};self.port_addresses={}
    def run(self,argv,**kwargs):
        local=argv[2:] if argv[0]=='nsenter' else argv
        if local[:3]==['docker','network','inspect']:
            found=next((v for v in self.extra_networks.values() if local[3] in (v['Name'],v['Id'])),None)
            if found is not None:self.calls.append(list(argv));self.before(argv);return json.dumps([found])
        if local[:3]==['ip','-j','addr']:
            self.calls.append(list(argv));self.before(argv)
            return json.dumps([{'addr_info':[{'local':v.split('/')[0],'prefixlen':int(v.split('/')[1])}
                for v in self.port_addresses.get(local[-1],[])]}])
        if local[:3]==['ip','link','add']:
            before_host=len(self.host);before_peer=len(self.peer)
            index=max(v['ifindex'] for v in self.host+self.peer)+1
            try:return super().run(argv,**kwargs)
            finally:
                if len(self.host)>before_host and len(self.peer)>before_peer:
                    own,peer=self.host[-1],self.peer[-1]
                    own.update(ifindex=index,link_index=index+1);peer.update(ifindex=index+1,link_index=index)
        if local[:2]==['python3','-c']:
            p=json.loads(local[-1])
            if p.get('operation')=='address':
                peer=next(v for v in self.peer if v['ifindex']==p['link']['ifindex'])
                result=super().run(argv,**kwargs)
                self.port_addresses.setdefault(peer['ifname'],[]).append(p['value']);return result
        return super().run(argv,**kwargs)
    def delete(self,expected,scope):
        self.calls.append(['delete-index',str(expected['ifindex'])])
        self.host=[v for v in self.host if signature(v)!=expected]
        self.peer=[v for v in self.peer if v.get('link_index')!=expected['ifindex']]
    def add_segment(self,worker,segment='blue'):
        bridge='br-'+segment;network='mgmt-'+segment
        self.host.append(self.link(bridge,20+len(self.extra_networks),'bridge',master='vrf-test',address='02:00:00:00:00:02'))
        expected=deepcopy(self.origin['networks']['default']['expected'])
        expected.update(network=network,bridge=bridge,ipv4_subnet='198.18.1.0/24',ipv4_gateway='198.18.1.1',reserved=['198.18.1.1','198.18.1.254'])
        actual=deepcopy(self.management);actual.update(Id='d'*64,Name=network)
        actual['Labels']['org.dnlab.management.creator']='6'*32
        actual['Options']['dnlab.bridge']=bridge
        actual['IPAM']['Options'].update({'dnlab.tenant':network,'dnlab.reserved':','.join(expected['reserved'])})
        actual['IPAM']['Config']=[{'Subnet':expected['ipv4_subnet'],'Gateway':expected['ipv4_gateway']}]
        self.extra_networks[network]=actual
        self.origin['plan']['segments'][segment]={'bridge':bridge,'address':expected['ipv4_gateway']+'/24'}
        value=self.host[-1]
        self.origin['resources'][bridge]={'phase':'active','identity':{k:value.get(k) for k in ('ifname','ifindex','address','ifalias')}|{'kind':'bridge'}}
        self.origin['networks'][segment]={'expected':expected,'phase':'active','nonce':'6'*32,'id':actual['Id']}
        self.origin_path.write_text(json.dumps(self.origin))
        parent=worker.read()
        return {'request_id':'add-'+segment,'container_id':parent['container_id'],'generation':parent['config']['generation'],
                'management_intent':expected,'attachment':{'segment':segment,'network':network,'bridge':bridge,
                    'interface':'jmblue','ipv4':'198.18.1.254/24','ipv6':''}}


@pytest.fixture
def fixture(tmp_path):
    world=MultiWorld(config());worker=world.worker(tmp_path/'journal');parent=worker.operate('ensure',world.cfg)
    request=world.add_segment(worker)
    return world,worker,parent,request


def mutations(world):
    return [v for v in world.calls if v[:2] in (['docker','create'],['docker','start'],['docker','kill'],['docker','rm'])
            or v[:3]==['ip','link','add'] or v[:2]==['python3','-c'] or v[:1]==['delete-index']]


def test_additional_attachment_preserves_original_container_birth_and_default_port(fixture):
    world,worker,parent,request=fixture
    default=deepcopy(parent['host']);container=deepcopy(world.values[parent['container_id']]);before=deepcopy(parent['config'])
    value=worker.operate('segment-add',request)
    assert value['config']==before and value['host']==default and value['container_id']==parent['container_id']
    row=value['management_attachments']['blue'];assert row['phase']=='active'
    assert world.values[parent['container_id']]==container
    assert worker.operate('read')==value and worker.operate('segment-add',request)==value
    assert sum(v[:2]==['docker','create'] for v in world.calls)==1
    assert row['host']['ifindex']!=default['ifindex']
    assert world.port_addresses['eth1']==['198.18.0.254/24']
    assert world.port_addresses['jmblue']==['198.18.1.254/24']


@pytest.mark.parametrize('lost',['veth','alias'])
def test_lost_additional_birth_reply_recovers_same_pair_without_recreating_container(fixture,lost):
    world,worker,parent,request=fixture;world.lost=lost
    with pytest.raises(JumphostError,match='lost'):worker.operate('segment-add',request)
    value=worker.read();assert value['phase']=='active' and value['management_attachments']['blue']['phase']=='recovery_required'
    interfaces=deepcopy(world.host)
    with pytest.raises(JumphostError,match='recovery'):worker.operate('read')
    world.lost=None
    result=worker.operate('segment-recover',request)
    assert result['management_attachments']['blue']['phase']=='active'
    assert len(world.host)==len(interfaces)
    assert sum(v[:3]==['ip','link','add'] for v in world.calls)==2
    assert sum(v[:2]==['docker','create'] for v in world.calls)==1


@pytest.mark.parametrize('collision',['host','peer','default_port','network'])
def test_unqualified_or_reserved_resources_refused_before_mutation(fixture,collision):
    world,worker,parent,request=fixture
    if collision=='host':world.host.append(world.link(names(worker.lab,'blue'),99))
    if collision=='peer':world.peer.append(world.link('jmblue',99))
    if collision=='default_port':request['attachment']['interface']='eth1'
    if collision=='network':request['attachment']['network']=parent['config']['attachment']['network']
    world.calls.clear();before=worker.path.read_bytes();host=deepcopy(world.host);peer=deepcopy(world.peer)
    with pytest.raises(JumphostError):worker.operate('segment-add',request)
    assert mutations(world)==[] and worker.path.read_bytes()==before and world.host==host and world.peer==peer


@pytest.mark.parametrize('change',['request','container','generation','address','network_id'])
def test_stale_or_changed_intent_refused_without_touching_existing_attachments(fixture,change):
    world,worker,parent,request=fixture;worker.operate('segment-add',request)
    altered=deepcopy(request)
    if change=='request':altered['request_id']='different'
    if change=='container':altered['container_id']='f'*64
    if change=='generation':altered['generation']='f'*32
    if change=='address':altered['attachment']['ipv4']='198.18.1.253/24'
    if change=='network_id':world.extra_networks['mgmt-blue']['Id']='f'*64
    world.calls.clear();before=deepcopy(world.host)
    with pytest.raises(JumphostError):worker.operate('segment-add',altered)
    assert mutations(world)==[] and world.host==before


@pytest.mark.parametrize('retain',[False,True])
def test_parent_shutdown_precedes_all_attachment_cleanup_and_verifies_every_segment(fixture,retain):
    world,worker,parent,request=fixture;worker.operate('segment-add',request)
    world.retain_veth_after_stop=retain;world.calls.clear()
    result=worker.operate('delete')
    assert result['phase']=='cleaned' and result['management_attachments']['blue']['phase']=='cleaned'
    assert worker.operate('verify-cleaned')['phase']=='cleaned'
    assert worker.operate('delete')['phase']=='cleaned'
    stop=next(i for i,v in enumerate(world.calls) if v[:2]==['docker','kill'])
    assert all(i>stop for i,v in enumerate(world.calls) if v[:1]==['delete-index'])
    assert not world.values and not any(v['linkinfo']['info_kind']=='veth' for v in world.host)


def test_replaced_additional_peer_prevents_parent_stop_and_all_unlink(fixture):
    world,worker,parent,request=fixture;worker.operate('segment-add',request)
    world.peer[-1]['ifindex']+=100;world.calls.clear();before=deepcopy(world.host)
    with pytest.raises(JumphostError):worker.operate('delete')
    assert mutations(world)==[] and world.host==before and world.values[parent['container_id']]['State']['Running']


def test_generic_recovery_resumes_original_additional_intent(fixture):
    world,worker,parent,request=fixture;world.lost='veth'
    with pytest.raises(JumphostError):worker.operate('segment-add',request)
    world.lost=None
    assert worker.operate('recover')['management_attachments']['blue']['phase']=='active'


def test_generic_recovery_does_not_mutate_default_when_an_additional_peer_is_replaced(fixture):
    world,worker,parent,request=fixture;worker.operate('segment-add',request)
    world.peer[-1]['ifindex']+=100
    with pytest.raises(JumphostError):worker.operate('delete')
    world.calls.clear();before=deepcopy(world.host)
    with pytest.raises(JumphostError):worker.operate('recover')
    assert mutations(world)==[] and world.host==before


def test_pending_additional_intent_is_durable_before_first_veth_mutation(fixture):
    world,worker,parent,request=fixture;checked=[]
    def inspect(argv):
        if argv[:3]==['ip','link','add']:
            row=worker.read()['management_attachments']['blue']
            assert row['phase']=='creating' and row['step']=='veth_create' and row['nonce']
            assert row['request']==request and row['namespace']==parent['namespace']
            checked.append(True)
    world.before=inspect
    worker.operate('segment-add',request)
    assert checked==[True]
