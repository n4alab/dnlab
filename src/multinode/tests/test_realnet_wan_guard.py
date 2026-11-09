import copy
import json
from pathlib import Path

import pytest

from dnlab_multinode.services.realnet_wan_host import Worker,WANError

CONTEXT={'boot_id':'fixture','device':1,'inode':2}
CONFIG={'network':'drsp-wan','bridge':'drsp-wan-br','subnet':'198.19.240.0/24','gateway':'198.19.240.1'}


class Kernel:
    def __init__(self):self.value=None;self.links=[];self.mutations=[];self.failure=None;self.gateway=CONFIG['gateway']
    def run(self,args):
        if args[:3]==['docker','network','ls']:
            return json.dumps({'ID':self.value['Id'],'Name':self.value['Name']})+'\n' if self.value else ''
        if args[:3]==['docker','network','inspect']:return json.dumps([self.value])
        if args[:3]==['ip','-j','-d']:return json.dumps(self.links)
        if args[:3]==['ip','-j','address']:return json.dumps([{'addr_info':[{'family':'inet','local':self.gateway,'prefixlen':24}]}])
        assert args[:3]==['docker','network','create'];self.mutations.append(args)
        if self.failure=='before':raise RuntimeError('command failed before create')
        labels=dict(arg.split('=',1) for i,arg in enumerate(args) if i and args[i-1]=='--label')
        options=dict(arg.split('=',1) for i,arg in enumerate(args) if i and args[i-1]=='--opt')
        self.value={'Id':'a'*64,'Name':args[-1],'Driver':'bridge','Scope':'local','Internal':False,'Ingress':False,
                    'EnableIPv6':False,'Attachable':False,'ConfigOnly':False,'Labels':labels,'Options':options,
                    'IPAM':{'Driver':'default','Options':None,'Config':[{'Subnet':args[args.index('--subnet')+1],'Gateway':args[args.index('--gateway')+1]}]},
                    'Containers':{},'Created':'original-start'}
        self.links=[{'ifname':CONFIG['bridge'],'ifindex':10,'address':'02:42:00:00:00:01','linkinfo':{'info_kind':'bridge'}}]
        if self.failure=='after':raise RuntimeError('create acknowledgement lost')
        return 'a'*64


@pytest.fixture
def fixture(tmp_path):
    kernel=Kernel();worker=Worker(CONFIG,directory=tmp_path/'wan',run=kernel.run,host_context=lambda:CONTEXT)
    return worker,kernel


def test_absent_preflight_is_read_only_then_create_and_active_reuse(fixture):
    worker,kernel=fixture;assert worker.preflight()['network_id'] is None and not worker.directory.exists()
    assert worker.operate()['network_id']=='a'*64
    original=worker.path.read_bytes();state=copy.deepcopy(kernel.value);count=len(kernel.mutations)
    assert worker.preflight()['status']=='verified'
    assert worker.operate()['network_id']=='a'*64
    assert worker.path.read_bytes()==original and kernel.value==state and len(kernel.mutations)==count


@pytest.mark.parametrize('failure',['before','after'])
def test_create_failure_retains_intent_and_requires_explicit_recovery(fixture,failure):
    worker,kernel=fixture;kernel.failure=failure
    with pytest.raises(RuntimeError):worker.operate()
    assert json.loads(worker.path.read_text())['phase']=='recovery_required'
    with pytest.raises(WANError,match='explicit recovery'):worker.operate()
    kernel.failure=None;count=len(kernel.mutations)
    fresh=Worker(CONFIG,directory=worker.directory,run=kernel.run,host_context=lambda:CONTEXT)
    assert fresh.operate('recover')['network_id']=='a'*64
    assert len(kernel.mutations)==count+(failure=='before')
    assert json.loads(worker.path.read_text())['phase']=='active'


@pytest.mark.parametrize('change',['driver','scope','subnet','gateway','ipam_driver','options','labels','network_id','bridge_mac','bridge_ifindex','bridge_kind','kernel_gateway','ipv6','internal','ingress','attachable'])
def test_active_reuse_refuses_incompatibility_without_mutation(fixture,change):
    worker,kernel=fixture;worker.operate();before=worker.path.read_bytes();count=len(kernel.mutations)
    if change=='driver':kernel.value['Driver']='macvlan'
    elif change=='scope':kernel.value['Scope']='swarm'
    elif change=='subnet':kernel.value['IPAM']['Config'][0]['Subnet']='203.0.113.0/24'
    elif change=='gateway':kernel.value['IPAM']['Config'][0]['Gateway']='198.19.240.2'
    elif change=='ipam_driver':kernel.value['IPAM']['Driver']='foreign'
    elif change=='options':kernel.value['Options']['com.docker.network.bridge.name']='foreign'
    elif change=='labels':kernel.value['Labels']={}
    elif change=='network_id':kernel.value['Id']='b'*64
    elif change=='bridge_mac':kernel.links[0]['address']='02:ff:ff:ff:ff:ff'
    elif change=='bridge_ifindex':kernel.links[0]['ifindex']=99
    elif change=='bridge_kind':kernel.links[0]['linkinfo']['info_kind']='dummy'
    elif change=='kernel_gateway':kernel.gateway='198.19.240.2'
    else:kernel.value[{'ipv6':'EnableIPv6','internal':'Internal','ingress':'Ingress','attachable':'Attachable'}[change]]=True
    with pytest.raises(WANError):worker.operate()
    assert worker.path.read_bytes()==before and len(kernel.mutations)==count


def test_unqualified_matching_network_is_not_adopted(fixture):
    worker,kernel=fixture;worker.operate();worker.path.unlink();count=len(kernel.mutations)
    with pytest.raises(WANError,match='refusing adoption'):worker.operate()
    assert len(kernel.mutations)==count


def test_foreign_bridge_prevents_create_before_intent(fixture):
    worker,kernel=fixture;kernel.links=[{'ifname':CONFIG['bridge'],'ifindex':99,'ifalias':'foreign'}]
    with pytest.raises(WANError,match='occupied'):worker.operate()
    assert not kernel.mutations and not worker.path.exists()


def test_missing_active_network_never_recreated(fixture):
    worker,kernel=fixture;worker.operate();kernel.value=None;kernel.links=[];count=len(kernel.mutations)
    for action in ('ensure','recover'):
        with pytest.raises(WANError,match='absent'):worker.operate(action)
    assert len(kernel.mutations)==count


def test_configuration_and_namespace_changes_refused(fixture):
    worker,kernel=fixture;worker.operate();count=len(kernel.mutations)
    for cfg,ctx in ((dict(CONFIG,gateway='198.19.240.2'),CONTEXT),(CONFIG,dict(CONTEXT,inode=99))):
        with pytest.raises(WANError,match='configuration/context'):Worker(cfg,directory=worker.directory,run=kernel.run,host_context=lambda:ctx).operate()
    assert len(kernel.mutations)==count


def test_recovery_cannot_adopt_foreign_replacement(fixture):
    worker,kernel=fixture;kernel.failure='after'
    with pytest.raises(RuntimeError):worker.operate()
    kernel.value['Labels']={};kernel.failure=None;count=len(kernel.mutations)
    with pytest.raises(WANError):worker.operate('recover')
    assert len(kernel.mutations)==count and json.loads(worker.path.read_text())['phase']=='recovery_required'


@pytest.mark.parametrize('options',[None,{}])
def test_empty_ipam_options_are_accepted_without_mutating_inspection(fixture,options):
    worker,kernel=fixture;worker.operate();kernel.value['IPAM']['Options']=options
    before=worker.path.read_bytes();value=copy.deepcopy(kernel.value);count=len(kernel.mutations)
    assert worker.operate()['status']=='active' and worker.preflight()['status']=='verified'
    assert worker.path.read_bytes()==before and kernel.value==value and len(kernel.mutations)==count


@pytest.mark.parametrize('options',[[],False,0,'','null',{'foreign':'yes'},['foreign']])
def test_nonempty_or_malformed_ipam_options_remain_rejected(fixture,options):
    worker,kernel=fixture;worker.operate();kernel.value['IPAM']['Options']=options
    before=worker.path.read_bytes();count=len(kernel.mutations)
    with pytest.raises(WANError,match='configuration differs'):worker.operate()
    assert worker.path.read_bytes()==before and len(kernel.mutations)==count


@pytest.mark.parametrize('change',['missing_options','extra_key','extra_subnet','wrong_gateway','wrong_driver'])
def test_empty_options_do_not_weaken_other_ipam_fields(fixture,change):
    worker,kernel=fixture;worker.operate();ipam=kernel.value['IPAM'];ipam['Options']={}
    if change=='missing_options':ipam.pop('Options')
    elif change=='extra_key':ipam['foreign']=True
    elif change=='extra_subnet':ipam['Config'].append({'Subnet':'203.0.113.0/24','Gateway':'203.0.113.1'})
    elif change=='wrong_gateway':ipam['Config'][0]['Gateway']='198.19.240.2'
    else:ipam['Driver']='foreign'
    count=len(kernel.mutations)
    with pytest.raises(WANError):worker.operate()
    assert len(kernel.mutations)==count


def test_lost_create_ack_with_empty_options_recovers_same_network(fixture):
    worker,kernel=fixture;kernel.failure='after'
    with pytest.raises(RuntimeError):worker.operate()
    kernel.value['IPAM']['Options']={};kernel.failure=None;count=len(kernel.mutations)
    assert worker.operate('recover')['network_id']==kernel.value['Id']
    assert len(kernel.mutations)==count and json.loads(worker.path.read_text())['phase']=='active'
