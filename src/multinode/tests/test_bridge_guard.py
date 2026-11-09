import copy
import json
import shlex

import pytest

from dnlab_multinode.models.state import RuntimeLinkState
from dnlab_multinode.services.bridge_guard import LocalBridgeGuard,BridgeOwnershipError
from dnlab_multinode.services import runtime_links


class Kernel:
    def __init__(self):
        self.records=[{'ifname':name,'ifindex':index,'address':'02:00:00:00:00:0'+str(index),
                       'link_index':index+10,'linkinfo':{'info_kind':'veth'}}
                      for name,index in [('rt-left',1),('rt-right',2)]]
        self.context={'boot_id':'host1','device':4,'inode':100}
        self.calls=[]
        self.qdiscs=set()
        self.rules={'rt-left':{},'rt-right':{}}
        self.egress={'rt-left':[],'rt-right':[]}
    def run(self,command,check=True):
        self.calls.append(command);args=shlex.split(command)
        if args==['ip','-j','-d','link','show']:return json.dumps(self.records)
        if args[:2]==['python3','-c']:return json.dumps(self.context)
        if args[:4]==['tc','-j','qdisc','show']:
            return json.dumps([{'kind':'clsact','handle':'ffff:'}] if args[-1] in self.qdiscs else [])
        if args[:4]==['tc','-j','filter','show']:
            iface=args[5]
            return json.dumps(list(self.rules[iface].values()) if args[-1]=='ingress' else self.egress[iface])
        if args[:3]==['ip','link','add']:
            self.records.append({'ifname':args[3],'ifindex':20,'address':args[5],
                                 'linkinfo':{'info_kind':'bridge'}})
        elif args[:3]==['ip','link','set']:
            name=args[4] if args[3]=='dev' else args[3]
            value=next(r for r in self.records if r['ifname']==name)
            if 'alias' in args:value['ifalias']=args[-1]
            if 'master' in args:value['master']=args[-1]
        elif args[:3]==['ip','link','delete']:
            self.records=[r for r in self.records if r['ifname']!=args[3]]
            for r in self.records:r.pop('master',None)
        elif args[:3]==['tc','qdisc','add']:self.qdiscs.add(args[4])
        elif args[:3]==['tc','qdisc','del']:
            self.qdiscs.discard(args[4]);self.rules[args[4]].clear()
        elif args[:3]==['tc','filter','replace']:
            pref=int(args[args.index('pref')+1]);protocol=args[args.index('protocol')+1]
            self.rules[args[4]][pref]={'kind':'flower','pref':pref,'protocol':protocol,'chain':0,
                'options':{'handle':1,'keys':{'eth_type':protocol[2:]},'actions':[{'kind':'mirred',
                'mirred_action':'redirect','direction':'egress','to_dev':args[-1],'control_action':{'type':'stolen'}}]}}
        elif args[:3]==['tc','filter','del']:self.rules[args[4]].pop(int(args[args.index('pref')+1]),None)
        return ''
    def mutations(self):return [c for c in self.calls if not c.startswith(('ip -j','python3 -c','tc -j'))]


def link():
    return RuntimeLinkState(id='l0',link_type='same_host',lab_name='lab',host_a='master',host_b='master',
                            endpoint_a={'node':'R1','iface':'eth1'},endpoint_b={'node':'R2','iface':'eth1'},
                            host_endpoint_a='rt-left',host_endpoint_b='rt-right')


def setup():
    kernel=Kernel();state=link()
    guard=LocalBridgeGuard(kernel,state,runtime_links._runtime_bridge_name(state))
    return kernel,state,guard


def test_actual_link_path_tags_bridge_and_removes_only_owned_resource():
    kernel,state,guard=setup()
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    assert guard.inspect()['ifalias']==guard.alias
    assert state.resource_identities['local_bridge']['context']==kernel.context
    runtime_links.delete_link(state,{'master':kernel})
    assert guard.inspect() is None
    assert len(kernel.records)==2


@pytest.mark.parametrize('field,value',[
    ('ifalias',''),('ifalias','foreign'),('address','02:ff:ff:ff:ff:ff'),
    ('linkinfo',{'info_kind':'dummy'}),('ifindex',21),
])
def test_foreign_or_replaced_bridge_blocks_teardown_before_mutation(field,value):
    kernel,state,guard=setup();guard.ensure()
    kernel.records[-1][field]=value
    kernel.calls=[]
    with pytest.raises(BridgeOwnershipError):runtime_links.delete_link(state,{'master':kernel})
    assert not kernel.mutations()


def test_foreign_port_and_namespace_change_block_teardown():
    kernel,state,guard=setup();guard.ensure()
    kernel.records.append({'ifname':'foreign','master':guard.bridge})
    with pytest.raises(BridgeOwnershipError,match='foreign port'):guard.inspect()
    kernel.records.pop();kernel.context['boot_id']='host2';kernel.calls=[]
    with pytest.raises(BridgeOwnershipError,match='namespace'):guard.delete()
    assert not kernel.mutations()


def test_endpoint_owned_by_other_bridge_rejected_before_creation():
    kernel,state,guard=setup();kernel.records[0]['master']='foreign'
    with pytest.raises(BridgeOwnershipError,match='another bridge'):guard.ensure()
    assert not kernel.mutations()


def test_endpoint_replacement_blocks_reuse_and_deletion():
    kernel,state,guard=setup();guard.ensure();kernel.records[0]['ifindex']=40;kernel.calls=[]
    with pytest.raises(BridgeOwnershipError,match='endpoint'):guard.ensure()
    assert not kernel.mutations()


def test_absent_bridge_teardown_is_idempotent():
    kernel,state,guard=setup();guard.delete()
    assert not kernel.mutations()


def test_owned_bridge_teardown_preserves_unrelated_endpoint_tc_filter():
    kernel=Kernel();state=link()
    foreign={'pref':12345,'kind':'matchall','protocol':'all'}
    kernel.qdiscs.add('rt-left');kernel.rules['rt-left'][12345]=foreign
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    runtime_links.delete_link(state,{'master':kernel})
    assert kernel.rules['rt-left']=={12345:foreign}
    assert kernel.qdiscs=={'rt-left'}


def test_existing_empty_clsact_is_preserved():
    kernel,state,guard=setup();kernel.qdiscs.add('rt-left')
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    runtime_links.delete_link(state,{'master':kernel})
    assert kernel.qdiscs=={'rt-left'} and not kernel.rules['rt-left']


@pytest.mark.parametrize('pref',[49140,49141])
def test_reserved_priority_conflict_blocks_all_mutations(pref):
    kernel,state,guard=setup();kernel.qdiscs.add('rt-left')
    kernel.rules['rt-left'][pref]={'pref':pref,'kind':'matchall','protocol':'all'}
    with pytest.raises(BridgeOwnershipError,match='priority'):
        runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    assert not kernel.mutations()


def test_retry_does_not_replace_existing_owned_rules():
    kernel,state,guard=setup()
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    rules=copy.deepcopy(kernel.rules);kernel.calls=[]
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    assert kernel.rules==rules
    assert not any(cmd.startswith(('tc filter','tc qdisc')) for cmd in kernel.calls)


@pytest.mark.parametrize('direction',['ingress','egress'])
def test_newly_shared_qdisc_is_preserved_and_ownership_relinquished(direction):
    kernel,state,guard=setup()
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    foreign={'kind':'matchall','pref':12345,'protocol':'all'}
    if direction=='ingress':kernel.rules['rt-left'][12345]=foreign
    else:kernel.egress['rt-left'].append(foreign)
    runtime_links.delete_link(state,{'master':kernel})
    assert kernel.qdiscs=={'rt-left'}
    assert state.resource_identities['local_tc']['ports']['rt-left']['created_qdisc'] is False
    assert (kernel.rules['rt-left'][12345] if direction=='ingress' else kernel.egress['rt-left'][0])==foreign


def test_changed_owned_rule_blocks_teardown_before_carrier_or_firewall():
    kernel,state,guard=setup()
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    kernel.rules['rt-left'][49140]['options']['actions'][0]['to_dev']='foreign'
    kernel.calls=[]
    with pytest.raises(BridgeOwnershipError,match='priority'):runtime_links.delete_link(state,{'master':kernel})
    assert not kernel.mutations()


def test_lost_filter_ack_cleanup_preserves_preexisting_clsact():
    class LostAck(Kernel):
        def run(self,command,check=True):
            result=super().run(command,check)
            if command.startswith('tc filter replace') and not getattr(self,'failed',False):
                self.failed=True;raise RuntimeError('lost filter acknowledgement')
            return result
    kernel=LostAck();state=link();kernel.qdiscs.add('rt-left')
    with pytest.raises(RuntimeError,match='lost filter acknowledgement'):
        runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    assert kernel.qdiscs=={'rt-left'}
    assert not kernel.rules['rt-left'] and len(kernel.records)==2


def test_failed_qdisc_removal_is_reported_and_can_be_retried():
    class Unremoved(Kernel):
        def run(self,command,check=True):
            if command.startswith('tc qdisc del') and not getattr(self,'failed',False):
                self.calls.append(command);self.failed=True;return ''
            return super().run(command,check)
    kernel=Unremoved();state=link()
    runtime_links.create_link(state,{'master':kernel},running_nodes={'R1','R2'})
    with pytest.raises(BridgeOwnershipError,match='remains'):runtime_links.delete_link(state,{'master':kernel})
    assert state.resource_identities['local_tc']['ports']['rt-left']['created_qdisc'] is True
    runtime_links.delete_link(state,{'master':kernel})
    assert not kernel.qdiscs and len(kernel.records)==2
