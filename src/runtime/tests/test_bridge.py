import copy

import pytest

from dnlab_runtime.bridge import BridgeManager
from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict


class Crash(BaseException):pass


class Linux:
    def __init__(self):
        self.records=[{'ifname':name,'ifindex':index,'address':'02:00:00:00:00:0'+str(index),'link_index':index+10,
                       'ifalias':'dnlab-runtime:fixture-'+name,'mtu':1450,'flags':['UP'],'linkinfo':{'info_kind':'veth'}}
                      for name,index in [('rt-left',1),('rt-right',2)]]
        self.qd=set();self.rules={'rt-left':{},'rt-right':{}};self.egress={'rt-left':[],'rt-right':[]}
        self.forward=[];self.calls=[];self.fail_after=None;self.crash=False
        self.identity={'boot_id':'host1','device':4,'inode':100}
    def network_identity(self):return dict(self.identity)
    def links(self):return copy.deepcopy(self.records)
    def qdiscs(self,name):return [{'kind':'clsact','handle':'ffff:'}] if name in self.qd else []
    def filters(self,name,direction='ingress'):
        return copy.deepcopy(list(self.rules[name].values()) if direction=='ingress' else self.egress[name])
    def forward_rules(self):return copy.deepcopy(self.forward)
    def run(self,args):
        self.calls.append(args)
        if args[:3]==['ip','link','add']:
            self.records.append({'ifname':args[3],'ifindex':20,'address':args[5],'mtu':int(args[7]),'flags':[],'linkinfo':{'info_kind':'bridge'}})
        elif args[:3]==['ip','link','set']:
            value=next(v for v in self.records if v['ifname']==args[4])
            if args[5]=='alias':value['ifalias']=args[6]
            elif args[5]=='up':value['flags']=['UP']
            elif args[5]=='master':value['master']=args[6]
            elif args[5]=='nomaster':
                master=value.pop('master',None)
                bridge=next((v for v in self.records if v['ifname']==master),None)
                if bridge:
                    bridge['mtu']=min((v['mtu'] for v in self.records if v.get('master')==master),default=1500)
            else:raise AssertionError(args)
        elif args[:3]==['ip','link','delete']:
            self.records=[v for v in self.records if v['ifname']!=args[4]]
        elif args[:2]==['iptables','-I']:self.forward.append(['-A','FORWARD',*args[4:]])
        elif args[:2]==['iptables','-D']:self.forward.remove(['-A',*args[2:]])
        elif args[:3]==['tc','qdisc','add']:self.qd.add(args[4])
        elif args[:3]==['tc','qdisc','del']:self.qd.discard(args[4])
        elif args[:3]==['tc','filter','add']:
            pref=int(args[args.index('pref')+1]);protocol=args[args.index('protocol')+1]
            self.rules[args[4]][pref]={'kind':'flower','pref':pref,'protocol':protocol,'chain':0,
              'options':{'handle':1,'keys':{'eth_type':protocol[2:]},'actions':[{'kind':'mirred','mirred_action':'redirect',
              'direction':'egress','to_dev':args[args.index('redirect')+2], 'cookie':args[args.index('cookie')+1], 'index':len(self.calls), 'ref':1, 'bind':1,'control_action':{'type':'stolen'}}]}}
        elif args[:3]==['tc','filter','del']:self.rules[args[4]].pop(int(args[args.index('pref')+1]),None)
        else:raise AssertionError(args)
        if self.fail_after==len(self.calls):
            self.fail_after=None
            raise Crash() if self.crash else RuntimeError('lost mutation acknowledgement')


@pytest.fixture
def fixture(tmp_path):
    journal=Journal(tmp_path);linux=Linux();manager=BridgeManager(journal,linux)
    sources=linux.links();identity=BridgeIdentity('lab','l0')
    yield manager,linux,identity,sources
    journal.close()


def create(manager,identity,sources):return manager.create(identity,sources=sources,mtu=1450)


def assert_clean(manager,linux,identity,sources):
    assert manager.row(identity.digest)['phase']=='cleaned'
    assert linux.records==sources and not linux.qd and not linux.forward
    assert not any(linux.rules.values())


def test_create_retry_delete_preserves_source_identities(fixture):
    manager,linux,identity,sources=fixture
    create(manager,identity,sources);count=len(linux.calls)
    create(manager,identity,sources);assert len(linux.calls)==count
    manager.delete(identity);assert_clean(manager,linux,identity,sources)
    count=len(linux.calls);manager.delete(identity);assert len(linux.calls)==count


@pytest.mark.parametrize('mutation',range(1,14))
def test_lost_create_ack_compensates_only_owned_resources(fixture,mutation):
    manager,linux,identity,sources=fixture;linux.fail_after=mutation
    with pytest.raises(RuntimeError,match='lost'):create(manager,identity,sources)
    assert_clean(manager,linux,identity,sources)


@pytest.mark.parametrize('mutation',range(1,14))
def test_process_crash_create_requires_recovery_without_recreation(fixture,mutation):
    manager,linux,identity,sources=fixture;linux.fail_after=mutation;linux.crash=True
    with pytest.raises(Crash):create(manager,identity,sources)
    restarted=BridgeManager(manager.journal,linux)
    with pytest.raises(Conflict,match='explicit recovery'):create(restarted,identity,sources)
    restarted.recover(identity);assert_clean(restarted,linux,identity,sources)


@pytest.mark.parametrize('mutation',range(1,12))
def test_process_crash_delete_finishes_owned_cleanup(fixture,mutation):
    manager,linux,identity,sources=fixture;create(manager,identity,sources)
    linux.fail_after=len(linux.calls)+mutation;linux.crash=True
    with pytest.raises(Crash):manager.delete(identity)
    restarted=BridgeManager(manager.journal,linux);restarted.recover(identity)
    assert_clean(restarted,linux,identity,sources)


def test_shared_clsact_and_foreign_rules_survive(fixture):
    manager,linux,identity,sources=fixture
    foreign={'pref':12345,'kind':'matchall','protocol':'all'}
    linux.qd.add('rt-left');linux.rules['rt-left'][12345]=foreign
    create(manager,identity,sources)
    linux.egress['rt-right'].append(foreign)
    manager.delete(identity)
    assert linux.qd=={'rt-left','rt-right'} and linux.rules['rt-left']=={12345:foreign}
    assert linux.egress['rt-right']==[foreign] and linux.records==sources


@pytest.mark.parametrize('change',['alias','source','member','context','filter','forward'])
def test_foreign_changed_identity_rejects_cleanup_before_mutation(fixture,change):
    manager,linux,identity,sources=fixture;create(manager,identity,sources)
    if change=='alias':linux.records[-1]['ifalias']='foreign'
    if change=='source':linux.records[0]['ifindex']=40
    if change=='member':linux.records.append({'ifname':'foreign','ifindex':30,'master':identity.kernel_name})
    if change=='context':linux.identity['boot_id']='host2'
    if change=='filter':linux.rules['rt-left'][49140]['options']['actions'][0]['to_dev']='foreign'
    if change=='forward':linux.forward[0][-1]='DROP'
    count=len(linux.calls)
    with pytest.raises(Conflict):manager.delete(identity)
    assert len(linux.calls)==count and manager.row(identity.digest)['phase']=='recovery_required'


def test_foreign_occupied_name_rejected_before_mutation(fixture):
    manager,linux,identity,sources=fixture
    linux.records.append({'ifname':identity.kernel_name,'ifindex':20,'linkinfo':{'info_kind':'bridge'}})
    with pytest.raises(Conflict,match='occupied'):create(manager,identity,sources)
    assert not linux.calls


def test_cleanup_handles_kernel_mtu_reset_after_last_owned_port_detach(fixture):
    manager,linux,identity,sources=fixture
    create(manager,identity,sources)
    manager.delete(identity)
    assert_clean(manager,linux,identity,sources)
    assert manager.row(identity.digest)['payload']['detach_complete_intent'] is True


@pytest.mark.parametrize('change',['active','unmarked','mtu','alias','mac','index','context','source','member'])
def test_mtu_reset_exception_requires_journalled_empty_owned_teardown(fixture,change):
    manager,linux,identity,sources=fixture;create(manager,identity,sources)
    payload=manager.row(identity.digest)['payload'];bridge=linux.records[-1]
    for source in linux.records[:-1]:source.pop('master',None)
    bridge['mtu']=1500;payload['detach_complete_intent']=True
    if change=='unmarked':payload.pop('detach_complete_intent')
    if change=='mtu':bridge['mtu']=1600
    if change=='alias':bridge['ifalias']='foreign'
    if change=='mac':bridge['address']='02:00:00:00:00:ff'
    if change=='index':bridge['ifindex']=21
    if change=='context':linux.identity['boot_id']='other'
    if change=='source':linux.records[0]['ifindex']=99
    if change=='member':linux.records.append({'ifname':'foreign','ifindex':30,'master':identity.kernel_name})
    manager.save(identity,payload,'active' if change=='active' else 'deleting')
    count=len(linux.calls)
    with pytest.raises(Conflict):manager.sources(identity,payload,missing_ok=True)
    assert len(linux.calls)==count


@pytest.mark.parametrize('phase',['creating','active','deleting','recovery_required'])
def test_active_vxlan_endpoint_cannot_be_attached_to_new_bridge(fixture,phase):
    from dnlab_runtime.vxlan import PREF,link_signature
    from dnlab_runtime.manifest import canonical
    manager,linux,identity,sources=fixture
    # A VXLAN may legitimately share a preexisting clsact. Its matchall
    # redirect occupies the source even though bridge-specific slots are free.
    linux.qd.add('rt-left')
    linux.rules['rt-left'][PREF]={'kind':'matchall','pref':PREF,'protocol':'all','chain':0,
        'options':{'handle':1,'actions':[{'kind':'mirred','mirred_action':'redirect',
        'direction':'egress','to_dev':'drvx-existing','control_action':{'type':'stolen'}}]}}
    with manager.journal.transaction():
        manager.journal.db.execute('INSERT INTO local_vxlans VALUES(?,?,?)',
            ('existing-vxlan',canonical({'source':link_signature(sources[0])}),phase))
    count=len(linux.calls)
    with pytest.raises(Conflict):create(manager,identity,sources)
    assert len(linux.calls)==count


def test_partial_bridge_reserves_both_sources_until_verified_recovery(fixture):
    manager,linux,identity,sources=fixture;linux.fail_after=1;linux.crash=True
    with pytest.raises(Crash):create(manager,identity,sources)
    count=len(linux.calls)
    other=BridgeIdentity('another-lab','l0')
    with pytest.raises(Conflict,match='reserved'):create(manager,other,sources)
    assert len(linux.calls)==count
    manager.recover(identity)
    create(manager,other,sources);manager.delete(other)
    assert_clean(manager,linux,other,sources)
