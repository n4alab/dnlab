"""Stateful no-host tests for management ownership, journals and recovery."""
import copy
import json
import shlex

import pytest

from dnlab_multinode.services.management_host import Worker, ManagementError, signature

SCOPE = dict(boot_id='boot', device=1, inode=2)


def plan(two=False):
    p = dict(lab='breakout-alpha', generation='a'*32, vrf='vrfa', table=42000, segments={})
    for n, i in [('default', 1), *([('other', 2)] if two else [])]:
        p['segments'][n] = dict(bridge=f'bm{i}', vxlan=f'vm{i}', vni=70000+i, underlay='eth0',
            local='192.0.2.1', remotes=['192.0.2.2'], address=f'10.{i}.0.1/24')
    return p


class Host:
    def __init__(self):
        self.links = {'eth0': dict(ifname='eth0', ifindex=1, address='02:00:00:00:00:01', linkinfo={'info_kind': 'dummy'})}
        self.rules = {'iptables': [], 'ip6tables': []}; self.addresses = {}; self.fdb = {}; self.calls = []; self.next = 10
        self.fail = None; self.after = None

    def run(self, args):
        if args[:5] == ['ip', '-j', '-d', 'link', 'show']: return json.dumps(list(self.links.values()))
        if args[:4] == ['ip', '-j', 'addr', 'show']:
            return json.dumps([{'addr_info': self.addresses.get(args[-1], [])}])
        if args[:4] == ['bridge', '-j', 'fdb', 'show']: return json.dumps(self.fdb.get(args[-1], []))
        if args[0].endswith('-save'):
            return ':FORWARD ACCEPT [0:0]\n' + '\n'.join(shlex.join(['-A', *x]) for x in self.rules[args[0][:-5]])
        if args[0] in self.rules:
            self.calls.append(args)
            if args[2] == '-I': self.rules[args[0]].insert(int(args[4])-1, args[3:4]+args[5:])
            else: self.rules[args[0]].remove(args[3:])
            return ''
        raise AssertionError(args)

    def kernel(self, payload):
        p = copy.deepcopy(payload); self.calls.append(p)
        if self.fail == p['op']: raise RuntimeError('injected kernel failure')
        if p['op'] == 'create':
            b=p['value']; name=b['name']; self.next+=1
            self.links[name]=dict(ifname=name, ifindex=self.next, address=b['mac'], ifalias=b['alias'],
                                  linkinfo=dict(info_kind=b['kind'], info_data=copy.deepcopy(b['config'])))
            if b['kind']=='vxlan': self.links[name]['linkinfo']['info_data']['link']=p['underlay']['ifname']
        else:
            v = self.links[p['link']['ifname']]
            assert signature(v) == p['link']
            if p['op']=='delete': self.links.pop(v['ifname']); self.fdb.pop(v['ifname'],None)
            elif p['op']=='master': v['master']=p['value']['ifname']
            elif p['op']=='alias': v['ifalias']=p['value']
            elif p['op']=='up': v['flags']=['UP']
            elif p['op']=='address':
                ip, prefix = p['value'].split('/')
                self.addresses.setdefault(v['ifname'], []).append(dict(local=ip, prefixlen=int(prefix)))
            elif p['op']=='fdb-add': self.fdb.setdefault(v['ifname'], []).append(dict(mac='00:00:00:00:00:00', dst=p['value'],flags=['self'],state='permanent'))
            else: raise AssertionError(p)
        if self.after == p['op']: self.after=None; raise RuntimeError('lost kernel ACK')
        return ''


@pytest.fixture
def fixture(tmp_path):
    h=Host(); p=plan(two=True)
    w=Worker(p, directory=tmp_path/'journal', run=h.run, host_context=lambda: SCOPE, kernel=h.kernel)
    return h,p,w


def test_birth_retry_and_complete_cleanup(fixture):
    h,p,w=fixture
    assert w.operate('preflight')['phase']=='absent'
    assert not w.directory.exists()  # Read-only admission must not create a journal.
    assert w.ensure()['status']=='active'
    before=copy.deepcopy(h.links)
    assert w.ensure()['status']=='active'
    assert h.links==before
    r=w.read(); assert r['phase']=='active' and all(v['identity'] for v in r['resources'].values())
    assert w.cleanup()['status']=='cleaned'
    assert set(h.links)=={'eth0'} and not any(h.rules.values())
    assert w.operate('verify-cleaned')['status']=='cleaned'
    assert w.cleanup()['status']=='cleaned'
    with pytest.raises(ManagementError): w.ensure(recover=True)


def test_first_allocation_failure_stops_before_bridge_vxlan_firewall(fixture):
    h,p,w=fixture; h.fail='create'
    with pytest.raises(RuntimeError,match='injected'): w.ensure()
    assert len(h.calls)==1 and h.calls[0]['value']['kind']=='vrf'
    assert w.read()['phase']=='applying'
    with pytest.raises(ManagementError,match='recovery'): w.ensure()
    h.fail=None; assert w.operate('recover')['status']=='active'
    w.cleanup()


@pytest.mark.parametrize('mutation', ['create','master','up','address','fdb-add'])
def test_lost_ack_recovery_does_not_recreate_owned_resources(fixture, mutation):
    h,p,w=fixture; h.after=mutation
    with pytest.raises(RuntimeError,match='lost'): w.ensure()
    before=copy.deepcopy(h.links)
    assert w.operate('recover')['status']=='active'
    assert all(h.links[name]['ifindex']==v['ifindex'] for name,v in before.items())
    w.cleanup()


def test_legacy_bridge_preflight_and_teardown_leave_it_intact(fixture):
    h,p,w=fixture
    h.links['bm1']=dict(ifname='bm1',ifindex=88,ifalias='foreign',address='02:ff:00:00:00:88',linkinfo={'info_kind':'bridge'})
    before=copy.deepcopy(h.links)
    with pytest.raises(ManagementError,match='unqualified'): w.operate('preflight')
    with pytest.raises(ManagementError): w.cleanup()
    assert h.links==before and not h.calls


@pytest.mark.parametrize('key,value', [('ifindex',999),('ifalias','foreign'),('address','02:ff:00:00:00:77')])
def test_replacement_before_cleanup_is_preserved(fixture,key,value):
    h,p,w=fixture; w.ensure(); h.links['bm1'][key]=value; before=copy.deepcopy(h.links)
    with pytest.raises(ManagementError): w.cleanup()
    assert h.links==before


def test_shared_vrf_survives_first_segment_cleanup(fixture):
    h,p,w=fixture; w.ensure(); vrf=copy.deepcopy(h.links['vrfa']); other=copy.deepcopy(h.links['bm2'])
    assert w.cleanup(['default'])['status']=='active'
    assert h.links['vrfa']==vrf and h.links['bm2']==other
    assert 'bm1' not in h.links and 'vm1' not in h.links
    assert w.cleanup(['other'])['status']=='cleaned'
    assert set(h.links)=={'eth0'}


def test_foreign_attached_port_blocks_entire_cleanup(fixture):
    h,p,w=fixture; w.ensure()
    h.links['foreign']=dict(ifname='foreign',ifindex=90,master='bm2'); before=copy.deepcopy(h.links)
    with pytest.raises(ManagementError,match='attached ports'): w.cleanup()
    assert h.links==before and w.read()['phase']=='active'


@pytest.mark.parametrize('resource', ['fdb','firewall','underlay','vrf-child','table','vni'])
def test_complete_preflight_preserves_conflicting_resources(fixture,resource):
    h,p,w=fixture; w.ensure()
    if resource=='fdb':h.fdb['vm2'].append(dict(mac='00:00:00:00:00:00',dst='192.0.2.99'))
    elif resource=='firewall':h.rules['iptables'][0][-1]='ACCEPT'
    elif resource=='underlay':h.links['eth0']['ifindex']=42
    elif resource=='vrf-child':h.links['alien']=dict(ifname='alien',ifindex=99,master='vrfa')
    elif resource=='table':h.links['alien']=dict(ifname='alien',ifindex=99,linkinfo=dict(info_kind='vrf',info_data={'table':42000}))
    elif resource=='vni':h.links['alien']=dict(ifname='alien',ifindex=99,linkinfo=dict(info_kind='vxlan',info_data={'id':70001}))
    before=copy.deepcopy(h.links); calls=len(h.calls)
    with pytest.raises(ManagementError):w.cleanup()
    assert h.links==before and len(h.calls)==calls


def test_crash_during_delete_requires_cleanup_recovery(fixture):
    h,p,w=fixture; w.ensure(); h.after='delete'
    with pytest.raises(RuntimeError,match='lost'):w.cleanup()
    assert w.read()['phase']=='cleanup_pending'
    assert w.operate('recover')['status']=='cleaned'
    assert set(h.links)=={'eth0'}


def test_directory_fsync_failure_forbids_network_mutations(fixture,monkeypatch):
    import dnlab_multinode.services.management_host as module
    h,p,w=fixture
    def fail(fd): raise OSError('fsync failed')
    monkeypatch.setattr(module.os,'fsync',fail)
    with pytest.raises(OSError):w.ensure()
    assert not h.calls


def test_add_segment_keeps_original_vrf_and_segment(tmp_path):
    h=Host(); p=plan(); w=Worker(p,directory=tmp_path/'journal',run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);w.ensure()
    before=copy.deepcopy(h.links)
    v=Worker(plan(two=True),directory=w.directory,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);v.ensure()
    assert all(h.links[k]==val for k,val in before.items());v.cleanup()


def test_old_generation_cannot_mutate(fixture):
    h,p,w=fixture;w.ensure();p=copy.deepcopy(p);p['generation']='b'*32
    v=Worker(p,directory=w.directory,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel)
    before=len(h.calls)
    with pytest.raises(ManagementError,match='generation'):v.cleanup()
    assert len(h.calls)==before


def test_missing_birth_alias_is_qualified_only_by_durable_nonce_mac(fixture):
    h,p,w=fixture; original=h.kernel
    def ignore_alias(payload):
        value=original(payload)
        if payload['op']=='create':h.links[payload['value']['name']].pop('ifalias',None)
        return value
    w.kernel=ignore_alias
    w.ensure()
    assert all(h.links[n]['ifalias']==v['alias'] for n,v in w.desired().items())
    assert len([v for v in h.calls if isinstance(v,dict) and v['op']=='alias'])==5
    w.cleanup()


def test_lost_birth_ack_before_alias_can_be_cleaned_without_recreating(fixture):
    h,p,w=fixture;original=h.kernel
    def fail(payload):
        value=original(payload)
        if payload['op']=='create':
            h.links[payload['value']['name']].pop('ifalias',None)
            raise RuntimeError('lost birth')
        return value
    w.kernel=fail
    with pytest.raises(RuntimeError):w.ensure()
    w.kernel=original
    assert w.cleanup()['status']=='cleaned'
    assert len([v for v in h.calls if isinstance(v,dict) and v['op']=='create'])==1


def test_missing_alias_with_wrong_birth_mac_is_never_adopted(fixture):
    h,p,w=fixture;h.after='create'
    with pytest.raises(RuntimeError):w.ensure()
    v=h.links['vrfa'];v.pop('ifalias',None);v['address']='02:ff:00:00:00:99'
    with pytest.raises(ManagementError):w.operate('recover')
    with pytest.raises(ManagementError):w.cleanup()
    assert h.links['vrfa']==v


def test_new_fdb_peer_is_added_without_replacing_segment(tmp_path):
    h=Host();p=plan();w=Worker(p,directory=tmp_path/'journal',run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);w.ensure()
    before=copy.deepcopy(h.links);new=copy.deepcopy(p);new['segments']['default']['remotes'].append('192.0.2.3')
    v=Worker(new,directory=w.directory,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel)
    v.ensure();assert before==h.links
    assert {row['dst'] for row in h.fdb['vm1']}=={'192.0.2.2','192.0.2.3'};v.cleanup()


def test_gate_normalization_preserves_non_timer_differences():
    import importlib.util
    from pathlib import Path
    path=Path(__file__).resolve().parents[2]/'runtime'/'tools'/'management_identity_smoke.py'
    spec=importlib.util.spec_from_file_location('management_gate',path);module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
    baseline={'resources':{'b':{'config':{'info_kind':'bridge','info_data':{'gc_timer':20,'stp_state':0}}},
                           'v':{'config':{'info_kind':'vxlan','info_data':{'id':70001},'info_slave_data':{'forward_delay_timer':10}}}}}
    actual=copy.deepcopy(baseline);actual['resources']['b']['config']['info_data']['gc_timer']=10
    actual['resources']['v']['config']['info_slave_data']['forward_delay_timer']=1
    assert module.stable_snapshot(actual)==module.stable_snapshot(baseline)
    for resource,path,key in [('b','info_data','stp_state'),('v','info_data','id'),('v','info_slave_data','alien')]:
        wrong=copy.deepcopy(actual);wrong['resources'][resource]['config'][path][key]=99
        assert module.stable_snapshot(wrong)!=module.stable_snapshot(baseline)
    assert actual['resources']['b']['config']['info_data']['gc_timer']==10


def test_explicit_new_generation_requires_cleaned_old_generation_and_archives(fixture):
    h,p,w=fixture;w.ensure();new=copy.deepcopy(p);new['generation']='b'*32
    v=Worker(new,directory=w.directory,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel)
    with pytest.raises(ManagementError,match='pending'):v.operate('preflight-provision')
    w.cleanup()
    assert v.operate('preflight-provision')['status']=='verified'
    assert v.operate('provision')['status']=='active'
    assert len(list(w.directory.glob('*-'+'a'*32+'.json')))==1
    with pytest.raises(ManagementError,match='generation'):w.cleanup()
    v.cleanup()


def test_cleaned_receipt_cannot_hide_a_residual_firewall_rule(fixture):
    h,p,w=fixture;w.ensure();rule=copy.deepcopy(h.rules['iptables'][0]);w.cleanup()
    h.rules['iptables'].append(rule)
    with pytest.raises(ManagementError,match='residual'):w.operate('verify-cleaned')


def test_add_segment_and_partial_cleanup_keep_vrf_drop_before_all_accepts(tmp_path):
    h=Host();p=plan();w=Worker(p,directory=tmp_path/'journal',run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);w.ensure()
    v=Worker(plan(two=True),directory=w.directory,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);v.ensure()
    for rows in h.rules.values():
        assert rows[0]==v.rules()[0] and rows[0][-1]=='DROP'
    v.cleanup(['default']);v.ensure()
    assert not any('bm1' in rule for rules in h.rules.values() for rule in rules)
    assert 'vrfa' in h.links
    v.cleanup(['other']);assert not any(h.rules.values())


@pytest.mark.parametrize('change',['order','fdb-state','fdb-flags','address','master'])
def test_configuration_drift_refused_without_mutation(fixture,change):
    h,p,w=fixture;w.ensure()
    if change=='order':h.rules['iptables'].append(h.rules['iptables'].pop(0))
    elif change=='fdb-state':h.fdb['vm1'][0]['state']='reachable'
    elif change=='fdb-flags':h.fdb['vm1'][0]['flags']=['extern_learn']
    elif change=='address':h.addresses['bm1']=[]
    elif change=='master':h.links['bm1'].pop('master')
    count=len(h.calls)
    with pytest.raises(ManagementError):w.cleanup()
    assert len(h.calls)==count


def test_historical_generation_cannot_be_provisioned_again(fixture):
    h,p,w=fixture;w.ensure();w.cleanup();new=copy.deepcopy(p);new['generation']='b'*32
    v=Worker(new,directory=w.directory,run=h.run,host_context=lambda:SCOPE,kernel=h.kernel);v.operate('provision');v.cleanup()
    with pytest.raises(ManagementError,match='historical'):w.operate('preflight-provision')
