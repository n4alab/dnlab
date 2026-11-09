"""Identity ownership and atomic admission regressions for sticky management."""
from copy import deepcopy

import pytest

from dnlab_multinode.models.topology import MgmtConfig, VDNode
from dnlab_multinode.services.config import ConfigError, assign_sticky_mgmt_identities


def management():
    return MgmtConfig(network='mgmt-lab', bridge='br-lab', ipv4_subnet='198.18.0.0/24',
        ipv4_gw='198.18.0.254', ipv6_subnet='2001:db8:1::/64', ipv6_gw='2001:db8:1::ffff')


def test_same_node_can_reuse_its_own_sticky_mac():
    original={'r1':VDNode(name='r1',kind='linux',image='test',mgmt_mac='02:00:00:00:00:11')}
    first=assign_sticky_mgmt_identities(deepcopy(original),management(),lab_name='lab')
    retry=deepcopy(original)
    second=assign_sticky_mgmt_identities(retry,management(),lab_name='lab',
        ipv6_reservations=first[0],mac_reservations=first[1],duid_reservations=first[2],iaid_reservations=first[3])
    assert second==first
    assert retry['r1'].mgmt_mac=='02:00:00:00:00:11'


def test_duplicate_explicit_ipv6_is_rejected_before_changing_nodes():
    nodes={name:VDNode(name=name,kind='linux',image='test',mgmt_ipv6='2001:db8:1::20',mgmt_ipv6_explicit=True)
        for name in ('r1','r2')}
    before=deepcopy(nodes)
    with pytest.raises(ConfigError,match='duplicate'):
        assign_sticky_mgmt_identities(nodes,management(),lab_name='lab')
    assert nodes==before


def make_nodes(*names):
    return {name:VDNode(name=name,kind='linux',image='test') for name in names}


def resolve(nodes, **ledgers):
    from dnlab_multinode.services.config import assign_sticky_management
    return assign_sticky_management(nodes,management(),lab_name='lab',**ledgers)


def arguments(values):
    return dict(zip(('ipv4_reservations','ipv6_reservations','mac_reservations','duid_reservations','iaid_reservations'),values))


def test_retry_hot_add_and_wipe_keep_identities_and_removed_reservations():
    original=make_nodes('r1','removed')
    first=resolve(original)
    before_ledgers=deepcopy(first)
    retry=make_nodes('r0-new','r1')
    second=resolve(retry,**arguments(first))
    assert first==before_ledgers
    for prior,current in zip(first,second):
        assert current['r1']==prior['r1'] and current['removed']==prior['removed']
        assert current['r0-new'] not in (prior['r1'],prior['removed'])
    wiped=make_nodes('r0-new','r1')
    assert resolve(wiped,**arguments(second))==second
    assert wiped['r1'].mgmt_mac==original['r1'].mgmt_mac
    assert wiped['r1'].mgmt_duid==original['r1'].mgmt_duid
    assert wiped['r1'].mgmt_iaid==original['r1'].mgmt_iaid


@pytest.mark.parametrize('kind',['ipv4','ipv6','mac'])
def test_explicit_identity_cannot_steal_a_removed_owner_reservation(kind):
    nodes=make_nodes('r1','r2')
    value={'ipv4':'198.18.0.30','ipv6':'2001:db8:1::30','mac':'02:00:00:00:00:30'}[kind]
    setattr(nodes['r2'],'mgmt_'+kind,value)
    if kind!='mac':setattr(nodes['r2'],'mgmt_'+kind+'_explicit',True)
    before=deepcopy(nodes);ledgers={kind+'_reservations':{'removed':value}} if kind!='mac' else {'mac_reservations':{'removed':value}}
    original=deepcopy(ledgers)
    with pytest.raises(ConfigError,match='duplicate'):resolve(nodes,**ledgers)
    assert nodes==before and ledgers==original


@pytest.mark.parametrize('kind',['ipv4','ipv6','mac'])
def test_same_owner_can_reuse_an_explicit_identity(kind):
    nodes=make_nodes('r1')
    value={'ipv4':'198.18.0.30','ipv6':'2001:db8:1::30','mac':'02:00:00:00:00:30'}[kind]
    setattr(nodes['r1'],'mgmt_'+kind,value)
    if kind!='mac':setattr(nodes['r1'],'mgmt_'+kind+'_explicit',True)
    key=kind+'_reservations' if kind!='mac' else 'mac_reservations'
    result=resolve(nodes,**{key:{'r1':value}})
    assert result[{'ipv4':0,'ipv6':1,'mac':2}[kind]]['r1']==value


@pytest.mark.parametrize('kind',['ipv4','ipv6','mac'])
def test_duplicate_sticky_ledger_is_rejected_without_partial_updates(kind):
    nodes=make_nodes('r1','r2');before=deepcopy(nodes)
    value={'ipv4':'198.18.0.30','ipv6':'2001:db8:1::30','mac':'02:00:00:00:00:30'}[kind]
    key=kind+'_reservations' if kind!='mac' else 'mac_reservations'
    ledger={'r1':value,'removed':value};original=deepcopy(ledger)
    with pytest.raises(ConfigError,match='duplicate'):resolve(nodes,**{key:ledger})
    assert nodes==before and ledger==original


@pytest.mark.parametrize('key,value',[
    ('ipv4_reservations','outside'),('ipv4_reservations','198.18.0.254'),('ipv4_reservations','198.19.0.30'),
    ('ipv6_reservations','outside'),('ipv6_reservations','2001:db8:1::ffff'),('ipv6_reservations','2001:db8:2::30'),
    ('mac_reservations','00:00:00:00:00:00'),('mac_reservations','01:00:00:00:00:01'),('mac_reservations',123),
    ('duid_reservations',''),('iaid_reservations',None),
])
def test_invalid_ledger_entries_fail_closed(key,value):
    nodes=make_nodes('r1');before=deepcopy(nodes);ledger={'removed':value};original=deepcopy(ledger)
    with pytest.raises(ConfigError):resolve(nodes,**{key:ledger})
    assert nodes==before and ledger==original


@pytest.mark.parametrize('key',['ipv4_reservations','ipv6_reservations','mac_reservations','duid_reservations','iaid_reservations'])
def test_malformed_ledger_structure_has_no_partial_publication(key):
    nodes=make_nodes('r1');before=deepcopy(nodes)
    with pytest.raises(ConfigError):resolve(nodes,**{key:[]})
    assert nodes==before
    with pytest.raises(ConfigError):resolve(nodes,**{key:{'':'invalid'}})
    assert nodes==before


def test_late_identity_failure_does_not_publish_ipv4_or_other_node_fields():
    nodes=make_nodes('r1','r2');nodes['r2'].mgmt_mac='invalid'
    before=deepcopy(nodes)
    with pytest.raises(ConfigError):resolve(nodes)
    assert nodes==before


def test_explicit_addresses_are_reserved_before_automatic_assignment():
    nodes=make_nodes('a-auto','z-explicit')
    nodes['z-explicit'].mgmt_ipv4='198.18.0.2';nodes['z-explicit'].mgmt_ipv4_explicit=True
    nodes['z-explicit'].mgmt_ipv6='2001:db8:1::10';nodes['z-explicit'].mgmt_ipv6_explicit=True
    resolve(nodes)
    assert nodes['a-auto'].mgmt_ipv4!='198.18.0.2'
    assert nodes['a-auto'].mgmt_ipv6!='2001:db8:1::10'


def test_mac_cannot_change_an_existing_vd_identity_implicitly():
    nodes=make_nodes('r1');nodes['r1'].mgmt_mac='02:00:00:00:00:22';before=deepcopy(nodes)
    with pytest.raises(ConfigError,match='sticky identity'):
        resolve(nodes,mac_reservations={'r1':'02:00:00:00:00:11'})
    assert nodes==before


def test_generated_collision_is_rejected_not_randomized_away():
    nodes=make_nodes('r1','r2')
    for node in nodes.values():node.persist_id='same-persistent-id'
    before=deepcopy(nodes)
    with pytest.raises(ConfigError,match='duplicate mgmt-mac'):resolve(nodes)
    assert nodes==before


def test_dhcp_client_pair_conflict_is_atomic_and_iaid_alone_can_repeat():
    nodes=make_nodes('r1','r2');before=deepcopy(nodes)
    with pytest.raises(ConfigError,match='DHCPv6 client identity'):
        resolve(nodes,duid_reservations={'r1':'client-a','r2':'client-a'},iaid_reservations={'r1':'port-1','r2':'port-1'})
    assert nodes==before
    result=resolve(nodes,duid_reservations={'r1':'client-a','r2':'client-b'},iaid_reservations={'r1':'port-1','r2':'port-1'})
    assert result[3]=={'r1':'client-a','r2':'client-b'} and result[4]=={'r1':'port-1','r2':'port-1'}


def test_small_ipv6_pool_allocates_only_within_prefix():
    import ipaddress
    cfg=management();cfg.ipv6_subnet='2001:db8:1::/124';cfg.ipv6_gw='2001:db8:1::f'
    nodes=make_nodes(*(f'r{i}' for i in range(14)))
    values=assign_sticky_mgmt_identities(nodes,cfg,lab_name='lab')
    assert len(set(values[0].values()))==14
    assert all(ipaddress.IPv6Address(v) in ipaddress.IPv6Network(cfg.ipv6_subnet) for v in values[0].values())
    assert cfg.ipv6_gw not in values[0].values()


def test_ipv6_exhaustion_has_no_partial_publication():
    cfg=management();cfg.ipv6_subnet='2001:db8:1::/124';cfg.ipv6_gw='2001:db8:1::f'
    nodes=make_nodes(*(f'r{i}' for i in range(15)));before=deepcopy(nodes)
    with pytest.raises(ConfigError,match='exhausted'):assign_sticky_mgmt_identities(nodes,cfg,lab_name='lab')
    assert nodes==before


def test_separate_lab_ledgers_allow_same_explicit_ip_and_mac():
    from dnlab_multinode.services.config import assign_sticky_management
    template=make_nodes('r1');template['r1'].mgmt_mac='02:00:00:00:00:11'
    template['r1'].mgmt_ipv6='2001:db8:1::20';template['r1'].mgmt_ipv6_explicit=True
    first,second=deepcopy(template),deepcopy(template)
    a=assign_sticky_management(first,management(),lab_name='lab-a')
    b=assign_sticky_management(second,management(),lab_name='lab-b')
    assert a[:3]==b[:3] and a[3]!=b[3]


def test_input_order_does_not_change_the_result():
    original=make_nodes('r1','r2','r3');reordered=dict(reversed(list(deepcopy(original).items())))
    assert resolve(original)==resolve(reordered)


def test_ipv4_exhaustion_publishes_nothing():
    from dnlab_multinode.services.config import assign_sticky_management
    cfg=management();cfg.ipv4_subnet='198.18.0.0/29';cfg.ipv4_gw='198.18.0.6'
    nodes=make_nodes('r1','r2','r3');before=deepcopy(nodes)
    with pytest.raises(ConfigError,match='exhausted'):assign_sticky_management(nodes,cfg,lab_name='lab')
    assert nodes==before


def test_hundred_vd_assignment_and_replay_preserve_all_ledgers():
    nodes=make_nodes(*(f'r{i:03}' for i in range(100)))
    first=resolve(nodes)
    assert all(len(set(values.values()))==100 for values in first)
    assert resolve(deepcopy(nodes),**arguments(first))==first
