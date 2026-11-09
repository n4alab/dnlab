import copy

import pytest

from tools.realnet_bootstrap_smoke import retry_invariant_differences


def baseline():
    return {'host':{'ifname':'vh-test','ifindex':4,'address':'02:00:00:00:00:01',
                    'ifalias':'owned','link_index':2,'master':'br-test',
                    'linkinfo':{'info_kind':'veth','info_slave_kind':'bridge',
                                'info_slave_data':{'forward_delay_timer':14.91,'state':'forwarding'}}},
            'peer':{'ifname':'eth1','ifindex':2,'link_index':4,'address':'02:00:00:00:00:02'},
            'started_at':'original'}


def test_elapsed_timer_keeps_raw_snapshots_unchanged():
    before=baseline();after=copy.deepcopy(before)
    after['host']['linkinfo']['info_slave_data']['forward_delay_timer']=14.49
    saved=copy.deepcopy((before,after))
    assert retry_invariant_differences(before,after)==[]
    assert (before,after)==saved


@pytest.mark.parametrize('key',['ifname','ifindex','address','ifalias','link_index','master'])
def test_identity_change_is_still_rejected(key):
    before=baseline();after=copy.deepcopy(before)
    after['host'][key]='changed'
    after['host']['linkinfo']['info_slave_data']['forward_delay_timer']=14.49
    assert len(retry_invariant_differences(before,after))==2


@pytest.mark.parametrize('value',[True,'14',None,-1,float('inf'),float('nan')])
def test_invalid_timer_is_rejected(value):
    before=baseline();after=copy.deepcopy(before)
    after['host']['linkinfo']['info_slave_data']['forward_delay_timer']=value
    assert retry_invariant_differences(before,after)


@pytest.mark.parametrize('change',['missing','kind','slave_kind','port_state','peer','started_at','wrong_path','config'])
def test_other_changes_are_rejected(change):
    before=baseline();after=copy.deepcopy(before)
    info=after['host']['linkinfo']
    if change=='missing':del info['info_slave_data']['forward_delay_timer']
    if change=='kind':info['info_kind']='dummy'
    if change=='slave_kind':info['info_slave_kind']='other'
    if change=='port_state':info['info_slave_data']['state']='disabled'
    if change=='peer':after['peer']['address']='foreign'
    if change=='started_at':after['started_at']='restarted'
    if change=='wrong_path':after['peer']['forward_delay_timer']=10
    if change=='config':info['info_slave_data']['forward_delay']=1000
    assert retry_invariant_differences(before,after)


@pytest.mark.parametrize('key',['info_kind','info_slave_kind'])
def test_timer_exception_requires_correct_kind_on_both_snapshots(key):
    before=baseline();before['host']['linkinfo'][key]='other'
    after=copy.deepcopy(before)
    after['host']['linkinfo']['info_slave_data']['forward_delay_timer']=14.49
    assert retry_invariant_differences(before,after)
