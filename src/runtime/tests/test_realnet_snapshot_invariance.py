import copy

import pytest

from tools.realnet_cleanup_smoke import invariant_differences,snapshot_differences


def baseline():
    return {'links':[
        {'ifname':'br-test','ifindex':3,'address':'02:00:00:00:00:01','ifalias':'owned',
         'linkinfo':{'info_kind':'bridge','info_data':{'gc_timer':0.02,'forward_delay':1500}}},
        {'ifname':'vx-test','ifindex':4,'address':'02:00:00:00:00:02','master':'br-test',
         'linkinfo':{'info_kind':'vxlan','info_data':{'id':42,'local':'198.18.0.1','remote':'198.18.0.2'},
                     'info_slave_kind':'bridge','info_slave_data':{'forward_delay_timer':14.93,'state':3}}}],
            'router_id':'a'*64,'started_at':'same-start','firewall':['-A FORWARD -i br-test -j ACCEPT']}


def test_only_two_exact_timer_values_can_drift_without_changing_raw_snapshots():
    before=baseline();after=copy.deepcopy(before)
    after['links'][0]['linkinfo']['info_data']['gc_timer']=297.79
    after['links'][1]['linkinfo']['info_slave_data']['forward_delay_timer']=12.69
    saved=copy.deepcopy((before,after))
    assert len(snapshot_differences(before,after))==2
    assert invariant_differences(before,after)==[]
    assert (before,after)==saved


@pytest.mark.parametrize('change',['mac','ifindex','alias','master','bridge_config','vni','local','remote','port_state','kind','router_id','started_at','firewall','timer_wrong_path','timer_wrong_kind','timer_deleted','timer_text','timer_bool'])
def test_timer_exception_preserves_identity_configuration_and_resource_checks(change):
    before=baseline();after=copy.deepcopy(before);bridge=after['links'][0];vxlan=after['links'][1]
    if change=='mac':bridge['address']='02:00:00:00:00:ff'
    if change=='ifindex':bridge['ifindex']=9
    if change=='alias':bridge['ifalias']='foreign'
    if change=='master':vxlan['master']='foreign'
    if change=='bridge_config':bridge['linkinfo']['info_data']['forward_delay']=1000
    if change=='vni':vxlan['linkinfo']['info_data']['id']=99
    if change=='local':vxlan['linkinfo']['info_data']['local']='198.18.1.1'
    if change=='remote':vxlan['linkinfo']['info_data']['remote']='198.18.1.2'
    if change=='port_state':vxlan['linkinfo']['info_slave_data']['state']=0
    if change=='kind':bridge['linkinfo']['info_kind']='dummy'
    if change=='router_id':after['router_id']='b'*64
    if change=='started_at':after['started_at']='different-start'
    if change=='firewall':after['firewall']=[]
    if change=='timer_wrong_path':bridge['gc_timer']=9
    if change=='timer_wrong_kind':
        before['links'][0]['linkinfo']['info_kind']='dummy';bridge['linkinfo']['info_kind']='dummy'
        bridge['linkinfo']['info_data']['gc_timer']=20
    if change=='timer_deleted':del bridge['linkinfo']['info_data']['gc_timer']
    if change=='timer_text':bridge['linkinfo']['info_data']['gc_timer']='invalid'
    if change=='timer_bool':bridge['linkinfo']['info_data']['gc_timer']=True
    assert invariant_differences(before,after)
