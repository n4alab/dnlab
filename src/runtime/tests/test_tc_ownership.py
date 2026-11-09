import copy

import pytest

from dnlab_runtime.tc_ownership import reserve, qualified
from dnlab_runtime.vxlan import owned_filter, PREF


@pytest.mark.parametrize('change',[None,'cookie','index','ref','bind','missing-index','renamed','replacement','source','legacy','target-replaced','target-renamed'])
def test_unbound_action_requires_complete_original_proof(change):
    source={'ifname':'source','ifindex':1,'ifalias':'owner','address':'a','link_index':10}
    target={'ifname':'target','ifindex':2,'ifalias':'owner','address':'b','link_index':11}
    proof=reserve(source,target);proof['index']=7
    action={'kind':'mirred','mirred_action':'redirect','direction':'egress','to_dev':'*',
            'control_action':{'type':'stolen'},'cookie':proof['cookie'],'index':7,'ref':1,'bind':1}
    rows=[{'kind':'matchall','pref':PREF,'protocol':'all','chain':0,
           'options':{'handle':1,'actions':[action]}}]
    links=[copy.deepcopy(source)]
    if change in ('cookie','index','ref','bind'):action[change]='changed'
    if change=='missing-index':proof['index']=None
    if change=='renamed':links[0]['ifname']='other'
    if change=='replacement':links[0]['ifindex']=88
    if change=='source':links[0]['ifalias']='foreign'
    if change=='legacy':proof=None
    if change=='target-replaced':links.append({**target,'ifindex':99})
    if change=='target-renamed':links.append({**target,'ifname':'other'})
    assert qualified(rows,'target',owned_filter,proof,links)==(change is None)


def test_bound_lost_ack_can_clean_but_cannot_authorize_unbound_without_readback():
    source={'ifname':'source','ifindex':1};target={'ifname':'target','ifindex':2}
    proof=reserve(source,target)
    action={'kind':'mirred','mirred_action':'redirect','direction':'egress','to_dev':'target',
            'control_action':{'type':'stolen'},'cookie':proof['cookie'],'index':7,'ref':1,'bind':1}
    rows=[{'kind':'matchall','pref':PREF,'protocol':'all','options':{'handle':1,'actions':[action]}}]
    assert qualified(rows,'target',owned_filter,proof,[source,target])
    assert proof['index'] is None
    assert qualified(rows,'target',owned_filter,proof,[source,target],capture=True)
    assert proof['index']==7
