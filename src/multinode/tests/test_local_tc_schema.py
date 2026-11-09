import copy
import json
from pathlib import Path

import pytest

from dnlab_multinode.services.local_tc import owned_rule


@pytest.fixture(params=[('tc-lldp.json','0x88cc',49140),('tc-lacp.json','0x8809',49141)])
def fixture(request):
    name,protocol,pref=request.param
    value=json.loads((Path(__file__).parent/'fixtures'/name).read_text())
    return value['ingress'] if isinstance(value,dict) else value,protocol,pref


def test_actual_classifier_header_and_rule_are_one_owned_slot(fixture):
    values,protocol,pref=fixture
    assert owned_rule(values,protocol,pref,'right')
    assert owned_rule(values[1:],protocol,pref,'right')
    assert not owned_rule(values,protocol,pref,'other')
    assert not owned_rule(values[:1],protocol,pref,'right')


@pytest.mark.parametrize('change',['handle','extra_key','chain','extra_action','extra_rule'])
def test_actual_schema_rejects_foreign_or_ambiguous_slot(fixture,change):
    values,protocol,pref=fixture;values=copy.deepcopy(values)
    if change=='handle':values[1]['options']['handle']=2
    if change=='extra_key':values[1]['options']['keys']['dst_ip']='192.0.2.1'
    if change=='chain':
        for value in values:value['chain']=1
    if change=='extra_action':values[1]['options']['actions'].append({'kind':'gact'})
    if change=='extra_rule':values.append(copy.deepcopy(values[1]))
    assert not owned_rule(values,protocol,pref,'right')
