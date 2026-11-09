"""Recorded iproute2 JSON must not hide an extra classifier or redirect."""
import copy
import json
from pathlib import Path

import pytest

from dnlab_runtime.vxlan import owned_filter


@pytest.fixture
def rules():
    return json.loads((Path(__file__).parent / 'fixtures/tc_matchall_iproute2_6_15.json').read_text())


def test_recorded_classifier_header_and_detail_are_one_rule(rules):
    assert owned_filter(rules, 'dst0')
    assert owned_filter(rules[1:], 'dst0')


@pytest.mark.parametrize('field,value', [('pref', 40), ('kind', 'flower'), ('chain', 1), ('protocol', 'ip')])
def test_changed_header_is_not_ignored(rules, field, value):
    rules[0][field] = value
    assert not owned_filter(rules, 'dst0')


@pytest.mark.parametrize('addition', ['detail', 'header', 'foreign'])
def test_any_additional_rule_or_header_is_rejected(rules, addition):
    rules.append(copy.deepcopy(rules[1] if addition == 'detail' else rules[0])
                 if addition != 'foreign' else {'kind': 'flower', 'pref': 40})
    assert not owned_filter(rules, 'dst0')


@pytest.mark.parametrize('handle', [True, 2, '0x2'])
def test_foreign_handle_is_rejected(rules, handle):
    rules[1]['options']['handle'] = handle
    assert not owned_filter(rules, 'dst0')


@pytest.mark.parametrize('field,value', [('to_dev', 'foreign'), ('direction', 'ingress'),
                                       ('mirred_action', 'mirror'), ('control_action', {'type': 'pipe'})])
def test_foreign_action_is_rejected(rules, field, value):
    rules[1]['options']['actions'][0][field] = value
    assert not owned_filter(rules, 'dst0')


def test_extra_action_is_rejected(rules):
    rules[1]['options']['actions'].append({'kind': 'gact', 'control_action': {'type': 'drop'}})
    assert not owned_filter(rules, 'dst0')
