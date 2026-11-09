from copy import deepcopy
import importlib
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'tools'))
probe = importlib.import_module('nos_interface_probe')


def redirect(target):
    return {'kind': 'mirred', 'mirred_action': 'redirect', 'direction': 'egress', 'to_dev': target}


def fixture():
    guest = [{'nics': ['e1000,netdev=p00,mac=02:00:00:00:00:01', 'e1000,netdev=p01', 'e1000,netdev=p02'], 'netdevs': ['tap,id=p00,ifname=tap0,script=/etc/tc-tap-mgmt-ifup', 'tap,id=p01,ifname=tap1,script=/etc/tc-tap-ifup', 'tap,id=p02,ifname=tap2,script=/etc/tc-tap-ifup']}]
    tc = {'mgmt0': [{'keys': {}, 'actions': [redirect('tap0')]}, {'keys': {'ip_proto': 'tcp', 'dst_port': {'start': 5000, 'end': 5007}}, 'actions': [{'kind': 'gact', 'control_action': {'type': 'pass'}}]}], 'tap0': [{'keys': {}, 'actions': [redirect('mgmt0')]}]}
    for index in (1, 2):
        tc[f'eth{index}'] = [{'keys': {}, 'actions': [redirect(f'tap{index}')]}]
        tc[f'tap{index}'] = [{'keys': {}, 'actions': [redirect(f'eth{index}')]}]
    return guest, {'tc': tc}


def test_oob_path_and_data_paths_are_separate():
    guest, datapath = fixture()
    probe.validate_oob(guest, datapath, '02:00:00:00:00:01', 2)


@pytest.mark.parametrize('bad', ['oob-mac', 'oob-tap', 'data-tap', 'mgmt-redirect', 'data-redirect', 'console'])
def test_oob_probe_rejects_data_management_confusion(bad):
    guest, datapath = fixture()
    if bad == 'oob-mac': guest[0]['nics'][0] = 'e1000,netdev=p00,mac=02:00:00:00:00:99'
    if bad == 'oob-tap': guest[0]['netdevs'][0] = 'tap,id=p00,ifname=tap1,script=/etc/tc-tap-mgmt-ifup'
    if bad == 'data-tap': guest[0]['netdevs'][1] = 'tap,id=p01,ifname=tap0,script=/etc/tc-tap-ifup'
    if bad == 'mgmt-redirect': datapath['tc']['mgmt0'][0]['actions'][0] = redirect('tap1')
    if bad == 'data-redirect': datapath['tc']['eth1'][0]['actions'][0] = redirect('mgmt0')
    if bad == 'console': datapath['tc']['mgmt0'].pop()
    with pytest.raises(RuntimeError):
        probe.validate_oob(guest, datapath, '02:00:00:00:00:01', 2)


def test_tc_signature_ignores_counters_but_preserves_forwarding_behavior():
    row = {'protocol':'all','pref':3,'kind':'flower','options':{'keys':{},'actions':[dict(redirect('tap0'), stats={'packets':1}, installed=10)]}}
    changed = deepcopy(row)
    changed['options']['actions'][0]['stats']['packets'] = 40
    changed['options']['actions'][0]['installed'] = 100
    assert probe.tc_signature([row]) == probe.tc_signature([changed])
    changed['options']['actions'][0]['to_dev'] = 'tap1'
    assert probe.tc_signature([row]) != probe.tc_signature([changed])


def selected_fixture(slot):
    mac='02:00:00:00:00:aa'
    guest=[{'nics':[], 'netdevs':[]}]
    tc={'mgmt0':[{'actions':[redirect(f'tap{slot}')]}]}
    links={}
    for i in range(16):
        data_mac=f'02:00:00:00:01:{i:02x}'
        guest[0]['nics'].append(f'e1000,netdev=p{i:02d},mac={mac if i==slot else data_mac}')
        script='/etc/tc-tap-mgmt-ifup' if i==slot else '/etc/tc-tap-ifup'
        guest[0]['netdevs'].append(f'tap,id=p{i:02d},ifname=tap{i},script={script}')
        links[f'eth{i}']={'address':data_mac}
        tc[f'eth{i}']=[] if i==slot else [{'actions':[redirect(f'tap{i}')]}]
        tc[f'tap{i}']=[{'actions':[redirect('mgmt0' if i==slot else f'eth{i}')]}]
    return guest,{'tc':tc,'links':links},mac


@pytest.mark.parametrize('slot',[0,1,8,15])
def test_selected_management_keeps_every_other_data_path(slot):
    guest,datapath,mac=selected_fixture(slot)
    probe.validate_selected(guest,datapath,mac,15,slot)


@pytest.mark.parametrize('bad',['guest-mac','backend','mgmt-redirect','reserved-data','other-data','data-mac'])
def test_selected_probe_rejects_confused_or_shared_paths(bad):
    guest,datapath,mac=selected_fixture(8)
    if bad=='guest-mac':guest[0]['nics'][8]=guest[0]['nics'][8].replace(mac,'02:00:00:00:00:bb')
    if bad=='backend':guest[0]['netdevs'][8]=guest[0]['netdevs'][8].replace('mgmt-ifup','ifup')
    if bad=='mgmt-redirect':datapath['tc']['mgmt0'][0]['actions']=[redirect('tap0')]
    if bad=='reserved-data':datapath['tc']['eth8']=[{'actions':[redirect('tap8')]}]
    if bad=='other-data':datapath['tc']['eth0'][0]['actions']=[redirect('tap8')]
    if bad=='data-mac':datapath['links']['eth0']['address']=mac
    with pytest.raises(RuntimeError):probe.validate_selected(guest,datapath,mac,15,8)
