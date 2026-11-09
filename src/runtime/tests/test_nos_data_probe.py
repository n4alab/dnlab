import importlib
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
DataProbe=importlib.import_module('nos_data_probe').DataProbe


def fixture(tmp_path):
    state={'attached':set(),'carrier':{},'time':0,'calls':[],'override':None}
    def attach(i):
        assert i not in state['attached'];state['attached'].add(i);state['calls'].append(('attach',i))
    def detach(i):
        assert state['carrier'][i]=='down';state['attached'].remove(i);state['calls'].append(('detach',i))
    def carrier(i,value):
        state['carrier'][i]=value;state['calls'].append(('carrier',i,value))
    def ping(i):
        state['time']+=1
        good=i in state['attached'] and state['carrier'].get(i)=='up'
        if state['override'] is not None:good=state['override']
        return SimpleNamespace(returncode=0 if good else 1,stdout='reply' if good else 'packet loss',stderr='')
    obj=DataProbe([0,1,15],8,lambda i:state['calls'].append(('configure',i)),carrier,attach,detach,ping,tmp_path/'events.json',clock=lambda:state['time'],sleep=lambda t:None)
    return obj,state


def test_warm_carrier_cycles_and_peer_reattach_preserve_expected_traffic(tmp_path):
    probe,state=fixture(tmp_path)
    probe.prepare()
    probe.verify('after-management-move')
    probe.verify('after-management-rollback')
    probe.finish()
    assert not state['attached'] and not probe.attached
    for slot in (0,1,15):
        assert state['calls'].count(('attach',slot))==2
        assert state['calls'].count(('detach',slot))==2
        assert state['carrier'][slot]=='down'
    rows=json.loads(probe.path.read_text())
    assert rows[-1]['stage']=='finished'
    assert {r['stage'] for r in rows} >= {'initial-down','first-up','cycle-down','reattached-up','after-management-move-verified','after-management-rollback-verified','final-down'}
    assert probe.path.stat().st_mode & 0o777 == 0o600


@pytest.mark.parametrize('slots',[[8],[0,0],[],[-1],[16],[True]])
def test_reserved_invalid_or_duplicate_slot_cannot_attach(slots,tmp_path):
    with pytest.raises(ValueError):
        DataProbe(slots,8,None,None,None,None,None,tmp_path/'events.json')
    assert not (tmp_path/'events.json').exists()


@pytest.mark.parametrize('override',[True,False])
def test_incorrect_carrier_traffic_is_bounded_and_persisted(tmp_path,override):
    probe,state=fixture(tmp_path)
    state['override']=override
    with pytest.raises(RuntimeError,match='traffic differs'):
        probe.prepare()
    rows=json.loads(probe.path.read_text())
    assert rows[-1]['expected_reachable'] != override
    assert len(rows)<50
    assert state['calls'].count(('attach',0))==1
    assert ('attach',1) not in state['calls']


def test_data_loss_after_management_move_cannot_be_reported_successful(tmp_path):
    probe,state=fixture(tmp_path);probe.prepare();state['override']=False
    with pytest.raises(RuntimeError,match='after-management-move'):
        probe.verify('after-management-move')
    rows=json.loads(probe.path.read_text())
    assert rows[-1]['stage']=='after-management-move'
    assert not any(r['stage']=='after-management-move-verified' for r in rows)
