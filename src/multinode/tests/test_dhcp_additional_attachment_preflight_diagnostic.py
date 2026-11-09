"""Diagnostic: every shared dnsmasq mutation must qualify all attached L2s.

Simulated Docker/kernel, real worker journals and DHCP files. No host mutation
or real dnsmasq signalling occurs. Do not weaken the additional-port guard.
"""
from copy import deepcopy
import json

import pytest

from dnlab_multinode.services.jumphost_host import JumphostError
from tests.test_jumphost_host import config
from tests.test_jumphost_segments import MultiWorld
from tests.test_jumphost_dhcp import content, install_service


def dhcp(ip='198.18.0.11'):
    return (content(ip) + 'interface=jmblue\n'
        'dhcp-range=set:blue,198.18.1.0,static,12h\n'
        'dhcp-option=tag:blue,option:router,198.18.1.254\n'
        'dhcp-option=tag:blue,option:dns-server,192.0.2.53\n'
        'dhcp-host=02:00:00:12:34:57,198.18.1.11\n')


def prepared(tmp_path):
    cfg=config();cfg['dhcp']=dhcp()
    world=MultiWorld(cfg);worker=world.worker(tmp_path/'journal')
    worker.operate('ensure',cfg)
    request=world.add_segment(worker)
    worker.operate('segment-add',request)
    service,calls,fault=install_service(worker)
    record=worker.operate('read')
    request={'container':cfg['name'],'generation':cfg['generation'],
        'request_id':'a'*32,'content':dhcp('198.18.0.12')}
    return world,worker,record,request,calls,fault


@pytest.mark.parametrize('phase',['fresh','recover','replay'])
def test_control_refresh_and_recovery_work_with_both_qualified_attachments(tmp_path,phase):
    world,worker,record,request,calls,fault=prepared(tmp_path)
    if phase=='recover':
        fault['reload']=True
        with pytest.raises(JumphostError):worker.operate('dhcp-refresh',request)
        fault['reload']=False
        result=worker.operate('recover')
    else:
        result=worker.operate('dhcp-refresh',request)
        if phase=='replay':result=worker.operate('dhcp-refresh',request)
    assert result['phase']=='active'
    assert worker.operate('read')==result


@pytest.mark.parametrize('phase',['fresh','recover','replay'])
@pytest.mark.parametrize('side',['host','peer'])
def test_unqualified_additional_attachment_blocks_refresh_recover_and_replay(tmp_path,phase,side):
    world,worker,record,request,calls,fault=prepared(tmp_path)
    if phase=='recover':
        fault['reload']=True
        with pytest.raises(JumphostError):worker.operate('dhcp-refresh',request)
        fault['reload']=False
    elif phase=='replay':worker.operate('dhcp-refresh',request)
    current=worker.read();row=current['management_attachments']['blue']
    port=next(value for value in (world.host if side=='host' else world.peer)
              if value['ifindex']==row[side]['ifindex'])
    port['ifindex']+=1000;port['address']='02:ff:00:00:00:99'
    # The existing attachment guard detects this same substitution. A pending
    # journal read only reports its status; it is not a readiness assertion.
    with pytest.raises(JumphostError):worker.verify_extensions(worker.read())
    directory=worker.dhcp_directory(current)
    before={p.name:p.read_bytes() for p in directory.iterdir()}
    journal=worker.path.read_bytes();hosts=deepcopy(world.host);peers=deepcopy(world.peer)
    calls.clear();rejected=False
    try:
        worker.operate('recover' if phase=='recover' else 'dhcp-refresh',None if phase=='recover' else request)
    except JumphostError:rejected=True
    evidence={'phase':phase,'side':side,'rejected':rejected,'service_actions':calls,
        'assets_changed':before!={p.name:p.read_bytes() for p in directory.iterdir()},
        'journal_changed':journal!=worker.path.read_bytes(),
        'interfaces_preserved':world.host==hosts and world.peer==peers,
        'final_phase':worker.read()['phase']}
    (tmp_path/'diagnostic.json').write_text(json.dumps(evidence,indent=2)+'\n')
    assert rejected,evidence
    assert 'reload' not in calls
    assert not evidence['assets_changed'] and evidence['interfaces_preserved']


@pytest.mark.parametrize('boundary',['write','replace','reload','commit'])
def test_attachment_conflict_between_phases_retains_recoverable_intent(tmp_path,monkeypatch,boundary):
    world,worker,record,request,calls,fault=prepared(tmp_path)
    row=record['management_attachments']['blue']
    port=next(v for v in world.host if v['ifindex']==row['host']['ifindex'])
    original=deepcopy(port);armed=[True]
    def conflict():
        if armed[0]:
            armed[0]=False;port['address']='02:ff:00:00:00:99'
    if boundary=='write':
        service=worker.dhcp_service
        def inspect(value,action='inspect',expected=None):
            result=service(value,action,expected)
            if expected is not None and action=='inspect':conflict()
            return result
        monkeypatch.setattr(worker,'dhcp_service',inspect)
    elif boundary=='replace':
        save=worker.save
        def synced(value):
            save(value)
            if value.get('action')=='dhcp' and (value.get('dhcp_operation') or {}).get('writes',{}).get('hosts',{}).get('synced'):
                conflict()
        monkeypatch.setattr(worker,'save',synced)
    elif boundary=='reload':
        write=worker.dhcp_write
        def written(value):
            write(value);conflict()
        monkeypatch.setattr(worker,'dhcp_write',written)
    else:
        service=worker.dhcp_service
        def reload(value,action='inspect',expected=None):
            result=service(value,action,expected)
            if action=='reload':conflict()
            return result
        monkeypatch.setattr(worker,'dhcp_service',reload)
    before={key:(worker.dhcp_directory(record)/key).read_bytes() for key in ('main','hosts','options')}
    with pytest.raises(JumphostError):worker.operate('dhcp-refresh',request)
    assert not armed[0]
    pending=worker.read()
    assert pending['phase']=='recovery_required' and pending['dhcp_operation']['id']==request['request_id']
    assert pending['dhcp_current']==record['dhcp_current'] and not pending.get('dhcp_history')
    if boundary in ('write','replace'):
        assert before=={key:(worker.dhcp_directory(record)/key).read_bytes() for key in before}
    assert calls.count('reload')==(1 if boundary=='commit' else 0)
    port.clear();port.update(original)
    result=worker.operate('recover')
    assert result['phase']=='active' and result['container_id']==record['container_id']
    assert result['dhcp_history'][0]['request_id']==request['request_id']
