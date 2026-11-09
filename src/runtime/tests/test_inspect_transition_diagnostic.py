"""Inspect separates an owned restart from its previous committed node."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import Conflict
from dnlab_runtime.workload_generation import latest
from test_runtime import runtime, request, stop, run


@pytest.mark.parametrize('changed_spec',[False,True])
def test_inspect_describes_qualified_restart_before_commit(runtime,monkeypatch,changed_spec):
    engine,journal,docker,linux=runtime
    initial=request();initial['spec']['endpoints']=[]
    assert run(engine,journal,initial)['phase']=='completed'
    assert run(engine,journal,stop())['phase']=='completed'
    restarted=deepcopy(initial)
    restarted.update(expected_revision=2,request_id='restart-transition')
    if changed_spec:restarted['spec']['command']=['sleep','7200']
    operation=journal.submit(restarted)
    original_finish=journal.finish
    def crash_before_commit(*args,**kwargs):raise SystemExit('before node commit')
    monkeypatch.setattr(journal,'finish',crash_before_commit)
    with pytest.raises(SystemExit):engine.execute(operation['id'])
    # The new Docker birth is already qualified and running; only the final
    # node-spec/revision commit was interrupted.
    observed=engine.backend.verify(restarted,restarted['spec'])
    birth=latest(journal,restarted)
    assert birth['container_id']==observed['Id'] and birth['phase']=='bound'
    assert journal.node('demo','R1')['state']=='stopped'
    assert journal.node('demo','R1')['revision']==2
    assert journal.get(operation['id'])['phase']=='verifying'
    before=deepcopy(docker.containers);calls=list(docker.calls)
    view=engine.inspect('demo','R1')
    assert view['committed_state']=='stopped' and view['container_state']=='running'
    assert view['operation']['id']==operation['id'] and view['operation']['phase']=='verifying'
    assert view['workload']['container_id']==birth['container_id']
    assert view['workload']['generation']==2 and view['workload']['phase']=='bound'
    assert view['guest_readiness']=='unknown'
    assert docker.containers==before and docker.calls==calls
    # Recovery of the original request succeeds without a new Docker birth.
    monkeypatch.setattr(journal,'finish',original_finish)
    assert engine.recover()[0]['phase']=='completed'
    assert latest(journal,restarted)['container_id']==birth['container_id']
    assert engine.inspect('demo','R1')['revision']==3


@pytest.fixture
def pending_restart(runtime,monkeypatch):
    engine,journal,docker,linux=runtime
    initial=request();initial['spec']['endpoints']=[]
    assert run(engine,journal,initial)['phase']=='completed'
    assert run(engine,journal,stop())['phase']=='completed'
    pending=deepcopy(initial);pending.update(expected_revision=2,request_id='new-start')
    pending['spec']['command']=['sleep','7200'];pending['spec']['env']={'TOKEN':'inspection-private-marker'}
    operation=journal.submit(pending)
    original=journal.finish
    def crash(*args,**kwargs):raise SystemExit('before commit')
    monkeypatch.setattr(journal,'finish',crash)
    with pytest.raises(SystemExit):engine.execute(operation['id'])
    monkeypatch.setattr(journal,'finish',original)
    return engine,journal,docker,linux,pending,operation


def test_inspection_retries_commit_from_another_journal_connection(pending_restart,monkeypatch):
    import json
    from pathlib import Path
    from dnlab_runtime.journal import Journal
    engine,journal,docker,linux,pending,operation=pending_restart
    path=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    other=Journal(path);original=engine.backend.inspect;count=0
    def inspect(*args):
        nonlocal count
        result=original(*args);count+=1
        if count==1:other.finish(operation['id'],pending['spec'],'running')
        return result
    monkeypatch.setattr(engine.backend,'inspect',inspect)
    try:
        result=engine.inspect('demo','R1')
        assert result['revision']==3 and result['committed_state']=='running'
        assert result['operation'] is None and result['workload']['phase']=='running'
        assert count>=4 and 'inspection-private-marker' not in json.dumps(result)
    finally:other.close()


def test_inspection_rejects_replacement_between_docker_reads(pending_restart,monkeypatch):
    engine,journal,docker,linux,pending,operation=pending_restart
    original=engine.backend.inspect;count=0;before=list(docker.calls)
    def inspect(*args):
        nonlocal count
        result=original(*args);count+=1
        if count==1:docker.containers[pending['spec']['container_name']]['Id']='foreign-generation'
        return result
    monkeypatch.setattr(engine.backend,'inspect',inspect)
    with pytest.raises(Conflict,match='generation'):engine.inspect('demo','R1')
    assert docker.calls==before and journal.node('demo','R1')['revision']==2


def test_inspection_bounds_retries_when_docker_state_keeps_changing(pending_restart,monkeypatch):
    engine,journal,docker,linux,pending,operation=pending_restart
    original=engine.backend.inspect;count=0
    def inspect(*args):
        nonlocal count
        count+=1;docker.containers[pending['spec']['container_name']]['State']['Pid']+=1
        return original(*args)
    monkeypatch.setattr(engine.backend,'inspect',inspect)
    with pytest.raises(Conflict,match='changed concurrently'):engine.inspect('demo','R1')
    assert count==6


@pytest.mark.parametrize('tamper',['creator','hash','spec','revision','ambiguous'])
def test_pending_spec_requires_exact_original_operation(pending_restart,tamper):
    import json
    from dnlab_runtime.manifest import fingerprint
    engine,journal,docker,linux,pending,operation=pending_restart
    if tamper=='creator':journal.db.execute("UPDATE workload_generations SET creator=? WHERE generation=2",('f'*32,))
    elif tamper=='hash':journal.db.execute('UPDATE operations SET hash=? WHERE id=?',('f'*64,operation['id']))
    elif tamper=='ambiguous':
        journal.db.execute("INSERT INTO operations(id,lab,node,request_id,payload,hash,phase) SELECT ?,lab,node,?,payload,hash,phase FROM operations WHERE id=?",('f'*32,'another',operation['id']))
    else:
        changed=deepcopy(pending)
        if tamper=='spec':changed['spec']['command']=['other']
        else:changed['expected_revision']=1
        journal.db.execute('UPDATE operations SET payload=?,hash=? WHERE id=?',(json.dumps(changed),fingerprint(changed),operation['id']))
    before=deepcopy(docker.containers);calls=list(docker.calls)
    with pytest.raises(Conflict):engine.inspect('demo','R1')
    assert docker.containers==before and docker.calls==calls


def test_initial_start_can_be_inspected_before_first_commit(runtime,monkeypatch):
    engine,journal,docker,linux=runtime
    pending=request();pending['spec']['endpoints']=[]
    operation=journal.submit(pending)
    def crash(*args,**kwargs):raise SystemExit('before commit')
    monkeypatch.setattr(journal,'finish',crash)
    with pytest.raises(SystemExit):engine.execute(operation['id'])
    view=engine.inspect('demo','R1')
    assert view['revision']==0 and view['committed_state']=='absent'
    assert view['committed_spec_fingerprint'] is None
    assert view['workload']['generation']==1 and view['operation']['id']==operation['id']
    assert view['container_state']=='running' and view['guest_readiness']=='unknown'
