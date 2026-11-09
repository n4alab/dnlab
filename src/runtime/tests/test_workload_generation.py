from copy import deepcopy
from pathlib import Path

import pytest

from dnlab_runtime.backend import LABEL
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.workload_generation import latest
from test_runtime import runtime, request, stop, run


def native():
    value=request();value['spec']['endpoints']=[]
    return value


@pytest.mark.parametrize('change',['id','creator','birth','missing-proof'])
def test_generation_conflict_preserves_replacement_and_reservations(runtime,change):
    engine,journal,docker,linux=runtime;value=native()
    assert run(engine,journal,value)['phase']=='completed'
    container=docker.containers[value['spec']['container_name']]
    if change=='id':container['Id']='different-generation'
    elif change=='missing-proof':journal.db.execute('DELETE FROM workload_generations')
    else:container['Config']['Labels'][LABEL+'.'+change]='changed'
    before=deepcopy(docker.containers);calls=list(docker.calls)
    with pytest.raises(Conflict):engine.inspect('demo','R1')
    with pytest.raises(Conflict):engine.plan(stop())
    result=run(engine,journal,stop())
    assert result['phase']=='recovery_required'
    assert docker.containers==before and docker.calls==calls
    assert journal.node('demo','R1')['revision']==1
    assert journal.db.execute('SELECT count(*) FROM resources').fetchone()[0]>0
    assert engine.reconcile(result['id'],force=True)['phase']=='recovery_required'
    assert docker.containers==before and docker.calls==calls


def test_stop_start_commits_new_generation_and_keeps_history(runtime):
    engine,journal,docker,linux=runtime;value=native()
    assert run(engine,journal,value)['phase']=='completed'
    original=latest(journal,value)
    assert run(engine,journal,stop())['phase']=='completed'
    assert latest(journal,value)['phase']=='cleaned'
    assert run(engine,journal,{**value,'expected_revision':2,'request_id':'restart'})['phase']=='completed'
    current=latest(journal,value)
    assert current['generation']==2 and current['container_id']!=original['container_id']
    assert current['nonce']!=original['nonce'] and current['creator']!=original['creator']
    assert current['committed_revision']==3
    history=[dict(row) for row in journal.db.execute('SELECT * FROM workload_generations ORDER BY generation')]
    assert history[0]['container_id']==original['container_id'] and history[0]['phase']=='cleaned'
    assert history[1]['phase']=='running'


def test_running_start_retry_preserves_original_generation(runtime):
    engine,journal,docker,linux=runtime;value=native()
    assert run(engine,journal,value)['phase']=='completed'
    original=latest(journal,value)
    assert run(engine,journal,{**value,'expected_revision':1,'request_id':'again'})['phase']=='completed'
    current=latest(journal,value)
    assert current['generation']==original['generation'] and current['container_id']==original['container_id']
    assert current['creator']==original['creator'] and current['committed_revision']==2


def test_missing_committed_container_cannot_be_recreated_by_start_retry(runtime):
    engine,journal,docker,linux=runtime;value=native()
    assert run(engine,journal,value)['phase']=='completed'
    docker.containers.clear();calls=list(docker.calls);proof=latest(journal,value)
    result=run(engine,journal,{**value,'expected_revision':1,'request_id':'again'})
    assert result['phase']=='recovery_required' and docker.calls==calls
    assert latest(journal,value)==proof and journal.node('demo','R1')['state']=='running'


def test_unbound_create_response_does_not_adopt_or_remove_container(runtime):
    engine,journal,docker,linux=runtime;value=native();original=docker.create
    def missing_id(*args):original(*args);return {}
    docker.create=missing_id
    result=run(engine,journal,value)
    assert result['phase']=='recovery_required'
    assert [c[0] for c in docker.calls]==['create']
    assert latest(journal,value)['container_id'] is None
    assert engine.reconcile(result['id'],force=True)['phase']=='recovery_required'
    assert [c[0] for c in docker.calls]==['create']


def test_binding_persistence_failure_blocks_start_and_cleanup_adoption(runtime,monkeypatch):
    from dnlab_runtime import workload_generation
    engine,journal,docker,linux=runtime;value=native()
    def fail(*args):raise OSError('binding storage failed')
    monkeypatch.setattr(workload_generation,'bind',fail)
    result=run(engine,journal,value)
    assert result['phase']=='recovery_required' and journal.node('demo','R1') is None
    assert [c[0] for c in docker.calls]==['create'] and docker.containers
    assert latest(journal,value)['phase']=='reserved'


def test_crash_before_allocation_reuses_durable_intent_after_reopen(runtime):
    engine,journal,docker,linux=runtime;value=native();original=docker.create
    def crash(*args):raise SystemExit('before allocation')
    docker.create=crash;operation=journal.submit(value)
    with pytest.raises(SystemExit):engine.execute(operation['id'])
    birth=latest(journal,value)
    path=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    journal.close();reopened=Journal(path)
    try:
        docker.create=original;restored=Engine(reopened,engine.backend)
        assert restored.recover()[0]['phase']=='completed'
        assert latest(reopened,value)['nonce']==birth['nonce']
        assert latest(reopened,value)['generation']==1
    finally:reopened.close()


def test_replay_new_birth_spec_uses_start_spec_after_committed_stop(runtime):
    engine,journal,docker,linux=runtime;value=native()
    assert run(engine,journal,value)['phase']=='completed'
    assert run(engine,journal,stop())['phase']=='completed'
    replacement={**value,'expected_revision':2,'request_id':'new-birth',
                 'spec':{**value['spec'],'command':['sleep','7200']}}
    operation=journal.submit(replacement)
    # Stage a fully recorded create before start/commit, just as the real smoke.
    engine.backend.create(replacement,replacement['spec'],operation['id'])
    proof=latest(journal,replacement);calls=list(docker.calls)
    assert engine.plan(replacement)['expected_revision']==2
    assert engine.execute(operation['id'])['phase']=='completed'
    assert latest(journal,replacement)['container_id']==proof['container_id']
    assert not any(c[0]=='remove' for c in docker.calls[len(calls):])
    assert journal.node('demo','R1')['revision']==3
