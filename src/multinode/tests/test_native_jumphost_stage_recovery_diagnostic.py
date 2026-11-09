"""Diagnostic: stage retry must preserve its original durable relay intent."""
from copy import deepcopy
import json

import pytest

from tests.test_native_jumphost_stage import stage, inventory, configure, native
import native_jumphost_stage as module


def test_retry_refused_by_guard_cannot_overwrite_original_stage_intent(stage, monkeypatch):
    value, docker, control, relay = stage
    value.prepare()
    path=value.root/'native-jumphost-stage-intent.json'
    original=path.read_bytes()
    config=deepcopy(value.config)
    guard=module.relays._guard

    def qualified_guard(host,lab,name,action,config=None,generation=None):
        if action=='preflight' and config is not None:
            assert config==relay['record']['config']
            raise RuntimeError('inert preflight rejection')
        return guard(host,lab,name,action,config,generation)

    monkeypatch.setattr(module.relays,'_guard',qualified_guard)
    with pytest.raises(RuntimeError,match='inert preflight rejection'):
        value.prepare()
    assert path.read_bytes()==original, 'stage retry overwrote the original durable relay intent'
    assert relay['record']['config']==config


def reopen(value):
    return module.NativeJumphostStage(value.root,value.topo,value.state,value.store,value.runtime,
                                      value.host,value.image,value.bind_ip,node=value.node)


def test_reopen_after_restart_keeps_original_intents_and_latest_generation(stage):
    value,docker,control,relay=stage
    value.prepare();value.restart()
    relay_intent=(value.root/'native-jumphost-stage-intent.json').read_bytes()
    publication=(value.root/'native-jumphost-initial-publication.json').read_bytes()
    history=deepcopy(value.lifecycle.record)
    calls=deepcopy(docker.calls);writes=control['writes']
    current=reopen(value);current.prepare()
    assert (current.root/'native-jumphost-stage-intent.json').read_bytes()==relay_intent
    assert (current.root/'native-jumphost-initial-publication.json').read_bytes()==publication
    assert current.lifecycle.record==history and relay['allocations']==1
    assert docker.calls==calls and control['writes']==writes


@pytest.mark.parametrize('boundary',['relay-ack','publication-ack'])
def test_lost_response_reuses_original_relay_and_publication(stage,monkeypatch,boundary):
    value,docker,control,relay=stage
    guard=module.relays._guard;armed=[True]
    if boundary=='publication-ack':control['failure']='ack'
    def lose_reply(*args,**kwargs):
        result=guard(*args,**kwargs)
        if boundary=='relay-ack' and args[3]=='ensure' and armed[0]:
            armed[0]=False;raise OSError('lost relay reply')
        return result
    monkeypatch.setattr(module.relays,'_guard',lose_reply)
    with pytest.raises(OSError):value.prepare()
    original=(value.root/'native-jumphost-stage-intent.json').read_bytes()
    calls=deepcopy(docker.calls)
    current=reopen(value);current.prepare()
    assert (current.root/'native-jumphost-stage-intent.json').read_bytes()==original
    assert relay['allocations']==1 and docker.calls==calls and control['writes']==1


@pytest.mark.parametrize('field',['image','bind_ip'])
def test_static_input_drift_refuses_before_guard_or_file_write(stage,field):
    value,docker,control,relay=stage
    value.prepare();path=value.root/'native-jumphost-stage-intent.json'
    original=path.read_bytes();state=module.states.state_file_path(value.topo.name,value.root).read_bytes()
    calls=deepcopy(relay['calls'])
    current=reopen(value)
    setattr(current,field,'sha256:'+'6'*64 if field=='image' else '127.0.0.2')
    with pytest.raises(RuntimeError,match='intent differs'):current.prepare()
    assert path.read_bytes()==original and relay['calls']==calls
    assert module.states.state_file_path(value.topo.name,value.root).read_bytes()==state


@pytest.mark.parametrize('conflict',['port','generation','extra'])
def test_malformed_saved_intent_is_preserved_and_never_invoked(stage,conflict):
    value,docker,control,relay=stage
    value.prepare();path=value.root/'native-jumphost-stage-intent.json'
    config=json.loads(path.read_text())
    if conflict=='port':config['port']=True
    elif conflict=='generation':config.pop('generation')
    else:config['unqualified']=True
    module.private_json(path,config);original=path.read_bytes();calls=deepcopy(relay['calls'])
    with pytest.raises(RuntimeError,match='intent differs'):reopen(value).prepare()
    assert path.read_bytes()==original and relay['calls']==calls


def test_missing_original_intent_cannot_adopt_published_relay(stage):
    value,docker,control,relay=stage
    value.prepare();path=value.root/'native-jumphost-stage-intent.json';path.unlink()
    calls=deepcopy(relay['calls'])
    with pytest.raises(RuntimeError,match='no adoption'):reopen(value).prepare()
    assert not path.exists() and relay['calls']==calls


def test_reopen_pending_restart_recovers_original_publication_without_restart(stage):
    value,docker,control,relay=stage
    value.prepare();control['failure']='ack'
    with pytest.raises(OSError):value.restart()
    original=(value.root/'native-jumphost-stage-intent.json').read_bytes()
    calls=deepcopy(docker.calls)
    current=reopen(value);current.prepare();current.restart()
    assert docker.calls==calls and relay['allocations']==1
    assert len(current.lifecycle.record['births'])==2 and control['writes']==2
    assert (current.root/'native-jumphost-stage-intent.json').read_bytes()==original


def test_missing_lifecycle_history_is_not_recreated_before_refusal(stage):
    value,docker,control,relay=stage
    value.prepare();path=value.root/'native-jumphost-lifecycle.json';path.unlink()
    original=(value.root/'native-jumphost-stage-intent.json').read_bytes()
    calls=deepcopy(relay['calls'])
    with pytest.raises(RuntimeError,match='lifecycle history missing'):reopen(value).prepare()
    assert not path.exists() and relay['calls']==calls
    assert (value.root/'native-jumphost-stage-intent.json').read_bytes()==original


def test_reopened_cleanup_cannot_skip_persisted_running_cli_exec(stage):
    from tests.test_jumphost_cli_execution import World
    from jumphost_cli_execution import Execution
    value,docker,control,relay=stage
    value.prepare()
    world=World();world.failure='running'
    world.owner['container_id']=control['record']['container_id']
    path=value.root/'cli-before-connect-exec.json'
    execution=Execution(path,world,world.owner,world.config,world.nonce,world.observe,
                        lambda record,status:deepcopy(world.result))
    with pytest.raises(RuntimeError,match='cleanup pending'):execution.run(timeout=.01)
    assert json.loads(path.read_text())['start_attempted'] and world.exec['Running']
    current=reopen(value);current.prepare()
    calls=deepcopy(docker.calls)
    try:outcome=current.cleanup()
    except RuntimeError as error:assert 'CLI' in str(error) and 'pending' in str(error)
    else:
        pytest.fail('cleanup skipped persisted CLI: verified='+str(outcome['verified'])
                    +', cli_running='+str(world.exec['Running'])
                    +', vd_count='+str(len(docker.containers))+', relay_phase='+relay['record']['phase'])
    assert docker.calls==calls and relay['record']['phase']=='active'
