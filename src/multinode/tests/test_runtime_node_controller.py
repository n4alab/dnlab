import pytest

from dnlab_multinode.controllers.runtime_node import RuntimeNodeController
from dnlab_multinode.services.runtime_operations import RuntimeOperationError
from tests.test_runtime_operations import fixture, REQUEST, TARGET


def prepare(fixture):
    store,client,driver=fixture
    request={k:v for k,v in REQUEST.items() if k!='spec'}
    request.update(action='stop',stop_mode='coordinated')
    controller=RuntimeNodeController(store,lambda target:client)
    controller.prepare_local_stop(request,TARGET,participating_hosts=['master'])
    controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    return controller,store,client


def stage_client(client,phase='awaiting_link_cleanup',stage='exit_verified',verified=True):
    client.remote['start-a'].update(phase=phase,stop_stage=stage,shutdown_verified=verified)
    def send(identity,lab,node,next_stage):
        client.calls.append(('stage',next_stage))
        return dict(client.remote['start-a'])
    client.node_stop_stage=send


def test_controller_persists_cleanup_then_finalization(fixture):
    controller,store,client=prepare(fixture);stage_client(client)
    original=client.node_stop_stage
    def checked(identity,lab,node,stage):
        assert store.get(lab,'start-a')['stop_requested_stage']==stage
        return original(identity,lab,node,stage)
    client.node_stop_stage=checked
    controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert store.get('lab','start-a')['stop_requested_stage']=='cleanup'
    stage_client(client,'awaiting_finalization','links_cleaned')
    controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert store.get('lab','start-a')['stop_requested_stage']=='finalize'


@pytest.mark.parametrize('phase',['recovery_required','failed','cancelled','queued','applying'])
def test_controller_never_reconciles_or_forces_pending_and_failed_shutdown(fixture,phase):
    controller,store,client=prepare(fixture);stage_client(client,phase)
    controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert store.get('lab','start-a')['stop_requested_stage']==''
    assert not any(isinstance(c,tuple) for c in client.calls)


@pytest.mark.parametrize('stage,verified',[('shutdown_requested',True),('exit_verified',False),('exit_verified',None)])
def test_controller_refuses_unverified_receipt(fixture,stage,verified):
    controller,store,client=prepare(fixture);stage_client(client,stage=stage,verified=verified)
    with pytest.raises(RuntimeOperationError,match='does not verify'):
        controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert store.get('lab','start-a')['stop_requested_stage']==''


def test_controller_rechecks_remote_before_authorizing_stale_parked_receipt(fixture):
    controller,store,client=prepare(fixture);stage_client(client)
    store.observe('lab','start-a',client.remote['start-a'])
    client.remote['start-a']['phase']='recovery_required'
    controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert store.get('lab','start-a')['stop_requested_stage']==''


def test_controller_requires_full_single_host_footprint_before_any_remote_call(fixture):
    controller,store,client=prepare(fixture);before=list(client.calls)
    with pytest.raises(RuntimeOperationError,match='single-host'):
        controller.advance_local_stop('lab','start-a',participating_hosts=['master','worker'])
    assert client.calls==before


def test_controller_lost_stage_ack_reopens_same_intent(fixture):
    controller,store,client=prepare(fixture);stage_client(client)
    original=client.node_stop_stage
    def lost(*args):
        client.node_stop_stage=original
        original(*args)
        raise RuntimeError('lost acknowledgement')
    client.node_stop_stage=lost
    with pytest.raises(RuntimeError,match='lost acknowledgement'):
        controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert store.get('lab','start-a')['stop_requested_stage']=='cleanup'
    fresh=RuntimeNodeController(store,lambda target:client)
    fresh.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert client.calls.count('submit')==1
    assert store.get('lab','start-a')['operation_id']=='1'*32


def test_controller_does_not_send_stage_after_intent_persistence_failure(fixture,monkeypatch):
    controller,store,client=prepare(fixture);stage_client(client)
    original=store.request_stop_stage
    def fail(*args):
        original(*args)
        raise OSError('directory synchronization failed')
    monkeypatch.setattr(store,'request_stop_stage',fail)
    with pytest.raises(OSError,match='synchronization'):
        controller.advance_local_stop('lab','start-a',participating_hosts=['master'])
    assert not any(isinstance(c,tuple) for c in client.calls)
    assert store.get('lab','start-a')['stop_requested_stage']=='cleanup'
