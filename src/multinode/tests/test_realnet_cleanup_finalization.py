"""RealNet teardown must not discard state while persisted endpoints remain."""
import pytest

from dnlab_multinode.models.state import DeploymentState,RealNetState
from dnlab_multinode.services import lab_cleanup as cleanup,state as state_svc
from tests.test_lab_cleanup import FakeClient,_hosts


def realnet_state(tmp_path):
    return DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml'),teardown_requested=True,
        realnets=[RealNetState(name='access',bridge='br-realnet',vxlan_id=42001,
            hosts=['master','worker1'],router_container='dnlab-demo-access-realnet',
            router_veth='vh-realnet',vxlan_ifaces={'master':['vx-peer-one','vx-peer-two'],'worker1':['vx-worker']})])


def test_realnet_expected_artifacts_cover_every_persisted_kernel_resource(tmp_path):
    state=realnet_state(tmp_path)
    resources={(entry.host,entry.name) for entry in cleanup.expected_artifacts_from_state(state)}
    assert resources.issuperset({('master','br-realnet'),('worker1','br-realnet'),
        ('master','dnlab-demo-access-realnet'),('master','vh-realnet'),
        ('master','vx-peer-one'),('master','vx-peer-two'),('worker1','vx-worker')})


@pytest.mark.parametrize('host,remaining',[('master','vh-realnet'),('master','vx-peer-one'),('master','vx-peer-two'),('worker1','vx-worker')])
def test_finalizer_retains_state_when_only_realnet_endpoint_remains(tmp_path,host,remaining):
    state=realnet_state(tmp_path);state_svc.save_state(state,tmp_path)
    clients={name:FakeClient(name,interfaces=[remaining] if name==host else []) for name in ('master','worker1')}
    status=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients=clients)
    assert state_svc.load_state('demo',tmp_path) is not None,status
    assert 'retained' in status['demo']
    assert 'interfaces still present' in status['demo']
    assert remaining in status['demo']


def test_finalizer_retains_empty_inventory_until_journal_is_verified(monkeypatch,tmp_path):
    from dnlab_multinode.services import realnet_cleanup
    state=realnet_state(tmp_path);state_svc.save_state(state,tmp_path)
    def verify(*args):raise RuntimeError('journal cleanup_pending')
    monkeypatch.setattr(realnet_cleanup,'verify_realnets_cleaned',verify)
    clients={name:FakeClient(name) for name in ('master','worker1')}
    status=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients=clients)
    assert state_svc.load_state('demo',tmp_path) is not None
    assert 'journal cleanup_pending' in status['demo']


def test_finalizer_rechecks_guard_before_removing_state(monkeypatch,tmp_path):
    from dnlab_multinode.services import realnet_cleanup
    state=realnet_state(tmp_path);state_svc.save_state(state,tmp_path);verified=[]
    monkeypatch.setattr(realnet_cleanup,'verify_realnets_cleaned',lambda lab,clients,states:verified.append(lab))
    clients={name:FakeClient(name) for name in ('master','worker1')}
    status=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients=clients)
    assert verified==['demo'] and state_svc.load_state('demo',tmp_path) is None
    assert status['demo'].endswith('finalized')


def test_realnet_inventory_never_emits_generic_delete_actions(tmp_path):
    state=realnet_state(tmp_path)
    for artifact in cleanup.expected_artifacts_from_state(state):
        assert cleanup._action_for_artifact(artifact,state) is None
    orphan=cleanup.CleanupArtifact('container','dnlab-orphan-access-realnet','master','orphan')
    assert cleanup._action_for_artifact(orphan,None) is None


@pytest.mark.parametrize('failure',['preflight','host_unavailable','legacy_intent'])
def test_daemon_preflight_refusal_precedes_all_generic_cleanup(monkeypatch,tmp_path,failure):
    from dnlab_multinode.services import realnet
    state=realnet_state(tmp_path);state_svc.save_state(state,tmp_path);called=[]
    artifact=cleanup.CleanupArtifact('container','owned-service','master','demo')
    action=cleanup.CleanupAction('remove-container',artifact,'docker rm -f owned-service','fixture')
    plan=cleanup.LabCleanupPlan(lab='demo',actions=[action])
    clients={name:FakeClient(name) for name in ('master','worker1')}
    if failure=='host_unavailable':del clients['worker1']
    if failure=='legacy_intent':state.teardown_requested=False
    def preflight(*args):called.append('preflight');raise RuntimeError('ownership mismatch')
    monkeypatch.setattr(realnet,'preflight_realnets',preflight)
    cleanup._execute_plans({'demo':plan},clients,own_clients=False,states={'demo':state},state_directory=tmp_path)
    assert plan.protected and not action.executed
    assert all(command.startswith(('docker ps -a','docker container ls','docker inspect'))
               for client in clients.values() for command in client.commands)
    assert state_svc.load_state('demo',tmp_path) is not None


def test_daemon_guard_failure_retains_checkpoint_for_retry(monkeypatch,tmp_path):
    from dnlab_multinode.services import realnet
    state=realnet_state(tmp_path);state_svc.save_state(state,tmp_path);calls=[]
    plan=cleanup.LabCleanupPlan(lab='demo');clients={name:FakeClient(name) for name in ('master','worker1')}
    monkeypatch.setattr(realnet,'preflight_realnets',lambda *args:calls.append('preflight'))
    monkeypatch.setattr('dnlab_multinode.services.realnet_cleanup.detach_realnet_attachments',lambda *args,**kwargs:calls.append('detach'))
    def recover(lab,clients,states,checkpoint):
        calls.append('recovery');states[0].resource_identities['realnet_cleanup_operation']={'phase':'cleanup_pending'}
        checkpoint();raise RuntimeError('worker lost after mutation')
    monkeypatch.setattr(realnet,'destroy_realnets',recover)
    cleanup._execute_plans({'demo':plan},clients,own_clients=False,states={'demo':state},state_directory=tmp_path)
    saved=state_svc.load_state('demo',tmp_path)
    assert calls==['preflight','detach','recovery']
    assert saved.realnets[0].resource_identities['realnet_cleanup_operation']['phase']=='cleanup_pending'
    assert any('recovery pending' in warning for warning in plan.warnings)


def test_finalizer_does_not_discard_state_with_unreleased_vni_reservation(monkeypatch,tmp_path):
    """Crash after remote cleanup but before coordinator VNI release."""
    from types import SimpleNamespace
    from dnlab_multinode.services import realnet_cleanup,realnet_vni
    from tests.test_realnet_vni import request,empty
    registry=realnet_vni.Registry(tmp_path/'vni')
    row=next(iter(registry.reserve([request('demo')],empty).values()))
    monkeypatch.setattr(realnet_vni,'PATHS',SimpleNamespace(realnet_vni_dir=str(registry.directory)))
    state=realnet_state(tmp_path)
    state.realnets[0].vxlan_id=row['vni'];state.realnets[0].vxlan_ids={'worker1':row['vni']}
    state.realnets[0].resource_identities['realnet_vni_v1']={'worker1':row}
    state.realnets[0].resource_identities['realnet_cleanup_operation']={'phase':'cleaned','hosts':{'master':'cleaned','worker1':'cleaned'}}
    state_svc.save_state(state,tmp_path)
    verified=[]
    # The remote guard has completed. Only the coordinator step remains;
    # no actual kernel, Docker or SSH operation is performed by this test.
    monkeypatch.setattr(realnet_cleanup,'verify_realnets_cleaned',lambda lab,clients,states:verified.append(lab))
    clients={name:FakeClient(name) for name in ('master','worker1')}
    status=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients=clients)
    saved=state_svc.load_state('demo',tmp_path)
    reservation=registry.read()['reservations'][row['key']]
    assert verified and set(verified)=={'demo'}
    assert saved is not None or reservation['phase']=='released',{
        'daemon_status':status,'state_retained':saved is not None,'reservation_phase':reservation['phase'],
        'failure':'state deleted before pending VNI release/recovery'}


def reserved_teardown(monkeypatch,tmp_path):
    from types import SimpleNamespace
    from dnlab_multinode.services import realnet_cleanup,realnet_vni
    from tests.test_realnet_vni import request,empty
    registry=realnet_vni.Registry(tmp_path/'vni')
    req=request('demo');row=next(iter(registry.reserve([req],empty).values()))
    monkeypatch.setattr(realnet_vni,'PATHS',SimpleNamespace(realnet_vni_dir=str(registry.directory)))
    state=realnet_state(tmp_path)
    state.realnets[0].vxlan_id=row['vni'];state.realnets[0].vxlan_ids={'worker1':row['vni']}
    state.realnets[0].resource_identities['realnet_vni_v1']={'worker1':row}
    state_svc.save_state(state,tmp_path)
    monkeypatch.setattr(realnet_cleanup,'verify_realnets_cleaned',lambda *args:None)
    clients={name:FakeClient(name) for name in ('master','worker1')}
    return state,registry,row,req,clients


def test_finalizer_releases_vni_before_deleting_local_state(monkeypatch,tmp_path):
    state,registry,row,_,clients=reserved_teardown(monkeypatch,tmp_path)
    original=state_svc.delete_state;seen=[]
    def delete(lab,directory):
        seen.append(registry.read()['reservations'][row['key']]['phase'])
        return original(lab,directory)
    monkeypatch.setattr(state_svc,'delete_state',delete)
    result=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients=clients)
    assert seen==['released'] and result['demo'].endswith('finalized')


@pytest.mark.parametrize('failure',['write_error','generation_conflict','remote_recheck','unavailable_worker'])
def test_finalizer_retains_state_and_reservation_on_release_failure(monkeypatch,tmp_path,failure):
    from dnlab_multinode.services import realnet_vni,realnet_cleanup
    state,registry,row,req,clients=reserved_teardown(monkeypatch,tmp_path)
    if failure=='write_error':
        def fail(*args):raise OSError('registry storage unavailable')
        monkeypatch.setattr(realnet_vni.Registry,'save',fail)
    if failure=='generation_conflict':
        value=registry.read();value['reservations'][row['key']]['token']='b'*32;registry.save(value)
    if failure=='remote_recheck':
        calls=[]
        def verify(*args):
            calls.append(True)
            if len(calls)>1:raise RuntimeError('remote journal changed before release')
        monkeypatch.setattr(realnet_cleanup,'verify_realnets_cleaned',verify)
    if failure=='unavailable_worker':del clients['worker1']
    before=(registry.directory/'registry.json').read_bytes()
    status=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients=clients)
    assert 'retained' in status['demo'] and state_svc.load_state('demo',tmp_path) is not None
    assert (registry.directory/'registry.json').read_bytes()==before
    assert registry.read()['reservations'][row['key']]['phase']=='reserved'


def test_finalizer_recovers_crash_after_vni_release_before_state_delete(monkeypatch,tmp_path):
    from dnlab_multinode.services import realnet_vni
    state,registry,row,_,clients=reserved_teardown(monkeypatch,tmp_path)
    realnet_vni.release_realnets('demo',clients,state.realnets)
    before=(registry.directory/'registry.json').read_bytes()
    assert state_svc.load_state('demo',tmp_path) is not None
    status=cleanup._finalize_requested_teardowns({'demo':state},tmp_path,_hosts(),clients=clients)
    assert status['demo'].endswith('finalized') and state_svc.load_state('demo',tmp_path) is None
    assert (registry.directory/'registry.json').read_bytes()==before


def test_daemon_detach_failure_blocks_generic_actions_and_retains_state(monkeypatch,tmp_path):
    from dnlab_multinode.services import realnet
    state=realnet_state(tmp_path);state_svc.save_state(state,tmp_path)
    plan=cleanup.LabCleanupPlan(lab='demo');clients={name:FakeClient(name) for name in ('master','worker1')}
    monkeypatch.setattr(realnet,'preflight_realnets',lambda *args:None)
    def detach(lab,clients,states,checkpoint,**kwargs):
        states[0].resource_identities['realnet_attachment_teardown']={'phase':'cleanup_pending'}
        checkpoint();raise RuntimeError('attachment journal needs recovery')
    monkeypatch.setattr('dnlab_multinode.services.realnet_cleanup.detach_realnet_attachments',detach)
    cleanup._execute_plans({'demo':plan},clients,own_clients=False,states={'demo':state},state_directory=tmp_path)
    assert plan.protected and 'realnet-preflight-failed' in plan.reasons
    assert state_svc.load_state('demo',tmp_path).realnets[0].resource_identities['realnet_attachment_teardown']['phase']=='cleanup_pending'
