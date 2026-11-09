"""Cleanup callers must preserve dependencies until jumphost cleanup is verified."""
from unittest.mock import MagicMock

import pytest

from dnlab_multinode.controllers.destroy import DestroyController, DestroyError
from dnlab_multinode.models.state import DeploymentState, JumphostState
from dnlab_multinode.services import jumphost, lab_cleanup as cleanup, state as state_svc


def state(tmp_path):
    result=DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml'),teardown_requested=True)
    result.jumphost=JumphostState(generation='1'*32,node='master',container='dnlab-demo-jumphost',mgmt_ip='198.18.0.254',host_ip='192.0.2.2',ext_network='shared')
    return result


def plan():
    return cleanup.LabCleanupPlan(lab='demo',actions=[
        cleanup._action_for_artifact(cleanup.CleanupArtifact('container','dnlab-demo-jumphost','master','demo'),None),
        cleanup.CleanupAction(action='delete-interface',artifact=cleanup.CleanupArtifact('interface','br-demo','master','demo',metadata={'role':'mgmt-infra'}),command='ip link delete br-demo',reason='test')])


@pytest.mark.parametrize('failed_phase',['preflight','delete'])
def test_daemon_preserves_dependencies_on_jumphost_conflict(monkeypatch,failed_phase,tmp_path):
    client=MagicMock();client.run_no_check.return_value=(0,'','');p=plan();events=[]
    def preflight(*a):
        events.append('preflight')
        if failed_phase=='preflight':raise RuntimeError('foreign generation')
    def delete(*a):events.append('delete');raise RuntimeError('recovery pending')
    monkeypatch.setattr(jumphost,'preflight_jumphost_cleanup',preflight)
    monkeypatch.setattr(jumphost,'destroy_jumphost',delete)
    cleanup._execute_plans({'demo':p},{'master':client},own_clients=False,states={'demo':state(tmp_path)})
    assert p.protected
    assert events==(['preflight'] if failed_phase=='preflight' else ['preflight','delete'])
    assert not p.actions[1].executed
    assert all(call.args[0].startswith(('docker ps ', 'docker container ls ')) for call in client.run_no_check.call_args_list)


def test_daemon_delegates_before_dependent_network_actions(monkeypatch,tmp_path):
    client=MagicMock();client.run_no_check.return_value=(0,'','');p=plan();events=[]
    monkeypatch.setattr(jumphost,'preflight_jumphost_cleanup',lambda *a:events.append('preflight'))
    monkeypatch.setattr(jumphost,'destroy_jumphost',lambda *a:events.append('delete'))
    client.run_no_check.side_effect=lambda *a,**kw:(events.append(a[0]) or (0,'',''))
    cleanup._execute_plans({'demo':p},{'master':client},own_clients=False,states={'demo':state(tmp_path)})
    assert [e for e in events if not e.startswith(('docker ps ', 'docker container ls '))]==['preflight','delete','ip link delete br-demo']
    assert all(a.executed and a.ok for a in p.actions)
    assert p.actions[0].command==''


def test_destroy_stops_before_dependencies_on_jumphost_failure(tmp_path,monkeypatch):
    ctrl=DestroyController(str(tmp_path/'demo.yml'));ctrl._state=state(tmp_path);ctrl._clients={'master':MagicMock()}
    monkeypatch.setattr(jumphost,'preflight_jumphost_cleanup',lambda *a:(_ for _ in ()).throw(RuntimeError('identity differs')))
    remove=MagicMock();monkeypatch.setattr(jumphost,'destroy_jumphost',remove)
    with pytest.raises(DestroyError,match='dependent infrastructure retained'):ctrl._destroy_jumphost()
    remove.assert_not_called()
    assert ctrl._errors


def test_daemon_finalization_keeps_state_until_journal_cleaned(tmp_path,monkeypatch):
    st=state(tmp_path);state_svc.save_state(st,tmp_path);client=MagicMock()
    monkeypatch.setattr(cleanup,'_vd_preflight',lambda *a,**kw:None)
    monkeypatch.setattr(cleanup,'_teardown_remaining_artifacts',lambda *a:(False,''))
    def pending(*a):raise RuntimeError('cleanup pending')
    monkeypatch.setattr(jumphost,'verify_jumphost_cleaned',pending)
    result=cleanup._finalize_requested_teardowns({'demo':st},tmp_path,None,clients={'master':client})
    assert 'jumphost journal' in result['demo'] and state_svc.load_state('demo',tmp_path)
    monkeypatch.setattr(jumphost,'verify_jumphost_cleaned',lambda *a:None)
    result=cleanup._finalize_requested_teardowns({'demo':st},tmp_path,None,clients={'master':client})
    assert result['demo']=='pending teardown state finalized'
    assert state_svc.load_state('demo',tmp_path) is None


@pytest.mark.parametrize('persistence_failure',[False,True])
def test_coordinator_generation_is_saved_before_host_allocation(tmp_path,monkeypatch,topo_factory,persistence_failure):
    from types import SimpleNamespace
    from dnlab_multinode.controllers.deploy import DeployController
    ctrl=DeployController(str(tmp_path/'demo.yml'));ctrl._state=DeploymentState(lab_name='demo',topology_file=ctrl.topology_file)
    ctrl._clients={'master':MagicMock()};topo=topo_factory(name='demo')
    monkeypatch.setattr(jumphost,'collect_authorized_pubkeys',lambda c:'')
    calls=[]
    def deploy(*args,**kwargs):
        saved=state_svc.load_state('demo',tmp_path)
        assert saved.jumphost.generation==kwargs['generation'] and len(kwargs['generation'])==32
        calls.append(kwargs['generation']);raise RuntimeError('intercepted allocation')
    monkeypatch.setattr(jumphost,'deploy_jumphost',deploy)
    if persistence_failure:
        from dnlab_multinode.controllers import deploy as module
        monkeypatch.setattr(module.state_svc,'save_state',lambda *a:(_ for _ in ()).throw(OSError('fsync failed')))
        with pytest.raises(OSError):ctrl._deploy_jumphost(topo,SimpleNamespace(assignments={}))
        assert not calls
    else:
        with pytest.raises(RuntimeError,match='intercepted allocation'):ctrl._deploy_jumphost(topo,SimpleNamespace(assignments={}))
        with pytest.raises(RuntimeError,match='intercepted allocation'):ctrl._deploy_jumphost(topo,SimpleNamespace(assignments={}))
        assert calls[0]==calls[1]
