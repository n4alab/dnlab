"""Tests for destroy-controller compatibility cleanup."""

from pathlib import Path

from dnlab_multinode.controllers.destroy import DestroyController
from dnlab_multinode.models.state import DeploymentState, RuntimeLinkState
from dnlab_multinode.services import state as state_svc


class FakeClient:
    def __init__(self, name: str, fail: bool = False):
        self.name = name
        self.fail = fail
        self.commands: list[str] = []

    def run(self, cmd, *args, **kwargs):
        self.commands.append(cmd)
        if self.fail:
            raise RuntimeError("boom")
        return ""


def test_destroy_legacy_logging_removes_old_artifacts_best_effort():
    master = FakeClient("master")
    worker = FakeClient("worker1")
    ctrl = DestroyController("/tmp/demo.yml")
    ctrl._state = DeploymentState(lab_name="demo", topology_file="/tmp/demo.yml")
    ctrl._clients = {"master": master, "worker1": worker}

    ctrl._destroy_legacy_logging()

    assert any("docker rm -f dnlab-demo-log-shipper" in cmd for cmd in master.commands)
    assert any("docker rm -f dnlab-demo-log-shipper" in cmd for cmd in worker.commands)
    assert any("docker rm -f dnlab-demo-syslog" in cmd for cmd in master.commands)
    assert any("docker volume rm dnlab-demo-logs" in cmd for cmd in master.commands)
    assert ctrl._errors == []


def test_destroy_legacy_logging_ignores_cleanup_errors():
    master = FakeClient("master", fail=True)
    worker = FakeClient("worker1", fail=True)
    ctrl = DestroyController("/tmp/demo.yml")
    ctrl._state = DeploymentState(lab_name="demo", topology_file="/tmp/demo.yml")
    ctrl._clients = {"master": master, "worker1": worker}

    ctrl._destroy_legacy_logging()

    assert ctrl._errors == []


def test_destroy_mgmt_network_uses_guarded_service(monkeypatch, topo_factory):
    topo = topo_factory(name="demo", num_workers=1)
    master = FakeClient("master")
    worker = FakeClient("worker1")
    ctrl = DestroyController("/tmp/demo.yml")
    ctrl._state = DeploymentState(lab_name="demo", topology_file="/tmp/demo.yml")
    ctrl._clients = {"master": master, "worker1": worker}
    removed = []

    monkeypatch.setattr(
        "dnlab_multinode.controllers.destroy.netsetup.network_action",
        lambda state, clients, action, **kwargs: removed.append((state.lab_name,sorted(clients),action)),
    )

    ctrl._destroy_mgmt_network(topo)

    assert removed == [("demo",["master","worker1"],"cleanup")]
    assert ctrl._errors == []


def test_destroy_runtime_links_skips_warm_carrier_shutdown(monkeypatch):
    from dnlab_multinode.services import runtime_links
    # Controller ordering fixture; structured ownership is covered separately.
    class Guard:
        def __init__(self,client,link,bridge):self.client,self.bridge=client,bridge
        def inspect(self):return {'ifindex':1}
        def delete(self):self.client.run('ip link delete '+self.bridge)
    monkeypatch.setattr(runtime_links,'LocalBridgeGuard',Guard)
    class TC:
        def __init__(self,*args):pass
        def preflight(self,**kwargs):pass
        def cleanup(self):pass
    monkeypatch.setattr(runtime_links,'LocalTCGuard',TC)
    master = FakeClient("master")
    ctrl = DestroyController("/tmp/demo.yml")
    ctrl._state = DeploymentState(
        lab_name="demo",
        topology_file="/tmp/demo.yml",
        runtime_links=[
            RuntimeLinkState(
                id="l0",
                link_type="same_host",
                endpoint_a={"node": "R1", "iface": "eth1"},
                endpoint_b={"node": "R2", "iface": "eth1"},
                host_a="master",
                host_b="master",
                host_endpoint_a="wp-e1-left",
                host_endpoint_b="wp-e1-right",
                container_a="clab-dnlab-demo-R1-R1",
                warm_a=True,
            )
        ],
    )
    ctrl._clients = {"master": master}

    ctrl._destroy_runtime_links()

    assert not any("dnlab-linkctl" in cmd for cmd in master.commands)
    assert any("ip link delete br-rt-" in cmd for cmd in master.commands)
    assert ctrl._errors == []


def test_destroy_retains_teardown_state_after_partial_failure(tmp_path):
    ctrl = DestroyController(str(tmp_path / "demo.yml"))
    ctrl._state = DeploymentState(lab_name="demo", topology_file=str(tmp_path / "demo.yml"))

    ctrl._mark_teardown_requested(tmp_path)
    ctrl._errors.append("SSH connect failed: worker1")
    ctrl._finalize_state("demo", tmp_path)

    retained = state_svc.load_state("demo", tmp_path)
    assert retained is not None
    assert retained.teardown_requested is True


def test_destroy_deletes_state_after_clean_teardown(tmp_path):
    ctrl = DestroyController(str(tmp_path / "demo.yml"))
    ctrl._state = DeploymentState(lab_name="demo", topology_file=str(tmp_path / "demo.yml"))

    ctrl._mark_teardown_requested(tmp_path)
    ctrl._finalize_state("demo", tmp_path)

    assert state_svc.load_state("demo", tmp_path) is None


def test_complete_preflight_blocks_all_teardown_when_worker_unavailable(monkeypatch,tmp_path,topo_factory):
    import pytest
    from dnlab_multinode.controllers.destroy import DestroyError
    from dnlab_multinode.services import config,ssh
    topo=topo_factory(name='demo',num_workers=1)
    state=DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml'))
    state_svc.save_state(state,tmp_path)
    class Client:
        def __init__(self,name):self.name=name;self.commands=[];self.closed=False
        def connect(self):
            if self.name=='worker1':raise RuntimeError('unavailable')
        def close(self):self.closed=True
        def run(self,command,**kwargs):self.commands.append(command);return ''
    clients={name:Client(name) for name in ('master','worker1')}
    monkeypatch.setattr(config,'parse_topology',lambda *a,**k:topo)
    monkeypatch.setattr(ssh,'create_clients',lambda hosts:clients)
    controller=DestroyController(str(tmp_path/'demo.yml'))
    with pytest.raises(DestroyError,match='no teardown started'):controller.run()
    assert all(not client.commands and client.closed for client in clients.values())
    assert state_svc.load_state('demo',tmp_path).teardown_requested


def test_realnet_preflight_precedes_every_destroy_phase(monkeypatch,tmp_path,topo_factory):
    import pytest
    from dnlab_multinode.services import config,ssh
    from dnlab_multinode.models.state import RealNetState
    from dnlab_multinode.services.realnet_cleanup_host import OwnershipError
    topo=topo_factory(name='demo',num_workers=0)
    state=DeploymentState(lab_name='demo',topology_file=str(tmp_path/'demo.yml'),realnets=[RealNetState(name='access',bridge='br-legacy',vxlan_id=1,hosts=['master'])])
    state_svc.save_state(state,tmp_path)
    class Client:
        def __init__(self):self.commands=[]
        def connect(self):pass
        def close(self):pass
        def run(self,command,**kwargs):self.commands.append(command);return ''
    client=Client()
    monkeypatch.setattr(config,'parse_topology',lambda *a,**k:topo)
    monkeypatch.setattr(ssh,'create_clients',lambda hosts:{'master':client})
    controller=DestroyController(str(tmp_path/'demo.yml'))
    with pytest.raises(OwnershipError,match='qualification'):controller.run()
    assert not client.commands
    assert state_svc.load_state('demo',tmp_path).realnets


def test_dns_failure_stops_dependent_teardown(monkeypatch):
    import pytest
    from dnlab_multinode.controllers.destroy import DestroyError
    from dnlab_multinode.models.state import DnsState
    ctrl=DestroyController('/tmp/demo.yml')
    ctrl._state=DeploymentState(lab_name='demo',topology_file='/tmp/demo.yml')
    ctrl._state.dns=DnsState(node='master',container='dnlab-demo-dns',mgmt_ip='192.0.2.2',generation='a'*32)
    ctrl._clients={'master':FakeClient('master')}
    def reject(*args):raise RuntimeError('ownership conflict')
    monkeypatch.setattr('dnlab_multinode.controllers.destroy.dns_svc.destroy_dns',reject)
    with pytest.raises(DestroyError,match='dependent infrastructure retained'):ctrl._destroy_dns()
    assert ctrl._errors and ctrl._state.dns.generation=='a'*32
