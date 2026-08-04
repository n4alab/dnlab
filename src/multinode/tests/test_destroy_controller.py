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
        "dnlab_multinode.controllers.destroy.mgmt_network_svc.destroy_mgmt_network",
        lambda given_topo, client: removed.append((given_topo.name, client.name)),
    )

    ctrl._destroy_mgmt_network(topo)

    assert sorted(removed) == [("demo", "master"), ("demo", "worker1")]
    assert ctrl._errors == []


def test_destroy_runtime_links_skips_warm_carrier_shutdown():
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
