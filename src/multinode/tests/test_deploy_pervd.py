"""Tests for per-VD deploy orchestration."""

from dnlab_multinode.controllers.deploy import DeployController, DeployError
from dnlab_multinode.models.schedule import HostAssignment, SchedulePlan
from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.models.topology import VDNode


class FakeClient:
    def __init__(self, name, fail_on=None):
        self.name = name
        self.fail_on = fail_on or set()
        self.uploads = []
        self.deploys = []
        self.deploy_options = []
        self.destroys = []
        self.runs = []
        self.events = []

    def upload_text(self, content, remote_path):
        self.events.append(("upload", remote_path))
        self.uploads.append((remote_path, content))

    def deploy_clab(self, remote_path, *, reconfigure=False):
        self.events.append(("deploy", remote_path, reconfigure))
        self.deploys.append(remote_path)
        self.deploy_options.append((remote_path, reconfigure))
        if remote_path in self.fail_on:
            raise RuntimeError("clab exploded")
        return "ok"

    def destroy_clab(self, remote_path):
        self.events.append(("destroy", remote_path))
        self.destroys.append(remote_path)
        return "ok"

    def run(self, command, **kwargs):
        self.runs.append((command, kwargs))
        return ""


def _controller_for(topo):
    ctrl = DeployController("/tmp/lab.yml")
    ctrl._state = DeploymentState(lab_name=topo.name, topology_file="/tmp/lab.yml")
    ctrl._underlay_ips = {
        host_name: host.host
        for host_name, host in topo.all_hosts.items()
    }
    return ctrl


def test_initial_deploy_defers_warm_carriers(monkeypatch, topo_factory):
    topo = topo_factory(nodes={}, links=[], num_workers=0)
    ctrl = _controller_for(topo)
    ctrl._clients = {}
    marker = object()
    observed = {}

    monkeypatch.setattr(
        "dnlab_multinode.controllers.deploy.runtime_links_svc.build_runtime_links",
        lambda *_args: [marker],
    )

    def reconcile(*_args, **kwargs):
        observed.update(kwargs)
        return []

    monkeypatch.setattr(
        "dnlab_multinode.controllers.deploy.runtime_links_svc.reconcile_all_links",
        reconcile,
    )

    ctrl._deploy_runtime_links(
        topo, SchedulePlan(lab_name=topo.name, assignments={}),
    )

    assert observed["defer_warm_carriers"] is True


def test_pervd_deploy_is_sequential_within_each_host(topo_factory):
    topo = topo_factory(
        nodes={
            "R1": VDNode(name="R1", kind="linux", image="alpine"),
            "R2": VDNode(name="R2", kind="linux", image="alpine"),
            "R3": VDNode(name="R3", kind="linux", image="alpine"),
        },
        links=[],
        num_workers=1,
    )
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1", "R2"]),
            "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R3"]),
        },
    )
    ctrl = _controller_for(topo)
    ctrl._clients = {
        "master": FakeClient("master"),
        "worker1": FakeClient("worker1"),
    }

    ctrl._deploy_clab(topo, plan)

    assert ctrl._clients["master"].deploys == [
        "/tmp/dnlab-lab-R1-master.clab.yml",
        "/tmp/dnlab-lab-R2-master.clab.yml",
    ]
    assert ctrl._clients["worker1"].deploys == [
        "/tmp/dnlab-lab-R3-worker1.clab.yml",
    ]
    assert set(ctrl._state.node_runtime) == {"R1", "R2", "R3"}
    assert ctrl._state.node_runtime["R1"].container == "clab-dnlab-lab-R1-R1"
    assert ctrl._state.scheduling["master"].topology_file == ""


def test_mgmt_anchors_deploy_before_vd_microtopologies(topo_factory):
    topo = topo_factory(
        nodes={
            "R1": VDNode(name="R1", kind="linux", image="alpine"),
            "R2": VDNode(name="R2", kind="linux", image="alpine"),
        },
        links=[],
        num_workers=0,
    )
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1", "R2"]),
        },
    )
    ctrl = _controller_for(topo)
    ctrl._clients = {"master": FakeClient("master")}

    ctrl._deploy_mgmt_anchors(topo, plan)
    ctrl._deploy_clab(topo, plan)

    assert ctrl._clients["master"].destroys == []
    assert ctrl._clients["master"].events[:2] == [
        ("upload", "/tmp/dnlab-lab-mgmt-master.clab.yml"),
        ("deploy", "/tmp/dnlab-lab-mgmt-master.clab.yml", True),
    ]
    assert ctrl._clients["master"].deploy_options == [
        ("/tmp/dnlab-lab-mgmt-master.clab.yml", True),
        ("/tmp/dnlab-lab-R1-master.clab.yml", False),
        ("/tmp/dnlab-lab-R2-master.clab.yml", False),
    ]
    assert ctrl._clients["master"].deploys == [
        "/tmp/dnlab-lab-mgmt-master.clab.yml",
        "/tmp/dnlab-lab-R1-master.clab.yml",
        "/tmp/dnlab-lab-R2-master.clab.yml",
    ]
    assert ctrl._state.mgmt_anchors["master"].container == (
        "clab-dnlab-lab-mgmt-master-mgmt-anchor"
    )
    assert ctrl._state.phases_completed[:2] == ["mgmt_anchor", "dnlab"]


def test_mgmt_network_phase_runs_before_containerlab_and_is_rollback_tracked(monkeypatch, topo_factory):
    topo = topo_factory(name="lab", num_workers=1)
    ctrl = _controller_for(topo)
    ctrl._clients = {
        "master": FakeClient("master"),
        "worker1": FakeClient("worker1"),
    }
    ensured = []
    destroyed = []

    monkeypatch.setattr(
        "dnlab_multinode.controllers.deploy.mgmt_network_svc.ensure_mgmt_network",
        lambda _topo, client: ensured.append(client.name),
    )
    monkeypatch.setattr(
        "dnlab_multinode.controllers.deploy.mgmt_network_svc.destroy_mgmt_network",
        lambda _topo, client: destroyed.append(client.name),
    )

    ctrl._deploy_mgmt_network(topo)

    assert sorted(ensured) == ["master", "worker1"]
    assert ctrl._state.phases_completed == ["mgmt_network"]

    ctrl._rollback(topo)
    assert sorted(destroyed) == ["master", "worker1"]


def test_mgmt_anchor_partial_failure_is_tracked_for_rollback(topo_factory):
    topo = topo_factory(
        nodes={
            "R1": VDNode(name="R1", kind="linux", image="alpine"),
            "R2": VDNode(name="R2", kind="linux", image="alpine"),
        },
        links=[],
        num_workers=1,
    )
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1"]),
            "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R2"]),
        },
    )
    ctrl = _controller_for(topo)
    failing_path = "/tmp/dnlab-lab-mgmt-worker1.clab.yml"
    ctrl._clients = {
        "master": FakeClient("master"),
        "worker1": FakeClient("worker1", fail_on={failing_path}),
    }

    try:
        ctrl._deploy_mgmt_anchors(topo, plan)
    except DeployError as exc:
        msg = str(exc)
        assert "worker1" in msg
        assert failing_path in msg
        assert "clab exploded" in msg
    else:
        raise AssertionError("mgmt anchor failure should raise DeployError")

    assert ctrl._state.phases_completed == ["mgmt_anchor"]
    assert set(ctrl._state.mgmt_anchors) == {"master"}

    ctrl._rollback(topo)

    assert ctrl._clients["master"].runs == [
        (
            "containerlab destroy -t /tmp/dnlab-lab-mgmt-master.clab.yml --cleanup --keep-mgmt-net",
            {"check": False},
        )
    ]


def test_pervd_deploy_error_includes_host_vd_and_topology_file(topo_factory):
    topo = topo_factory(
        nodes={
            "R1": VDNode(name="R1", kind="linux", image="alpine"),
            "R2": VDNode(name="R2", kind="linux", image="alpine"),
        },
        links=[],
        num_workers=0,
    )
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1", "R2"]),
        },
    )
    ctrl = _controller_for(topo)
    failing_path = "/tmp/dnlab-lab-R2-master.clab.yml"
    ctrl._clients = {"master": FakeClient("master", fail_on={failing_path})}

    try:
        ctrl._deploy_clab(topo, plan)
    except DeployError as exc:
        msg = str(exc)
        assert "master" in msg
        assert "R2" in msg
        assert failing_path in msg
        assert "clab exploded" in msg
    else:
        raise AssertionError("deploy failure should raise DeployError")

    assert set(ctrl._state.node_runtime) == {"R1", "R2"}
    assert ctrl._state.phases_completed == ["dnlab"]

    ctrl._rollback(topo)

    assert ctrl._clients["master"].runs == [
        (
            "containerlab destroy -t /tmp/dnlab-lab-R1-master.clab.yml --cleanup --keep-mgmt-net",
            {"check": False},
        ),
        (
            "containerlab destroy -t /tmp/dnlab-lab-R2-master.clab.yml --cleanup --keep-mgmt-net",
            {"check": False},
        ),
    ]


def test_pervd_parallel_deploy_failure_rolls_back_every_worker_target(topo_factory):
    topo = topo_factory(
        nodes={
            "R1": VDNode(name="R1", kind="linux", image="alpine"),
            "R2": VDNode(name="R2", kind="linux", image="alpine"),
        },
        links=[],
        num_workers=1,
    )
    plan = SchedulePlan(
        lab_name=topo.name,
        assignments={
            "master": HostAssignment("master", "10.0.0.10", vd_names=["R1"]),
            "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R2"]),
        },
    )
    ctrl = _controller_for(topo)
    failing_path = "/tmp/dnlab-lab-R2-worker1.clab.yml"
    ctrl._clients = {
        "master": FakeClient("master"),
        "worker1": FakeClient("worker1", fail_on={failing_path}),
    }

    try:
        ctrl._deploy_clab(topo, plan)
    except DeployError:
        pass
    else:
        raise AssertionError("deploy failure should raise DeployError")

    ctrl._rollback(topo)

    assert ctrl._clients["master"].runs == [
        (
            "containerlab destroy -t /tmp/dnlab-lab-R1-master.clab.yml --cleanup --keep-mgmt-net",
            {"check": False},
        ),
    ]
    assert ctrl._clients["worker1"].runs == [
        (
            "containerlab destroy -t /tmp/dnlab-lab-R2-worker1.clab.yml --cleanup --keep-mgmt-net",
            {"check": False},
        ),
    ]
