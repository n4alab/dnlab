import threading

from dnlab_multinode.controllers import node as node_module
from dnlab_multinode.controllers.node import NodeLifecycleController
from dnlab_multinode.models.schedule import HostAssignment, SchedulePlan
from dnlab_multinode.models.state import (
    DeploymentState, DnsState, JumphostState, NodeRuntimeState,
    RuntimeRelayState,
)
from tests.conftest import make_topology


def test_restart_reuses_per_vd_stop_then_start():
    controller = object.__new__(NodeLifecycleController)
    calls = []
    expected = object()
    controller.stop = lambda node: calls.append(("stop", node))

    def start(node):
        calls.append(("start", node))
        return expected

    controller.start = start

    assert controller.restart("r1") is expected
    assert calls == [("stop", "r1"), ("start", "r1")]


def test_start_routes_missing_runtime_node_to_hot_add():
    controller = object.__new__(NodeLifecycleController)
    controller.state = DeploymentState(
        lab_name="demo", topology_file="/tmp/demo.yml", runtime_mode="per-vd",
    )
    expected = object()
    controller.add = lambda node: expected if node == "r2" else None

    assert controller.start("r2") is expected


def test_shared_service_reconcile_reloads_dns_and_refreshes_jumphost(monkeypatch):
    controller = object.__new__(NodeLifecycleController)
    controller.topo = make_topology(name="demo", num_workers=1)
    controller.state = DeploymentState(
        lab_name="demo", topology_file="/tmp/demo.yml", runtime_mode="per-vd",
        dns=DnsState("master", "dnlab-demo-dns", "10.100.0.2", entries=2),
        jumphost=JumphostState(
            "master", "dnlab-demo-jumphost", "172.20.0.1",
            "10.100.0.3", "jh-net",
        ),
    )
    r1 = "clab-dnlab-demo-R1-R1"
    r2 = "clab-dnlab-demo-R2-R2"
    controller.state.node_runtime = {
        "R1": NodeRuntimeState(
            node="R1", host="master", container=r1, mgmt_ipv4="172.20.0.2",
        ),
        "R2": NodeRuntimeState(
            node="R2", host="worker1", container=r2, mgmt_ipv4="172.20.0.3",
        ),
    }
    controller.state.runtime_relays = {
        "master": RuntimeRelayState(
            "master", "dnlab-demo-runtime-relay", "10.0.0.10", 23001,
            "secret", [r1],
        ),
    }
    controller._underlay_ips = lambda: {
        "master": "10.0.0.10", "worker1": "10.0.0.11",
    }
    plan = SchedulePlan("demo", assignments={
        "master": HostAssignment("master", "10.0.0.10", vd_names=["R1"]),
        "worker1": HostAssignment("worker1", "10.0.0.11", vd_names=["R2"]),
    })
    relay_result = {
        "master": {
            "container": "dnlab-demo-runtime-relay", "bind_ip": "10.0.0.10",
            "port": 23001, "api_key": "secret", "allowed": [r1],
        },
        "worker1": {
            "container": "dnlab-demo-runtime-relay", "bind_ip": "10.0.0.11",
            "port": 23001, "api_key": "secret", "allowed": [r2],
        },
    }
    calls = {}
    monkeypatch.setattr(
        node_module.runtime_relay_svc, "reconcile_runtime_relays",
        lambda *args: relay_result,
    )
    monkeypatch.setattr(
        node_module.dns_svc, "deploy_dns",
        lambda *args, **kwargs: (_ for _ in ()).throw(
            AssertionError("hot-add must not redeploy DNS")
        ),
    )

    def refresh_dns(*args, **kwargs):
        calls["dns_entries"] = kwargs["extra_entries"]
        return 4, kwargs["extra_entries"]

    def refresh_inventory(lab, client, vd_map, relay_map):
        calls["inventory"] = (lab, vd_map, relay_map)

    monkeypatch.setattr(node_module.dns_svc, "refresh_dns", refresh_dns)
    monkeypatch.setattr(
        node_module.jumphost_svc, "refresh_jumphost_inventory", refresh_inventory,
    )

    controller._reconcile_shared_services(
        plan, {"master": object(), "worker1": object()},
    )

    assert controller.state.dns.entries == 4
    assert {(entry.name, entry.ip) for entry in calls["dns_entries"]} == {
        ("R1", "172.20.0.2"), (r1, "172.20.0.2"),
        ("R2", "172.20.0.3"), (r2, "172.20.0.3"),
    }
    lab, vd_map, relay_map = calls["inventory"]
    assert lab == "demo"
    assert vd_map == {"R1": r1, "R2": r2}
    assert relay_map[r2]["host"] == "10.0.0.11"


class _LifecycleClient:
    def __init__(self, on_deploy=None):
        self.on_deploy = on_deploy
        self.destroyed = []

    def deploy_clab(self, path, *, cancel_event=None, reconfigure=False):
        if self.on_deploy:
            self.on_deploy(cancel_event)

    def destroy_clab(self, path):
        self.destroyed.append(path)

    def close(self):
        pass

    def cancel_active_commands(self):
        pass


def _starting_controller(tmp_path, monkeypatch, *, on_deploy=None):
    controller = object.__new__(NodeLifecycleController)
    controller.topo = make_topology(name="demo", num_workers=0)
    controller.state_dir = tmp_path
    controller.state = DeploymentState(
        lab_name="demo", topology_file="/tmp/demo.yml", runtime_mode="per-vd",
    )
    controller.state.node_runtime = {
        "R1": NodeRuntimeState(
            node="R1", state="stopped", host="master",
            container="clab-dnlab-demo-R1-R1",
            topology_file="/tmp/demo-R1.clab.yml",
        ),
    }
    controller.cancel_event = threading.Event()
    phases = []
    controller.phase_callback = phases.append
    client = _LifecycleClient(on_deploy)
    monkeypatch.setattr(node_module, "create_clients", lambda _hosts: {"master": client})
    controller._connect = lambda _clients: None
    controller._wait_container_running = lambda *_args, **_kwargs: None
    controller._set_default_route = lambda *_args: None
    controller._refresh_runtime_links = lambda *_args: None
    controller._sync_vxlan_state = lambda: None
    controller._underlay_ips = lambda: {"master": "10.0.0.10"}
    monkeypatch.setattr(
        node_module.runtime_links_svc, "reconcile_node_links", lambda *_args: None,
    )
    monkeypatch.setattr(
        node_module.runtime_links_svc, "delete_node_links", lambda *_args: None,
    )
    mgmt_network_calls = []
    monkeypatch.setattr(
        node_module.mgmt_network_svc,
        "ensure_mgmt_network",
        lambda topo, candidate: mgmt_network_calls.append((topo.name, candidate)),
    )
    controller._mgmt_network_calls = mgmt_network_calls
    return controller, client, phases


def test_start_persists_starting_reconciling_running(tmp_path, monkeypatch):
    controller, client, phases = _starting_controller(tmp_path, monkeypatch)

    state = controller.start("R1")

    assert phases == ["starting", "reconciling", "running"]
    assert state.node_runtime["R1"].state == "running"
    assert controller._mgmt_network_calls == [("demo", client)]


def test_cancel_during_deploy_cleans_up_and_never_marks_running(tmp_path, monkeypatch):
    def cancel(event):
        event.set()

    controller, client, phases = _starting_controller(
        tmp_path, monkeypatch, on_deploy=cancel,
    )
    controller._reconcile_shared_services = lambda *_args: None

    state = controller.start("R1")

    assert state.node_runtime["R1"].state == "stopped"
    assert phases == ["starting", "cancelling", "stopped"]
    assert "running" not in phases
    assert client.destroyed == ["/tmp/demo-R1.clab.yml"]


def test_force_stop_recovers_persisted_starting_state(tmp_path, monkeypatch):
    controller, client, phases = _starting_controller(tmp_path, monkeypatch)
    controller.state.node_runtime["R1"].state = "starting"

    state = controller.stop("R1", force=True)

    assert phases == ["cancelling", "stopped"]
    assert state.node_runtime["R1"].state == "stopped"
    assert client.destroyed == ["/tmp/demo-R1.clab.yml"]


def test_request_cancel_interrupts_active_remote_commands():
    controller = object.__new__(NodeLifecycleController)
    controller.cancel_event = threading.Event()
    interrupted = []

    class Client:
        def cancel_active_commands(self):
            interrupted.append(True)

    controller._active_clients = {"worker1": Client()}

    controller.request_cancel()
    controller.request_cancel()

    assert controller.cancel_event.is_set()
    assert interrupted == [True]
