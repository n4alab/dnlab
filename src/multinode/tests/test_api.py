import dataclasses
import asyncio

import pytest

pytest.importorskip("fastapi")

from dnlab_multinode import api
from dnlab_multinode.models.state import RuntimeLinkState


@dataclasses.dataclass
class _FakePlan:
    lab: str = "demo"


class _FakeState:
    def to_dict(self):
        return {"lab_name": "demo", "dnlab_deployed": True}


class _FakeJumphost:
    password = "secret"


class _FakeRuntime:
    node = "r1"
    host = "worker1"
    container = "clab-demo-r1"


class _FakeRelay:
    bind_ip = "127.0.0.1"
    port = 9001
    api_key = "key"
    allowed = ["clab-demo-r1"]


class _FakeDeploymentState:
    jumphost = _FakeJumphost()
    node_runtime = {"r1": _FakeRuntime()}
    runtime_relays = {"worker1": _FakeRelay()}


class _FakePlanController:
    def __init__(self, topology_file, no_cache=False, *, hosts_file=None):
        self.topology_file = topology_file
        self.no_cache = no_cache
        self.hosts_file = hosts_file

    def run(self):
        return _FakePlan()


class _FakeDeployController:
    def __init__(self, topology_file, *, hosts_file=None, progress=None):
        self.progress = progress

    def run(self):
        if self.progress:
            self.progress(api.ProgressEvent("deploy", "ok", detail="done"))
        return _FakeState()


class _FakeStatusReport:
    def to_dict(self):
        return {"lab_name": "demo", "deployed": False}


class _FakeStatusController:
    def __init__(self, topology_file, *, hosts_file=None, progress=None):
        self.progress = progress

    def run(self):
        if self.progress:
            self.progress(api.ProgressEvent("status", "ok", detail="not deployed"))
        return _FakeStatusReport()


class _FakeNodeLifecycleController:
    def __init__(
        self, topology_file, *, hosts_file=None, cancel_event=None, phase_callback=None,
    ):
        self.topo = dataclasses.make_dataclass("Topo", [("nodes", dict)])(
            {"r1": object(), "r2": object()}
        )

    def list_nodes(self):
        return {
            "r1": api.dataclasses.make_dataclass(
                "Runtime", [("node", str), ("state", str)]
            )("r1", "running")
        }

    def stop(self, node, *, force=False):
        return _FakeState()

    def start(self, node):
        return _FakeState()

    def restart(self, node):
        return _FakeState()

    def reconcile(self, node):
        return _FakeState()

    def reconcile_link(self, node_a, iface_a, node_b="", iface_b="", real_net=""):
        return RuntimeLinkState(
            id="l0", link_type="same_host",
            endpoint_a={"node": node_a, "iface": iface_a},
            endpoint_b={"node": node_b, "iface": iface_b},
            state="up",
        )


def test_plan_endpoint_uses_controller(monkeypatch):
    monkeypatch.setattr(api, "PlanController", _FakePlanController)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(api.lab_plan(api.PlanRequest(topology_file="/tmp/demo.yml")))

    assert res == {"lab": "demo"}


def test_deploy_endpoint_returns_state_and_records_event(monkeypatch):
    monkeypatch.setattr(api, "DeployController", _FakeDeployController)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)
    api._events.clear()

    res = asyncio.run(
        api.lab_deploy(api.LabRequest(topology_file="/tmp/demo.yml", lab_id="lab-1"))
    )

    assert res["lab_name"] == "demo"
    assert list(api._events["lab-1"])[0]["phase"] == "deploy"


def test_status_endpoint_does_not_record_progress_events(monkeypatch):
    monkeypatch.setattr(api, "StatusController", _FakeStatusController)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)
    api._events.clear()

    res = asyncio.run(
        api.lab_status(api.LabRequest(topology_file="/tmp/demo.yml", lab_id="lab-1"))
    )

    assert res == {"lab_name": "demo", "deployed": False}
    assert "lab-1" not in api._events


def test_node_list_endpoint_serializes_runtime(monkeypatch):
    monkeypatch.setattr(api, "NodeLifecycleController", _FakeNodeLifecycleController)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(api.lab_nodes(api.LabRequest(topology_file="/tmp/demo.yml")))

    assert res["nodes"]["r1"] == {"node": "r1", "state": "running"}


def test_node_restart_endpoint_uses_per_vd_controller(monkeypatch):
    monkeypatch.setattr(api, "NodeLifecycleController", _FakeNodeLifecycleController)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(
        api.lab_node_restart(api.NodeRequest(topology_file="/tmp/demo.yml", node="r1"))
    )

    assert res == {"lab_name": "demo", "dnlab_deployed": True}


def test_node_start_endpoint_reports_completed_operation(monkeypatch):
    monkeypatch.setattr(api, "NodeLifecycleController", _FakeNodeLifecycleController)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    result = asyncio.run(
        api.lab_node_start(api.NodeRequest(topology_file="/tmp/demo.yml", node="r1"))
    )

    assert result["_operation_outcome"] == "completed"


def test_duplicate_start_is_rejected_while_operation_is_registered():
    async def exercise():
        req = api.NodeRequest(topology_file="/tmp/demo.yml", node="r1")
        key = api._node_operation_key(req)
        operation = api._ActiveNodeStart(api.threading.Event(), asyncio.Event())
        api._active_node_starts[key] = operation
        try:
            with pytest.raises(api.HTTPException) as exc:
                await api.lab_node_start(req)
            assert exc.value.status_code == 409
        finally:
            api._active_node_starts.pop(key, None)

    asyncio.run(exercise())


def test_stop_cancels_queued_start_without_waiting_for_global_lock():
    async def exercise():
        req = api.NodeRequest(topology_file="/tmp/demo.yml", node="r1")
        key = api._node_operation_key(req)
        operation = api._ActiveNodeStart(api.threading.Event(), asyncio.Event())
        api._active_node_starts[key] = operation
        try:
            result = await api.lab_node_stop(req)
            assert result["cancelled"] is True
            assert operation.cancel.is_set()
            assert operation.phase == "stopped"
        finally:
            api._active_node_starts.pop(key, None)

    asyncio.run(exercise())


def test_stop_interrupts_running_start_controller():
    class Controller:
        def __init__(self):
            self.cancelled = False

        def request_cancel(self):
            self.cancelled = True

    async def exercise():
        req = api.NodeRequest(topology_file="/tmp/demo.yml", node="r1")
        key = api._node_operation_key(req)
        operation = api._ActiveNodeStart(api.threading.Event(), asyncio.Event())
        operation.controller = Controller()
        operation.phase = "reconciling"
        api._active_node_starts[key] = operation
        try:
            result = await api.lab_node_stop(req)
            assert result["cancelled"] is True
            assert operation.controller.cancelled is True
            assert operation.phase == "cancelling"
        finally:
            api._active_node_starts.pop(key, None)

    asyncio.run(exercise())


def test_link_reconcile_endpoint_returns_exact_runtime_link(monkeypatch):
    monkeypatch.setattr(api, "NodeLifecycleController", _FakeNodeLifecycleController)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(api.lab_link_reconcile(api.LinkRequest(
        topology_file="/tmp/demo.yml",
        source="r1", source_iface="eth1",
        target="r2", target_iface="eth2",
    )))

    assert res["state"] == "up"
    assert res["endpoint_a"] == {"node": "r1", "iface": "eth1"}


def test_runtime_relay_endpoint_reads_state(monkeypatch):
    monkeypatch.setattr(api, "_lab_state", lambda req: _FakeDeploymentState())
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(
        api.lab_runtime_relay(api.NodeRequest(topology_file="/tmp/demo.yml", lab_name="demo", node="r1"))
    )

    assert res == {
        "container": "clab-demo-r1",
        "host": "127.0.0.1",
        "port": 9001,
        "api_key": "key",
        "relay_host": "worker1",
    }


def test_runtime_relay_endpoint_resolves_new_node_alias(monkeypatch):
    @dataclasses.dataclass
    class Runtime:
        node: str
        host: str
        container: str

    class State:
        node_runtime = {
            "NEW-SERVER": Runtime(
                node="NEW-SERVER",
                host="worker1",
                container="clab-dnlab-demo-NEW-SERVER-NEW-SERVER",
            )
        }
        runtime_relays = {"worker1": _FakeRelay()}

    relay = _FakeRelay()
    relay.allowed = ["clab-dnlab-demo-NEW-SERVER-NEW-SERVER"]
    State.runtime_relays = {"worker1": relay}
    monkeypatch.setattr(api, "_lab_state", lambda req: State())
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(
        api.lab_runtime_relay(api.NodeRequest(
            topology_file="/tmp/demo.yml", lab_name="demo", node="SERVER",
        ))
    )

    assert res["container"] == "clab-dnlab-demo-NEW-SERVER-NEW-SERVER"
    assert res["relay_host"] == "worker1"


def test_runtime_relay_endpoint_rejects_ambiguous_alias(monkeypatch):
    @dataclasses.dataclass
    class Runtime:
        node: str
        host: str
        container: str

    class State:
        node_runtime = {
            "NEW-SERVER": Runtime("NEW-SERVER", "worker1", "clab-demo-NEW-SERVER"),
            "server": Runtime("server", "worker1", "clab-demo-server"),
        }
        runtime_relays = {"worker1": _FakeRelay()}

    monkeypatch.setattr(api, "_lab_state", lambda req: State())

    with pytest.raises(RuntimeError, match="matches multiple runtime nodes"):
        api._runtime_relay(api.NodeRequest(
            topology_file="/tmp/demo.yml", lab_name="demo", node="SERVER",
        ))


def test_jumphost_password_endpoint_reads_state(monkeypatch):
    monkeypatch.setattr(api, "_lab_state", lambda req: _FakeDeploymentState())
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(
        api.lab_jumphost_password(api.LabRequest(topology_file="/tmp/demo.yml", lab_name="demo"))
    )

    assert res == {"password": "secret"}


def test_hosts_validate_endpoint_uses_validator(monkeypatch):
    seen = {}

    def _validate(content):
        seen["content"] = content

    monkeypatch.setattr(api, "_validate_hosts_content", _validate)
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(api.hosts_validate(api.HostsValidateRequest(content="infrastructure: {}")))

    assert res == {"ok": True}
    assert seen["content"] == "infrastructure: {}"


def test_realnet_rr_status_endpoint_uses_hosts_status(monkeypatch):
    monkeypatch.setattr(
        api,
        "_realnet_rr_status_from_hosts",
        lambda hosts_file: {"running": True, "container": "dnlab-realnet-rr", "image": "dnlab-realnet-rr:latest"},
    )
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(api.realnet_rr_status(api.HostsRequest(hosts_file="/etc/dnlab/hosts.yml")))

    assert res["running"] is True
    assert res["container"] == "dnlab-realnet-rr"


def test_lab_cleanup_status_reads_state(monkeypatch):
    monkeypatch.setattr(api, "read_lab_cleanup_state_file", lambda path: {"updated_at": "now"})
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(api.lab_cleanup_status())

    assert res == {"available": True, "state": {"updated_at": "now"}}


def test_lab_cleanup_reconcile_uses_lock_and_returns_report(monkeypatch):
    class _Report:
        def to_dict(self):
            return {"labs": {}, "dry_run": True}

    monkeypatch.setattr(api, "load_hosts_config", lambda hosts_file=None: object())
    monkeypatch.setattr(api, "reconcile_lab_cleanup_once", lambda hosts, dry_run=None: _Report())
    monkeypatch.setattr(api.asyncio, "to_thread", _to_thread_sync)

    res = asyncio.run(api.lab_cleanup_reconcile(dry_run=True))

    assert res == {"labs": {}, "dry_run": True}


async def _to_thread_sync(fn, /, *args, **kwargs):
    return fn(*args, **kwargs)
