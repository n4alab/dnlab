from copy import deepcopy
from pathlib import Path
import os
import threading
import time

import pytest

from dnlab_runtime.backend import Backend, Docker, Linux
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Busy, Conflict, RuntimeErrorBase, capabilities, validate_request
from dnlab_runtime.transport import Client, Instance, Server
from fakes import FakeClock, FakeDocker, FakeLinux,planned_request


def request(**changes):
    value = {"schema_version": 1, "request_id": "start-1", "lab_id": "demo", "node_id": "R1", "expected_revision": 0, "action": "start", "spec": {"kind": "linux", "container_name": "clab-dnlab-demo-R1-R1", "image": "example/linux@sha256:" + "a" * 64, "command": ["sleep", "3600"], "endpoints": [{"host_interface": "dr-r1-eth1", "node_interface": "eth1", "mtu": 9000}], "stop_timeout": 1}}
    value.update(changes)
    return value


def stop(revision=1, **changes):
    value = request(action="stop", request_id="stop-1", expected_revision=revision)
    value.pop("spec")
    value.update(changes)
    return value


@pytest.fixture
def runtime(tmp_path):
    journal = Journal(tmp_path / "state")
    docker, linux, clock = FakeDocker(), FakeLinux(), FakeClock()
    engine = Engine(journal, Backend(docker, linux, clock=clock.clock, sleep=clock.sleep))
    yield engine, journal, docker, linux
    journal.close()


def run(engine, journal, payload):
    operation = journal.submit(planned_request(engine,payload))
    return engine.execute(operation["id"])


@pytest.mark.parametrize("field,value", [("schema_version", True), ("expected_revision", True), ("expected_revision", -1), ("lab_id", "../other"), ("action", "apply"), ("force", "false")])
def test_invalid_requests(field, value):
    with pytest.raises(RuntimeErrorBase):
        validate_request(request(**{field: value}))


@pytest.mark.parametrize("change", [{"kind": "cisco_n9kv"}, {"image": "alpine:latest"}, {"privileged": True}, {"stop_timeout": 0}, {"endpoints": [{"host_interface": "eth0;rm", "node_interface": "eth1"}]}, {"management": {"network": "mgmt", "ipv6": "10.0.0.2"}}, {"ports": [{"container_port": 80, "host_port": 8000, "host_ip": "127.0.0.1", "protocol": "tcp"}]}])
def test_unsupported_or_invalid_spec(change):
    payload = request()
    payload["spec"].update(change)
    with pytest.raises(RuntimeErrorBase):
        validate_request(payload)


def test_capabilities_never_claim_guest_or_live_qualification():
    result = capabilities()
    assert not result["safe_guest_shutdown"]
    assert not result["live_management_move"]
    assert not result["vrnetlab"]


def test_plan_has_no_side_effects(runtime):
    engine, journal, docker, linux = runtime
    assert engine.plan(request())["affected_nodes"] == ["R1"]
    assert journal.pending() == []
    assert docker.calls == linux.commands == []


def test_start_stop_restart_native_node(runtime):
    engine, journal, docker, linux = runtime
    assert run(engine, journal, request())["phase"] == "completed"
    assert engine.inspect("demo", "R1")["container_state"] == "running"
    assert engine.inspect("demo", "R1")["guest_readiness"] == "unknown"
    assert linux.link("eth1", 100)["mtu"] == 9000
    assert run(engine, journal, stop())["phase"] == "completed"
    assert docker.containers == linux.links == {}
    assert journal.node("demo", "R1")["revision"] == 2
    assert run(engine, journal, request(request_id="restart", expected_revision=2))["phase"] == "completed"
    assert journal.node("demo", "R1")["revision"] == 3


def test_idempotency_revision_and_same_content_retry(runtime):
    engine, journal, docker, _ = runtime
    original = request()
    first = run(engine, journal, original)
    assert journal.submit(original)["id"] == first["id"]
    assert engine.execute(first["id"])["phase"] == "completed"
    assert len([c for c in docker.calls if c[0] == "create"]) == 1
    changed = deepcopy(original)
    changed["spec"]["command"] = ["sleep", "2"]
    with pytest.raises(Conflict, match="different content"):
        journal.submit(changed)
    with pytest.raises(Conflict, match="stale revision"):
        journal.submit(request(request_id="second"))
    with pytest.raises(Conflict, match="implicitly reconfigured"):
        journal.submit({**changed, "request_id": "second", "expected_revision": 1})


def test_concurrent_duplicate_submit_creates_one_operation(runtime):
    _, journal, _, _ = runtime
    results = []
    threads = [threading.Thread(target=lambda: results.append(journal.submit(request())["id"])) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert len(results) == 8 and len(set(results)) == 1


def test_full_queue_still_returns_existing_request_without_new_reservations(runtime):
    _, journal, _, _ = runtime
    operation = journal.submit(request(), max_pending=1)
    assert journal.submit(request(), max_pending=1)["id"] == operation["id"]
    second = request(node_id="R2", request_id="second")
    second["spec"]["container_name"] = "different"
    second["spec"]["endpoints"] = []
    with pytest.raises(Busy):
        journal.submit(second, max_pending=1)
    assert len(journal.pending()) == 1


def test_resource_reservations_prevent_cross_node_and_cross_lab_collision(runtime):
    _, journal, _, _ = runtime
    journal.submit(request())
    with pytest.raises(Conflict, match="resource reserved"):
        journal.submit(request(node_id="R2", request_id="second"))
    with pytest.raises(Conflict, match="resource reserved"):
        journal.submit(request(lab_id="other"))


def test_cancel_queued_causes_no_docker_mutations(runtime):
    engine, journal, docker, linux = runtime
    op = journal.submit(request())
    assert journal.cancel(op["id"])["phase"] == "queued"
    assert engine.execute(op["id"])["phase"] == "cancelled"
    assert docker.calls == linux.commands == []
    assert journal.node("demo", "R1") is None


@pytest.mark.parametrize("event", ["create", "start"])
def test_cancel_after_side_effect_cleans_only_owned_resources(runtime, event):
    engine, journal, docker, linux = runtime
    op = journal.submit(request())
    docker.hook = lambda name: journal.cancel(op["id"]) if name == event else None
    assert engine.execute(op["id"])["phase"] == "cancelled"
    assert docker.containers == linux.links == {}
    assert journal.node("demo", "R1") is None


def test_cancel_after_endpoint_attachment(runtime):
    engine, journal, docker, linux = runtime
    op = journal.submit(request())
    linux.hook = lambda args: journal.cancel(op["id"]) if args[-1] == "up" else None
    assert engine.execute(op["id"])["phase"] == "cancelled"
    assert docker.containers == linux.links == {}


def test_cancel_repeated_start_preserves_committed_running_node(runtime):
    engine, journal, docker, linux = runtime
    run(engine, journal, request())
    op = journal.submit(request(request_id="again", expected_revision=1))
    journal.cancel(op["id"])
    assert engine.execute(op["id"])["phase"] == "cancelled"
    assert engine.inspect("demo", "R1")["container_state"] == "running"
    assert linux.link("dr-r1-eth1")
    assert not any(c[0] == "remove" for c in docker.calls)


@pytest.mark.parametrize("event", ["create", "start"])
def test_crash_between_side_effect_and_checkpoint_is_replayed(runtime, event):
    engine, journal, docker, linux = runtime
    op = journal.submit(request())
    def crash(name):
        if name == event:
            raise SystemExit("simulated process death")
    docker.hook = crash
    with pytest.raises(SystemExit):
        engine.execute(op["id"])
    path = Path(journal.db.execute("PRAGMA database_list").fetchone()[2]).parent
    journal.close()
    reopened = Journal(path)
    docker.hook = lambda name: None
    restored = Engine(reopened, engine.backend)
    result=restored.recover()[0]
    assert result['phase']==('recovery_required' if event=='create' else 'completed')
    if event=='create':
        assert not any(call[0] in ('signal','remove','start') for call in docker.calls)
        assert docker.containers and reopened.node('demo','R1') is None
    assert len([c for c in docker.calls if c[0] == "create"]) == 1
    reopened.close()


@pytest.mark.parametrize("stage", ["netns", "name"])
def test_crash_during_peer_transfer_recovers_existing_pair(runtime, stage):
    engine, journal, _, linux = runtime
    op = journal.submit(request())
    def crash(args):
        if args[:2] == ["link", "set"] and args[3] == stage:
            raise SystemExit("simulated process death")
    linux.hook = crash
    with pytest.raises(SystemExit):
        engine.execute(op["id"])
    linux.hook = lambda args: None
    assert engine.recover()[0]["phase"] == "completed"
    assert len([a for _, a in linux.commands if a[:2] == ["link", "add"]]) == 1


def test_crash_after_atomic_veth_creation_recovers_without_unlabelled_gap(runtime):
    engine, journal, docker, linux = runtime
    op = journal.submit(request())
    def crash(args):
        if args[:2] == ["link", "add"]:
            raise SystemExit("crash after atomic create")
    linux.hook = crash
    with pytest.raises(SystemExit):
        engine.execute(op["id"])
    linux.hook = lambda args: None
    assert "ifalias" not in linux.link("dr-r1-eth1")
    assert linux.link("dr-r1-eth1")["address"] == engine.backend.endpoint_macs(request(), request()["spec"], request()["spec"]["endpoints"][0])[0]
    assert engine.recover()[0]["phase"] == "completed"
    assert len([args for _, args in linux.commands if args[:2] == ["link", "add"]]) == 1
    assert not any(args[:2] == ["link", "delete"] for _, args in linux.commands)


def test_crash_after_removal_before_stop_commit_is_recovered(runtime):
    engine, journal, docker, linux = runtime
    run(engine, journal, request())
    op = journal.submit(stop())
    def crash(event):
        if event == "remove":
            raise SystemExit("crash after remove")
    docker.hook = crash
    with pytest.raises(SystemExit):
        engine.execute(op["id"])
    docker.hook = lambda event: None
    assert engine.recover()[0]["phase"] == "completed"
    assert journal.node("demo", "R1")["revision"] == 2
    assert not docker.containers and not linux.links


def test_namespace_fd_is_pinned_inherited_and_closed_without_mutating_host(monkeypatch):
    linux = Linux()
    calls = []
    def record(argv, *, pass_fds=()):
        calls.append((argv, pass_fds))
        return "[]"
    monkeypatch.setattr(linux, "run", record)
    with linux.namespace(os.getpid()) as namespace:
        descriptor = namespace.fd
        os.fstat(descriptor)
        linux.link("eth1", namespace)
        linux.move("example", namespace)
        assert calls[0][0][1] == f"--net=/proc/self/fd/{descriptor}"
        assert calls[0][1] == calls[1][1] == (descriptor,)
    with pytest.raises(OSError):
        os.fstat(descriptor)


def test_real_iproute_shape_resolves_same_namespace_named_peer(monkeypatch):
    import json
    linux = Linux()
    raw = [{"ifname": "host", "ifindex": 24, "link": "peer", "address": "02:00:00:00:00:01", "ifalias": "owner"}, {"ifname": "peer", "ifindex": 23, "link": "host", "address": "02:00:00:00:00:02"}]
    monkeypatch.setattr(linux, "run", lambda *args, **kwargs: json.dumps(raw))
    assert linux.link("host")["link_index"] == 23
    assert linux.link("peer")["link_index"] == 24
    assert linux.link("host")["ifalias"] == "owner"


def test_container_pid_change_blocks_namespace_mutations(runtime):
    engine, journal, docker, linux = runtime
    op = journal.submit(request())
    original = linux.namespace
    from contextlib import contextmanager
    @contextmanager
    def changed(pid):
        docker.find(next(iter(docker.containers.values()))["Id"])["State"]["Pid"] += 1
        with original(pid) as namespace:
            yield namespace
    linux.namespace = changed
    assert engine.execute(op["id"])["phase"] == "failed"
    assert linux.commands == []


def test_engine_adapter_never_requests_implicit_forced_removal():
    docker = Docker()
    calls = []
    docker.request = lambda *args, **kwargs: calls.append((args, kwargs)) or {}
    docker.remove("a-container")
    assert calls[0][0][0] == "DELETE"
    assert calls[0][0][1].endswith("?force=false")
    assert "v=true" not in calls[0][0][1]


def test_cancel_timeout_retains_inventory_and_requires_explicit_force(runtime):
    engine, journal, docker, _ = runtime
    docker.resist_term = True
    op = journal.submit(request())
    docker.hook = lambda event: journal.cancel(op["id"]) if event == "start" else None
    result = engine.execute(op["id"])
    assert result["phase"] == "recovery_required"
    assert ("signal", "SIGKILL") not in docker.calls
    assert docker.containers
    with pytest.raises(Conflict, match="requires recovery"):
        journal.submit(request(request_id="second"))
    docker.hook = lambda event: None
    assert engine.reconcile(op["id"], force=True)["phase"] == "cancelled"
    assert not docker.containers


def test_safe_stop_timeout_does_not_remove_or_kill_then_explicit_force_recovers(runtime):
    engine, journal, docker, linux = runtime
    run(engine, journal, request())
    committed = deepcopy(journal.node("demo", "R1"))
    endpoints = deepcopy(linux.links)
    containers = deepcopy(docker.containers)
    reservations = list(journal.db.execute("SELECT key,lab,node FROM resources ORDER BY key"))
    docker.resist_term = True
    op = run(engine, journal, stop())
    assert op["phase"] == "recovery_required"
    assert engine.inspect("demo", "R1")["container_state"] == "running"
    assert ("signal", "SIGKILL") not in docker.calls
    assert not any(call[0] == "remove" for call in docker.calls)
    assert journal.node("demo", "R1") == committed
    assert linux.links == endpoints and docker.containers == containers
    assert list(journal.db.execute("SELECT key,lab,node FROM resources ORDER BY key")) == reservations
    assert engine.reconcile(op["id"], force=True)["phase"] == "completed"
    assert journal.node("demo", "R1")["state"] == "stopped"


def test_foreign_container_is_never_mutated(runtime):
    engine, journal, docker, _ = runtime
    name = request()["spec"]["container_name"]
    docker.containers[name] = {"Id": "foreign", "Config": {"Labels": {}}, "State": {"Running": True}}
    assert run(engine, journal, request())["phase"] == "recovery_required"
    assert docker.calls == []
    assert docker.containers[name]["Id"] == "foreign"


def test_foreign_interface_blocks_cleanup_and_remains_present(runtime):
    engine, journal, docker, linux = runtime
    linux.links[(None, "dr-r1-eth1")] = {"ifname": "dr-r1-eth1", "ifalias": "foreign", "ifindex": 99, "link_index": 100}
    result = run(engine, journal, request())
    assert result["phase"] == "recovery_required"
    assert linux.link("dr-r1-eth1")["ifalias"] == "foreign"
    assert not any(args[:2] == ["link", "delete"] for _, args in linux.commands)


def test_management_driver_ipam_and_ports_are_preserved(runtime):
    engine, journal, docker, _ = runtime
    value = request()
    value["spec"]["management"] = {"network": "mgmt", "ipv4": "192.0.2.2", "ipv6": "2001:db8::2"}
    value["spec"]["ports"] = [{"container_port": 80, "host_port": 8080, "host_ip": "127.0.0.1", "protocol": "tcp"}]
    assert run(engine, journal, value)["phase"] == "completed"
    container = docker.containers[value["spec"]["container_name"]]
    assert container["NetworkSettings"]["Networks"]["mgmt"]["IPAddress"] == "192.0.2.2"
    assert container["Config"]["HostConfig"]["PortBindings"]["80/tcp"][0]["HostPort"] == "8080"


def test_network_of_another_lab_cannot_be_used(runtime):
    engine, journal, docker, _ = runtime
    docker.networks["mgmt"]["Labels"]["io.dnlab.lab"] = "another"
    value = request()
    value["spec"]["management"] = {"network": "mgmt"}
    with pytest.raises(Conflict):engine.plan(value)
    assert docker.calls == []


def test_verify_failure_compensates_owned_container_and_endpoints(runtime):
    engine, journal, docker, linux = runtime
    original = engine.backend.verify
    def fail(*args):
        raise RuntimeErrorBase("verification failed")
    engine.backend.verify = fail
    assert run(engine, journal, request())["phase"] == "failed"
    assert not docker.containers and not linux.links
    engine.backend.verify = original
    assert run(engine, journal, request(request_id="retry"))["phase"] == "completed"


def test_status_never_exposes_spec_env_or_unexpected_exception_text(runtime):
    engine, journal, _, _ = runtime
    value = request()
    value["spec"]["env"] = {"TOKEN": "private-token"}
    op = journal.submit(value)
    engine.backend.create = lambda *args: (_ for _ in ()).throw(ValueError("private-token"))
    result = engine.execute(op["id"])
    assert "private-token" not in str(result)
    assert "payload" not in result


def test_stop_cancel_racing_after_exit_commits_observed_stopped_state(runtime):
    engine, journal, docker, _ = runtime
    run(engine, journal, request())
    op = journal.submit(stop())
    docker.hook = lambda event: journal.cancel(op["id"]) if event == "signal" else None
    result = engine.execute(op["id"])
    assert result["phase"] == "completed" and result["cancel_requested"]
    assert journal.node("demo", "R1")["state"] == "stopped"


def test_single_daemon_lock_and_foreign_socket_file_protection(tmp_path):
    state, socket = tmp_path / "state", tmp_path / "run/runtime.sock"
    with Instance(state, socket):
        with pytest.raises(BlockingIOError):
            with Instance(state, socket):
                pass
    socket.write_text("do not overwrite")
    with pytest.raises(RuntimeErrorBase, match="non-socket"):
        with Instance(state, socket):
            pass
    assert socket.read_text() == "do not overwrite"


def test_unix_protocol_progress_cancel_and_restart(runtime, tmp_path):
    engine, journal, docker, _ = runtime
    socket = tmp_path / "socket"
    server = Server(str(socket), engine)
    thread = threading.Thread(target=server.serve_forever)
    thread.start()
    client = Client(str(socket))
    try:
        assert client.request("GET", "/v1/capabilities")["experimental"]
        assert client.request("POST", "/v1/plan", request())["mutations_performed"] is False
        op = client.request("POST", "/v1/operations", request())
        deadline = time.monotonic() + 3
        while time.monotonic() < deadline:
            result = client.request("GET", "/v1/operations/" + op["id"])
            if result["phase"] == "completed":
                break
            time.sleep(0.01)
        assert result["phase"] == "completed"
        assert client.request("GET", "/v1/nodes/demo/R1")["container_state"] == "running"
        assert client.request("POST", "/v1/operations", request())["id"] == op["id"]
        assert socket.stat().st_mode & 0o777 == 0o600
    finally:
        server.shutdown()
        server.server_close()
        thread.join()


def test_endpoint_replacement_retains_stop_state_until_guarded_recovery(runtime):
    engine,journal,docker,linux=runtime
    started=request();spec=started['spec'];host=spec['endpoints'][0]['host_interface']
    assert run(engine,journal,started)['phase']=='completed'
    original=linux.delete_link
    foreign={'ifname':host,'ifindex':999,'link_index':1000,'ifalias':'foreign-owner'}
    def replace(expected):
        linux.links[(None,host)]=deepcopy(foreign)
        original(expected)
    linux.delete_link=replace
    operation=journal.submit(stop())
    assert engine.execute(operation['id'])['phase']=='recovery_required'
    assert journal.node('demo','R1')['revision']==1 and journal.node('demo','R1')['spec']==spec
    assert docker.inspect(spec['container_name']) is not None and linux.link(host)==foreign
    linux.delete_link=original
    assert engine.reconcile(operation['id'])['phase']=='recovery_required'
    assert linux.link(host)==foreign and journal.node('demo','R1')['revision']==1
    # Simulate external removal of its own foreign object; recovery may now finish.
    linux.links.pop((None,host))
    assert engine.reconcile(operation['id'])['phase']=='completed'
    assert journal.node('demo','R1')['state']=='stopped' and journal.node('demo','R1')['revision']==2
