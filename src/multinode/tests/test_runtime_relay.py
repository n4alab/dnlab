"""Tests for the per-host runtime relay service."""

import os
import queue
import threading
import time
from unittest.mock import MagicMock

import pytest

from dnlab_multinode.models.schedule import HostAssignment, SchedulePlan
from dnlab_multinode.models.state import RuntimeRelayState
from dnlab_multinode.services import runtime_relay as relay_svc
from dnlab_multinode.utils.ids import runtime_relay_port
from dnlab_multinode.utils.naming import (
    micro_vd_container_name,
    runtime_relay_container_name,
)
from tests.conftest import make_topology
from tests.runtime_relay_import import load_runtime_relay_module


relay_daemon = load_runtime_relay_module()


class FakeRelaySocket:
    def __init__(self):
        self.read_fd, self.write_fd = os.pipe()
        self.sent: list[bytes] = []

    def fileno(self):
        return self.read_fd

    def sendall(self, data: bytes):
        self.sent.append(data)

    def recv(self, _size: int, _flags: int = 0):
        return b""

    def disconnect(self):
        os.write(self.write_fd, b"x")

    def close(self):
        for fd in (self.read_fd, self.write_fd):
            try:
                os.close(fd)
            except OSError:
                pass


class FakeConsoleSocket:
    def __init__(self):
        self.sent: list[bytes] = []
        self.incoming: queue.Queue[bytes | None] = queue.Queue()
        self.closed = False

    def sendall(self, data: bytes):
        if self.closed:
            raise OSError("closed")
        self.sent.append(data)

    def recv(self, _size: int):
        data = self.incoming.get()
        return b"" if data is None else data

    def client_send(self, data: bytes):
        self.incoming.put(data)

    def client_close(self):
        self.incoming.put(None)

    def shutdown(self, _how):
        self.closed = True
        self.incoming.put(None)


def _mock_host_client(image_exists: bool = True, runs_ok: bool = True) -> MagicMock:
    client = MagicMock()

    def run_no_check(cmd, *_, **__):
        if "docker image inspect" in cmd:
            return (0 if image_exists else 1), "", ""
        if "docker inspect" in cmd and "State.Running" in cmd:
            return (0 if runs_ok else 1), ("true" if runs_ok else "false"), ""
        if "docker logs" in cmd:
            return 0, "(fake logs)", ""
        return 0, "", ""

    client.run_no_check.side_effect = run_no_check
    client.run.return_value = ""
    return client


def _plan_with_assignments(lab_name: str, mapping: dict[str, list[str]]) -> SchedulePlan:
    assignments = {
        host: HostAssignment(host_name=host, host_ip="", vd_names=vds)
        for host, vds in mapping.items()
    }
    return SchedulePlan(lab_name=lab_name, assignments=assignments)


def test_deploy_runtime_relays_one_per_host_with_vds():
    topo = make_topology(name="demo", num_workers=2)
    plan = _plan_with_assignments("demo", {
        "master": ["R1"],
        "worker1": ["R2"],
        "worker2": [],
    })
    clients = {
        "master": _mock_host_client(),
        "worker1": _mock_host_client(),
        "worker2": _mock_host_client(),
    }

    results = relay_svc.deploy_runtime_relays(
        topo,
        plan,
        clients,
        {"master": "10.0.0.10", "worker1": "10.0.0.11", "worker2": "10.0.0.12"},
        api_key="secret",
    )

    assert set(results) == {"master", "worker1"}
    assert results["master"]["container"] == runtime_relay_container_name("demo")
    assert results["master"]["bind_ip"] == "10.0.0.10"
    assert results["master"]["port"] == runtime_relay_port("demo")
    assert results["master"]["api_key"] == "secret"
    assert results["master"]["allowed"] == [micro_vd_container_name("demo", "R1")]


def test_deploy_runtime_relay_command_is_lab_scoped_and_host_local():
    topo = make_topology(name="demo")
    plan = _plan_with_assignments("demo", {"master": ["R1", "R2"]})
    client = _mock_host_client()

    relay_svc.deploy_runtime_relays(
        topo,
        plan,
        {"master": client},
        {"master": "10.0.0.10"},
        api_key="secret with space",
    )

    run_cmds = [c.args[0] for c in client.run.call_args_list]
    run_cmd = next(cmd for cmd in run_cmds if "docker run -d" in cmd)
    expected_list = (
        f"{micro_vd_container_name('demo', 'R1')} "
        f"{micro_vd_container_name('demo', 'R2')}"
    )

    assert "--network host" in run_cmd
    assert "/var/run/docker.sock:/var/run/docker.sock" in run_cmd
    assert "-e RELAY_BIND=10.0.0.10" in run_cmd
    assert f"-e RELAY_PORT={runtime_relay_port('demo')}" in run_cmd
    assert "-e RELAY_API_KEY='secret with space'" in run_cmd
    assert f"-e RELAY_ALLOWED_CONTAINERS='{expected_list}'" in run_cmd
    assert "-e RELAY_ALLOWED_PREFIX=clab-dnlab-demo-" in run_cmd


def test_reconcile_runtime_relay_with_prefix_does_not_restart():
    topo = make_topology(name="demo")
    plan = _plan_with_assignments("demo", {"master": ["R1", "R2"]})
    client = _mock_host_client()
    client.run_no_check.side_effect = lambda cmd, *_, **__: (
        (0, "lab-prefix-console-port-v1,multisession-console-v1", "")
        if "runtime-relay.capabilities" in cmd else (0, "true", "")
    )
    current = {
        "master": RuntimeRelayState(
            host="master", container=runtime_relay_container_name("demo"),
            bind_ip="10.0.0.10", port=runtime_relay_port("demo"),
            api_key="secret", allowed=[micro_vd_container_name("demo", "R1")],
        ),
    }

    result = relay_svc.reconcile_runtime_relays(
        topo, plan, {"master": client}, {"master": "10.0.0.10"},
        "secret", current,
    )

    assert result["master"]["allowed"] == [
        micro_vd_container_name("demo", "R1"),
        micro_vd_container_name("demo", "R2"),
    ]
    assert not any(
        "docker rm -f" in call.args[0] or "docker run -d" in call.args[0]
        for call in client.run.call_args_list
    )


def test_reconcile_restarts_relay_without_multisession_capability():
    topo = make_topology(name="demo")
    plan = _plan_with_assignments("demo", {"master": ["R1"]})
    client = _mock_host_client()

    def run_no_check(cmd, *_, **__):
        if "runtime-relay.capabilities" in cmd:
            return 0, "lab-prefix-console-port-v1", ""
        if "docker image inspect" in cmd:
            return 0, "", ""
        if "docker inspect" in cmd and "State.Running" in cmd:
            return 0, "true", ""
        return 0, "", ""

    client.run_no_check.side_effect = run_no_check
    current = {
        "master": RuntimeRelayState(
            host="master", container=runtime_relay_container_name("demo"),
            bind_ip="10.0.0.10", port=runtime_relay_port("demo"),
            api_key="secret", allowed=[micro_vd_container_name("demo", "R1")],
        ),
    }

    relay_svc.reconcile_runtime_relays(
        topo, plan, {"master": client}, {"master": "10.0.0.10"},
        "secret", current,
    )

    commands = [call.args[0] for call in client.run.call_args_list]
    assert any("docker rm -f" in command for command in commands)
    assert any("docker run -d" in command for command in commands)


def test_relay_authorizes_lab_prefix_but_not_another_lab(monkeypatch):
    monkeypatch.setattr(relay_daemon, "API_KEY", "secret")
    monkeypatch.setattr(relay_daemon, "ALLOWED", set())
    monkeypatch.setattr(relay_daemon, "ALLOWED_PREFIX", "clab-dnlab-demo-")

    assert relay_daemon._authorized("secret", "clab-dnlab-demo-R2-R2")
    assert not relay_daemon._authorized("secret", "clab-dnlab-other-R2-R2")
    assert not relay_daemon._authorized("secret", "clab-dnlab-demo-arbitrary")


def test_deploy_runtime_relay_missing_image_raises():
    topo = make_topology(name="demo")
    plan = _plan_with_assignments("demo", {"master": ["R1"]})

    with pytest.raises(RuntimeError, match="not found"):
        relay_svc.deploy_runtime_relays(
            topo,
            plan,
            {"master": _mock_host_client(image_exists=False)},
            {"master": "10.0.0.10"},
            api_key="secret",
        )


def test_destroy_runtime_relays_removes_sidecar_on_each_host():
    clients = {"master": MagicMock(), "worker1": MagicMock()}

    relay_svc.destroy_runtime_relays("demo", clients)

    for client in clients.values():
        run_cmds = [c.args[0] for c in client.run.call_args_list]
        assert any(
            f"docker rm -f {runtime_relay_container_name('demo')}" in cmd
            for cmd in run_cmds
        )


def test_connect_cmd_returns_serial_port(monkeypatch):
    monkeypatch.setattr(relay_daemon, "_discover_console_port", lambda _container: "5003")
    monkeypatch.setattr(relay_daemon, "_serial_console_ready", lambda _container: True)

    cmd, port = relay_daemon._connect_cmd("container1")

    assert port == "5003"
    assert cmd == [
        "docker", "exec", "-it", "container1", "telnet", "127.0.0.1", "5003",
    ]


@pytest.mark.parametrize(
    "returncode, output, expected",
    [
        (0, "0 running\n", True),
        (0, "0 running-degraded: breakout reconciliation failed\n", True),
        (0, "1 starting\n", False),
        (1, "", None),
    ],
)
def test_serial_console_readiness_uses_vrnetlab_health(
    monkeypatch, returncode, output, expected,
):
    monkeypatch.setattr(
        relay_daemon.subprocess,
        "run",
        lambda *_args, **_kwargs: MagicMock(
            returncode=returncode,
            stdout=output,
        ),
    )

    assert relay_daemon._serial_console_ready("container1") is expected


@pytest.mark.parametrize("ready", [False, None])
def test_connect_cmd_waits_for_launcher_to_release_serial(monkeypatch, ready):
    monkeypatch.setattr(relay_daemon, "_discover_console_port", lambda _container: "5003")
    monkeypatch.setattr(relay_daemon, "_serial_console_ready", lambda _container: ready)

    assert relay_daemon._connect_cmd("container1") is None


def test_console_discovery_prefers_launcher_declared_port(monkeypatch):
    calls = []

    def fake_run(args, **_kwargs):
        calls.append(args)
        return MagicMock(returncode=0, stdout="5002\n")

    monkeypatch.setattr(relay_daemon.subprocess, "run", fake_run)

    assert relay_daemon._discover_console_port("container1") == "5002"
    assert calls == [[
        "docker", "exec", "container1", "cat", "/run/dnlab-console-port",
    ]]


def test_console_discovery_rejects_invalid_declaration_and_scans(monkeypatch):
    responses = iter([
        MagicMock(returncode=0, stdout="22\n"),
        MagicMock(returncode=0, stdout="5000\n"),
    ])
    monkeypatch.setattr(
        relay_daemon.subprocess, "run", lambda *_args, **_kwargs: next(responses),
    )

    assert relay_daemon._discover_console_port("container1") == "5000"


def test_connect_cmd_shell_fallback_has_no_serial_port(monkeypatch):
    monkeypatch.setattr(relay_daemon, "_discover_console_port", lambda _container: "")
    monkeypatch.setattr(relay_daemon, "_serial_console_expected", lambda _container: False)

    cmd, port = relay_daemon._connect_cmd("container1")

    assert port is None
    assert cmd[:4] == ["docker", "exec", "-it", "container1"]
    assert "vtysh" in cmd[-1]


def test_connect_cmd_waits_for_expected_serial_console(monkeypatch):
    monkeypatch.setattr(relay_daemon, "_discover_console_port", lambda _container: "")
    monkeypatch.setattr(relay_daemon, "_serial_console_expected", lambda _container: True)

    assert relay_daemon._connect_cmd("container1") is None


@pytest.mark.parametrize("returncode, expected", [(0, True), (1, False), (125, None)])
def test_serial_console_expectation_handles_vm_native_and_transient_failure(
    monkeypatch, returncode, expected,
):
    monkeypatch.setattr(
        relay_daemon.subprocess, "run",
        lambda *_args, **_kwargs: MagicMock(returncode=returncode),
    )

    assert relay_daemon._serial_console_expected("container1") is expected


def test_relay_pty_disconnect_cleans_container_telnet(monkeypatch):
    relay_sock = FakeRelaySocket()
    cleanup_calls = []

    class FakeProc:
        pid = os.getpid()

        def __init__(self, args, **_kwargs):
            self.args = args
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return self.returncode

    def fake_run(args, **_kwargs):
        cleanup_calls.append(args)
        return MagicMock(returncode=0)

    monkeypatch.setattr(relay_daemon.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(relay_daemon.subprocess, "run", fake_run)

    try:
        relay_sock.disconnect()
        relay_daemon._relay_pty(
            relay_sock,
            ["docker", "exec", "-it", "container1", "telnet", "127.0.0.1", "5000"],
            "container1",
            "5000",
        )
    finally:
        relay_sock.close()

    assert cleanup_calls == [[
        "docker",
        "exec",
        "container1",
        "sh",
        "-c",
        "pkill -f '[t]elnet 127[.]0[.]0[.]1 5000' || true",
    ]]


def test_relay_pty_shell_fallback_does_not_cleanup_telnet(monkeypatch):
    relay_sock = FakeRelaySocket()
    cleanup_calls = []

    class FakeProc:
        pid = os.getpid()

        def __init__(self, args, **_kwargs):
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return self.returncode

    monkeypatch.setattr(relay_daemon.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(
        relay_daemon.subprocess,
        "run",
        lambda args, **_kwargs: cleanup_calls.append(args),
    )

    try:
        relay_sock.disconnect()
        relay_daemon._relay_pty(
            relay_sock,
            ["docker", "exec", "-it", "container1", "sh"],
            "container1",
            None,
        )
    finally:
        relay_sock.close()

    assert cleanup_calls == []


def test_container_telnet_cleanup_errors_are_best_effort(monkeypatch):
    def fake_run(*_args, **_kwargs):
        raise TimeoutError("docker stuck")

    monkeypatch.setattr(relay_daemon.subprocess, "run", fake_run)

    relay_daemon._cleanup_container_telnet("container1", "5000")


def test_console_broker_fanout_input_replay_and_grace(monkeypatch):
    popen_calls = []
    writes = []

    class FakeProc:
        pid = os.getpid()

        def __init__(self, args, **_kwargs):
            popen_calls.append(args)
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    monkeypatch.setattr(relay_daemon, "_connect_cmd", lambda _container: (["fake"], "5000"))
    monkeypatch.setattr(relay_daemon.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(relay_daemon, "_cleanup_container_telnet", lambda *_: None)
    monkeypatch.setattr(relay_daemon, "CONSOLE_GRACE_SECONDS", 0.15)
    def no_upstream_data(*_args, **_kwargs):
        time.sleep(0.005)
        return [], [], []

    monkeypatch.setattr(relay_daemon.select, "select", no_upstream_data)
    real_write = relay_daemon.os.write

    def record_write(fd, data):
        writes.append(bytes(data))
        return len(data)

    relay_daemon._close_console_brokers()
    client1 = FakeConsoleSocket()
    client2 = FakeConsoleSocket()
    threads = [
        threading.Thread(
            target=relay_daemon._get_console_broker("container1").attach,
            args=(client1,), daemon=True,
        ),
        threading.Thread(
            target=relay_daemon._get_console_broker("container1").attach,
            args=(client2,), daemon=True,
        ),
    ]
    for thread in threads:
        thread.start()
    broker = relay_daemon._get_console_broker("container1")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and (
        len(broker._subscribers) != 2 or len(popen_calls) != 1
    ):
        time.sleep(0.005)
    assert len(broker._subscribers) == 2
    assert len(popen_calls) == 1

    broker._fan_out(b"ready\n")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and (not client1.sent or not client2.sent):
        time.sleep(0.005)
    assert client1.sent == [b"ready\n"]
    assert client2.sent == [b"ready\n"]

    monkeypatch.setattr(relay_daemon.os, "write", record_write)
    client1.client_send(b"one\n")
    client2.client_send(b"two\n")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len(writes) < 2:
        time.sleep(0.005)
    assert sorted(writes[:2]) == [b"one\n", b"two\n"]
    monkeypatch.setattr(relay_daemon.os, "write", real_write)

    client1.client_close()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len(broker._subscribers) != 1:
        time.sleep(0.005)
    broker._fan_out(b"still-live\n")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len(client2.sent) != 2:
        time.sleep(0.005)
    assert client2.sent[-1] == b"still-live\n"

    client2.client_close()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and broker._subscribers:
        time.sleep(0.005)
    assert not broker._subscribers

    client3 = FakeConsoleSocket()
    thread3 = threading.Thread(target=broker.attach, args=(client3,), daemon=True)
    thread3.start()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not client3.sent:
        time.sleep(0.005)
    assert client3.sent == [b"ready\nstill-live\n"]
    time.sleep(0.2)
    assert not broker.closed

    client3.client_close()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not broker.closed:
        time.sleep(0.005)
    assert broker.closed
    for thread in [*threads, thread3]:
        thread.join(timeout=1)


def test_console_broker_history_is_bounded_and_sessions_are_per_container(monkeypatch):
    popen_calls = []

    class FakeProc:
        pid = os.getpid()

        def __init__(self, args, **_kwargs):
            popen_calls.append(args)
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    monkeypatch.setattr(
        relay_daemon, "_connect_cmd", lambda container: (["fake", container], "5000"),
    )
    monkeypatch.setattr(relay_daemon.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(relay_daemon, "_cleanup_container_telnet", lambda *_: None)
    def no_upstream_data(*_args, **_kwargs):
        time.sleep(0.005)
        return [], [], []

    monkeypatch.setattr(relay_daemon.select, "select", no_upstream_data)
    relay_daemon._close_console_brokers()
    first = relay_daemon._get_console_broker("container1")
    second = relay_daemon._get_console_broker("container2")

    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len(popen_calls) != 2:
        time.sleep(0.005)

    first._fan_out(b"x" * (relay_daemon.CONSOLE_HISTORY_BYTES + 17))

    assert len(first._history) == relay_daemon.CONSOLE_HISTORY_BYTES
    assert first is relay_daemon._get_console_broker("container1")
    assert first is not second
    assert len(popen_calls) == 2
    first.close()
    replacement = relay_daemon._get_console_broker("container1")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len(popen_calls) != 3:
        time.sleep(0.005)
    assert replacement is not first
    assert len(popen_calls) == 3
    relay_daemon._close_console_brokers()


def test_console_clients_wait_together_for_one_serial_upstream(monkeypatch):
    ready = threading.Event()
    popen_calls = []
    writes = []

    class FakeProc:
        pid = os.getpid()

        def __init__(self, args, **_kwargs):
            popen_calls.append(args)
            self.returncode = None

        def poll(self):
            return self.returncode

        def wait(self, timeout=None):
            self.returncode = 0
            return 0

    def connect_when_ready(_container):
        return (["fake"], "5000") if ready.is_set() else None

    def no_upstream_data(*_args, **_kwargs):
        time.sleep(0.005)
        return [], [], []

    monkeypatch.setattr(relay_daemon, "_connect_cmd", connect_when_ready)
    monkeypatch.setattr(relay_daemon, "_container_running", lambda _container: True)
    monkeypatch.setattr(relay_daemon, "CONSOLE_READY_POLL_SECONDS", 0.01)
    monkeypatch.setattr(relay_daemon.subprocess, "Popen", FakeProc)
    monkeypatch.setattr(relay_daemon.select, "select", no_upstream_data)
    monkeypatch.setattr(relay_daemon, "_cleanup_container_telnet", lambda *_: None)
    monkeypatch.setattr(
        relay_daemon.os, "write",
        lambda _fd, data: writes.append(bytes(data)) or len(data),
    )
    relay_daemon._close_console_brokers()

    clients = [FakeConsoleSocket(), FakeConsoleSocket()]
    broker = relay_daemon._get_console_broker("waiting-container")
    threads = [
        threading.Thread(target=broker.attach, args=(client,), daemon=True)
        for client in clients
    ]
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len(broker._subscribers) != 2:
        time.sleep(0.005)

    assert len(broker._subscribers) == 2
    assert popen_calls == []
    clients[0].client_send(b"typed-while-waiting\n")
    time.sleep(0.02)
    assert writes == []

    ready.set()
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and len(popen_calls) != 1:
        time.sleep(0.005)
    assert popen_calls == [["fake"]]
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and not writes:
        time.sleep(0.005)
    assert writes == [b"typed-while-waiting\n"]

    broker._fan_out(b"console-ready\n")
    deadline = time.monotonic() + 1
    while time.monotonic() < deadline and any(not client.sent for client in clients):
        time.sleep(0.005)
    assert [client.sent for client in clients] == [
        [b"console-ready\n"], [b"console-ready\n"],
    ]

    for client in clients:
        client.client_close()
    for thread in threads:
        thread.join(timeout=1)
    broker.close()


def test_console_subscriber_rejects_slow_client_queue(monkeypatch):
    client = FakeConsoleSocket()
    subscriber = relay_daemon._ConsoleSubscriber(client)
    monkeypatch.setattr(relay_daemon, "CONSOLE_CLIENT_QUEUE_BYTES", 4)
    try:
        assert subscriber.enqueue(b"1234")
        assert not subscriber.enqueue(b"5")
    finally:
        subscriber.close()


def test_stream_logs_flushes_small_chunks_immediately(monkeypatch):
    read_fd, write_fd = os.pipe()
    relay_sock = FakeRelaySocket()

    class FakeStdout:
        def fileno(self):
            return read_fd

    class FakeProc:
        stdout = FakeStdout()

        def __init__(self, *_, **__):
            self.returncode = None
            self.terminated = False

        def poll(self):
            return self.returncode

        def terminate(self):
            self.terminated = True
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(relay_daemon.subprocess, "Popen", FakeProc)
    try:
        import threading

        thread = threading.Thread(
            target=relay_daemon._stream_logs,
            args=(relay_sock, "container1", "200", "1"),
            daemon=True,
        )
        thread.start()
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and not relay_sock.sent:
            time.sleep(0.01)
        assert relay_sock.sent == [b"OK\n"]

        os.write(write_fd, b"x\n")
        deadline = time.monotonic() + 1
        while time.monotonic() < deadline and b"x\n" not in relay_sock.sent:
            time.sleep(0.01)
        assert b"x\n" in relay_sock.sent

        relay_sock.disconnect()
        thread.join(timeout=2)
        assert not thread.is_alive()
    finally:
        relay_sock.close()
        for fd in (read_fd, write_fd):
            try:
                os.close(fd)
            except OSError:
                pass


def test_stream_logs_builds_history_and_follow_commands(monkeypatch):
    calls = []

    class FakeStdout:
        def __init__(self):
            self.read_fd, self.write_fd = os.pipe()
            os.close(self.write_fd)

        def fileno(self):
            return self.read_fd

    class FakeProc:
        def __init__(self, args, **_kwargs):
            calls.append(args)
            self.stdout = FakeStdout()
            self.returncode = 0

        def poll(self):
            return self.returncode

        def terminate(self):
            self.returncode = -15

        def wait(self, timeout=None):
            return self.returncode

        def kill(self):
            self.returncode = -9

    monkeypatch.setattr(relay_daemon.subprocess, "Popen", FakeProc)

    for tail, follow in (("all", "0"), ("200", "1")):
        relay_sock = FakeRelaySocket()
        try:
            relay_daemon._stream_logs(relay_sock, "container1", tail, follow)
            assert relay_sock.sent == [b"OK\n"]
        finally:
            relay_sock.close()

    assert calls == [
        ["docker", "logs", "container1"],
        ["docker", "logs", "-f", "--tail=200", "container1"],
    ]
