"""Real vd/client/relay framing with a loopback server and no Docker calls."""
import os
from pathlib import Path
import socket
import subprocess
import threading
from types import SimpleNamespace

import pytest

from dnlab_multinode.services.jumphost import render_relay_inventory
from tests.runtime_relay_import import load_runtime_relay_module


@pytest.mark.parametrize('action', ['connect', 'log', 'stale-log'])
def test_native_cli_to_relay_preserves_identity_and_console_input(tmp_path, monkeypatch, action):
    relay = load_runtime_relay_module()
    assets = Path(__file__).resolve().parents[1] / 'jumphost'
    name, identity = 'native-R1', 'a' * 64
    command = b'first-command-before-prompt\n'
    output = b'fixture-verified-output\n'
    observed, errors = [], []
    # Reproduce COPY --chmod=0755 from the image recipe; checkout mode is 0644.
    binary = tmp_path / 'bin'
    binary.mkdir()
    client = binary / 'vd-relay-client'
    client.write_bytes((assets / 'vd-relay-client').read_bytes())
    client.chmod(0o755)
    monkeypatch.setattr(relay, 'API_KEY', 'fixture-key')
    monkeypatch.setattr(relay, 'ALLOWED', {name})
    monkeypatch.setattr(relay.subprocess, 'run', lambda *a, **kw: pytest.fail('unexpected Docker call'))

    def resolve(container, expected_id=None):
        observed.append(('resolve', container, expected_id))
        assert container == name and expected_id == identity
        if action == 'stale-log':
            raise RuntimeError('original generation differs')
        return identity

    def console(sock):
        data = b''
        while len(data) < len(command):
            part = sock.recv(len(command) - len(data))
            if not part:
                break
            data += part
        observed.append(('console', data))
        assert data == command
        sock.sendall(output)

    def logs(sock, target, tail, follow):
        observed.append(('logs', target, tail, follow))
        sock.sendall(b'OK\n' + output)

    monkeypatch.setattr(relay, '_resolve_target', resolve)
    monkeypatch.setattr(relay, '_get_console_broker', lambda target: SimpleNamespace(attach=console))
    monkeypatch.setattr(relay, '_stream_logs', logs)
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(5)
        vds, routes = render_relay_inventory({'R1': name}, {name: {
            'host': '127.0.0.1', 'port': server.getsockname()[1], 'api_key': 'fixture-key',
            'runtime_backend': 'custom', 'container_id': identity}})
        (tmp_path / 'vds').write_text(vds)
        (tmp_path / 'relays').write_text(routes)

        def serve():
            try:
                conn, address = server.accept()
                conn.settimeout(5)
                relay._handle(conn, address)
            except Exception as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        env = dict(os.environ, VD_LIST_FILE=str(tmp_path / 'vds'),
                   VD_RELAY_FILE=str(tmp_path / 'relays'), PATH=str(binary) + ':' + os.environ['PATH'])
        # Popen deliberately bypasses the forbidden Docker subprocess.run path.
        with subprocess.Popen([str(assets / 'vd'), 'connect' if action == 'connect' else 'log', 'R1'],
                              env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE) as process:
            stdout, stderr = process.communicate(command if action == 'connect' else b'', timeout=5)
        thread.join(5)
        assert not thread.is_alive() and not errors, (errors, process.returncode, stdout, stderr)
    assert observed[0] == ('resolve', name, identity)
    if action == 'stale-log':
        assert process.returncode != 0 and b'original generation differs' in stderr
        assert len(observed) == 1
    else:
        assert process.returncode == 0 and stdout == output and not stderr
        assert observed[1] == (('console', command) if action == 'connect'
                               else ('logs', identity, 'all', '0'))


def test_actual_cli_and_broker_receive_delayed_output_with_input_open(tmp_path, monkeypatch):
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
    from console_input_fixture import exchange
    relay = load_runtime_relay_module()
    assets = Path(__file__).resolve().parents[1] / 'jumphost'
    client = tmp_path / 'vd-relay-client'
    client.write_bytes((assets / 'vd-relay-client').read_bytes())
    client.chmod(0o755)
    broker = relay._ConsoleBroker('a' * 64)
    command_received, detached = threading.Event(), threading.Event()
    errors = []
    command, marker = b'first-command\n', b'delayed-guest-response'
    monkeypatch.setattr(relay, 'API_KEY', 'key')
    monkeypatch.setattr(relay, 'ALLOWED', {'native-R1'})
    monkeypatch.setattr(relay, '_resolve_target', lambda *args: 'a' * 64)
    monkeypatch.setattr(relay, '_get_console_broker', lambda target: broker)

    def write(data):
        assert data == command
        command_received.set()

    original_detach = broker.detach

    def detach(subscriber):
        detached.set()
        original_detach(subscriber)

    monkeypatch.setattr(broker, 'write', write)
    monkeypatch.setattr(broker, 'detach', detach)
    monkeypatch.setattr(relay.subprocess, 'run', lambda *a, **kw: pytest.fail('unexpected Docker'))
    with socket.socket() as server:
        server.bind(('127.0.0.1', 0))
        server.listen(1)
        server.settimeout(5)
        vds, routes = render_relay_inventory({'R1': 'native-R1'}, {'native-R1': {
            'host': '127.0.0.1', 'port': server.getsockname()[1], 'api_key': 'key',
            'runtime_backend': 'custom', 'container_id': 'a' * 64}})
        (tmp_path / 'vds').write_text(vds)
        (tmp_path / 'relays').write_text(routes)

        def serve():
            try:
                conn, address = server.accept()
                conn.settimeout(5)
                relay._handle(conn, address)
            except Exception as error:
                errors.append(error)

        def guest():
            try:
                assert command_received.wait(3)
                assert not detached.is_set()
                broker._fan_out(marker + b'\n')
            except Exception as error:
                errors.append(error)

        threads = [threading.Thread(target=fn, daemon=True) for fn in (serve, guest)]
        for thread in threads:
            thread.start()
        env = dict(os.environ, VD_LIST_FILE=str(tmp_path / 'vds'),
                   VD_RELAY_FILE=str(tmp_path / 'relays'), PATH=str(tmp_path) + ':' + os.environ['PATH'])
        process = subprocess.Popen([str(assets / 'vd'), 'connect', 'R1'], env=env,
                                   stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            result = exchange(process, command, marker, timeout=5)
            assert result['output'] == marker + b'\n' and result['exit_verified']
        finally:
            if process.poll() is None:
                process.kill()
            process.wait(timeout=3)
            process.stdout.close()
            process.stderr.close()
            broker.close()
            for thread in threads:
                thread.join(5)
            assert not errors and all(not thread.is_alive() for thread in threads)
    assert detached.is_set()
