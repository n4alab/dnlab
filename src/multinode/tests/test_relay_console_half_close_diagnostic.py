"""Agreed contract: input EOF disconnects; probes must keep input open."""
import socket
import threading

from tests.runtime_relay_import import load_runtime_relay_module


def test_write_half_close_disconnects_before_later_console_output(monkeypatch):
    relay = load_runtime_relay_module()
    name, identity = 'native-R1', 'a' * 64
    command, response = b'first-command\n', b'delayed-guest-output\n'
    broker = relay._ConsoleBroker(identity)
    received = []
    monkeypatch.setattr(relay, 'API_KEY', 'fixture-key')
    monkeypatch.setattr(relay, 'ALLOWED', {name})
    monkeypatch.setattr(relay, '_resolve_target', lambda *args: identity)
    monkeypatch.setattr(relay, '_get_console_broker', lambda target: broker)
    monkeypatch.setattr(broker, 'write', received.append)
    # No upstream process is started. Guest output is injected only after the
    # input EOF has been processed, removing scheduling luck from the check.
    client, server = socket.socketpair()
    thread = threading.Thread(target=relay._handle, args=(server, None), daemon=True)
    try:
        client.settimeout(2)
        thread.start()
        client.sendall(f'CONNECT_ID fixture-key {name} {identity}\n'.encode() + command)
        client.shutdown(socket.SHUT_WR)
        thread.join(2)
        assert not thread.is_alive()
        assert received == [command]
        broker._fan_out(response)
        actual = client.recv(4096)
        assert actual == b''
        assert bytes(broker._history) == response and not broker._subscribers
    finally:
        client.close()
        broker.close()
        thread.join(2)
        assert not thread.is_alive()
