#!/usr/bin/env python3
"""Small lab-scoped runtime relay for dNLab jumphost and GUI.

The relay is intentionally narrow: it accepts CONNECT and LOG requests for
containers explicitly allowlisted at deploy time, guarded by one lab-scoped
API key. It is the only component in this path with the Docker socket.
"""

from __future__ import annotations

import os
import pty
import queue
import select
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time
from hmac import compare_digest


HOST = os.getenv("RELAY_BIND", "0.0.0.0")
PORT = int(os.getenv("RELAY_PORT", "23000"))
API_KEY = os.getenv("RELAY_API_KEY", "")
ALLOWED = {x for x in os.getenv("RELAY_ALLOWED_CONTAINERS", "").split() if x}
ALLOWED_PREFIX = os.getenv("RELAY_ALLOWED_PREFIX", "")
READ_SIZE = 4096
CONSOLE_PORT_FILE = "/run/dnlab-console-port"
CONSOLE_PORTS = {str(port) for port in range(5000, 5008)}
CONSOLE_HISTORY_BYTES = 64 * 1024
CONSOLE_CLIENT_QUEUE_BYTES = 256 * 1024
CONSOLE_GRACE_SECONDS = float(os.getenv("RELAY_CONSOLE_GRACE_SECONDS", "30"))
CONSOLE_READY_TIMEOUT = float(os.getenv("RELAY_CONSOLE_READY_TIMEOUT", "900"))
CONSOLE_READY_POLL_SECONDS = float(os.getenv("RELAY_CONSOLE_READY_POLL_SECONDS", "0.5"))


class _ConsoleSubscriber:
    """One downstream client with isolated, bounded output buffering."""

    def __init__(self, sock: socket.socket) -> None:
        self.sock = sock
        self._queue: queue.Queue[bytes | None] = queue.Queue()
        self._lock = threading.Lock()
        self._queued_bytes = 0
        self._closed = False
        self._sender = threading.Thread(target=self._send_loop, daemon=True)

    def start(self) -> None:
        self._sender.start()

    def enqueue(self, data: bytes) -> bool:
        if not data:
            return True
        with self._lock:
            if self._closed:
                return False
            if self._queued_bytes + len(data) > CONSOLE_CLIENT_QUEUE_BYTES:
                return False
            self._queued_bytes += len(data)
            self._queue.put(data)
            return True

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._queue.put(None)
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass

    def _send_loop(self) -> None:
        try:
            while True:
                data = self._queue.get()
                if data is None:
                    return
                try:
                    self.sock.sendall(data)
                except OSError:
                    self.close()
                    return
                with self._lock:
                    self._queued_bytes -= len(data)
        finally:
            self.close()


class _ConsoleBroker:
    """A single VD console upstream shared by multiple downstream clients."""

    def __init__(self, container: str) -> None:
        self.container = container
        self.port: str | None = None
        self.proc: subprocess.Popen | None = None
        self.master_fd: int | None = None
        self._lock = threading.RLock()
        self._input_lock = threading.Lock()
        self._subscribers: set[_ConsoleSubscriber] = set()
        self._history = bytearray()
        self._grace_timer: threading.Timer | None = None
        self._closed = False
        self._cleanup_done = threading.Event()
        self._ready_wakeup = threading.Event()
        self._upstream_ready = threading.Event()

    def start(self) -> None:
        threading.Thread(target=self._wait_for_upstream, daemon=True).start()

    @property
    def closed(self) -> bool:
        with self._lock:
            return self._closed

    def _wait_for_upstream(self) -> None:
        """Open one upstream when the real console endpoint becomes ready."""
        deadline = time.monotonic() + CONSOLE_READY_TIMEOUT
        try:
            while True:
                with self._lock:
                    if self._closed:
                        return
                target = _connect_cmd(self.container)
                if target is not None:
                    self._start_upstream(*target)
                    return
                if not _container_running(self.container):
                    self.close()
                    return
                if time.monotonic() >= deadline:
                    self.close()
                    return
                self._ready_wakeup.wait(CONSOLE_READY_POLL_SECONDS)
                self._ready_wakeup.clear()
        except Exception:
            self.close()

    def _start_upstream(self, cmd: list[str], port: str | None) -> None:
        master_fd, slave_fd = pty.openpty()
        try:
            proc = subprocess.Popen(
                cmd,
                stdin=slave_fd,
                stdout=slave_fd,
                stderr=slave_fd,
                close_fds=True,
                preexec_fn=os.setsid,
            )
        except Exception:
            os.close(master_fd)
            raise
        finally:
            os.close(slave_fd)
        with self._lock:
            if self._closed:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except OSError:
                    pass
                os.close(master_fd)
                return
            self.port = port
            self.master_fd = master_fd
            self.proc = proc
            self._upstream_ready.set()
        threading.Thread(target=self._read_upstream, daemon=True).start()

    def attach(self, sock: socket.socket) -> None:
        subscriber = _ConsoleSubscriber(sock)
        with self._lock:
            if self._closed:
                raise RuntimeError("console session closed")
            if self._grace_timer is not None:
                self._grace_timer.cancel()
                self._grace_timer = None
            # Register and queue history under the same lock used by fan-out:
            # live bytes can therefore arrive before or after the replay, never
            # in the middle of the attach snapshot.
            self._subscribers.add(subscriber)
            if self._history and not subscriber.enqueue(bytes(self._history)):
                self._subscribers.remove(subscriber)
                raise RuntimeError("console replay exceeds client queue")
        subscriber.start()
        try:
            while True:
                data = sock.recv(READ_SIZE)
                if not data:
                    break
                self.write(data)
        except OSError:
            pass
        finally:
            self.detach(subscriber)

    def write(self, data: bytes) -> None:
        with self._input_lock:
            while True:
                with self._lock:
                    if self._closed:
                        raise RuntimeError("console upstream closed")
                    master_fd = self.master_fd
                if master_fd is not None:
                    break
                self._upstream_ready.wait(0.2)
            view = memoryview(data)
            while view:
                written = os.write(master_fd, view)
                view = view[written:]

    def detach(self, subscriber: _ConsoleSubscriber) -> None:
        subscriber.close()
        with self._lock:
            self._subscribers.discard(subscriber)
            if self._closed or self._subscribers or self._grace_timer is not None:
                return
            self._grace_timer = threading.Timer(CONSOLE_GRACE_SECONDS, self.close)
            self._grace_timer.daemon = True
            self._grace_timer.start()

    def _read_upstream(self) -> None:
        try:
            while True:
                with self._lock:
                    if self._closed or self.master_fd is None:
                        return
                    master_fd = self.master_fd
                    proc = self.proc
                if proc is None or proc.poll() is not None:
                    break
                readable, _, _ = select.select([master_fd], [], [], 0.2)
                if not readable:
                    continue
                try:
                    data = os.read(master_fd, READ_SIZE)
                except OSError:
                    break
                if not data:
                    break
                self._fan_out(data)
        finally:
            self.close()

    def _fan_out(self, data: bytes) -> None:
        slow: list[_ConsoleSubscriber] = []
        with self._lock:
            if self._closed:
                return
            self._history.extend(data)
            overflow = len(self._history) - CONSOLE_HISTORY_BYTES
            if overflow > 0:
                del self._history[:overflow]
            for subscriber in self._subscribers:
                if not subscriber.enqueue(data):
                    slow.append(subscriber)
            for subscriber in slow:
                self._subscribers.discard(subscriber)
            if slow and not self._subscribers and self._grace_timer is None:
                self._grace_timer = threading.Timer(CONSOLE_GRACE_SECONDS, self.close)
                self._grace_timer.daemon = True
                self._grace_timer.start()
        for subscriber in slow:
            subscriber.close()

    def close(self) -> None:
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._ready_wakeup.set()
            self._upstream_ready.set()
            if self._grace_timer is not None:
                self._grace_timer.cancel()
                self._grace_timer = None
            subscribers = list(self._subscribers)
            self._subscribers.clear()
            master_fd = self.master_fd
            self.master_fd = None
            proc = self.proc
            self.proc = None
        for subscriber in subscribers:
            subscriber.close()
        if master_fd is not None:
            try:
                os.write(master_fd, b"\x1dquit\r")
            except OSError:
                pass
        if proc is not None and proc.poll() is None:
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                except OSError:
                    pass
                try:
                    proc.wait(timeout=1)
                except subprocess.TimeoutExpired:
                    try:
                        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                    except OSError:
                        pass
        if master_fd is not None:
            try:
                os.close(master_fd)
            except OSError:
                pass
        try:
            _cleanup_container_telnet(self.container, self.port)
        finally:
            _remove_console_broker(self.container, self)
            self._cleanup_done.set()


_CONSOLE_BROKERS: dict[str, _ConsoleBroker] = {}
_CONSOLE_BROKERS_LOCK = threading.Lock()


def _get_console_broker(container: str) -> _ConsoleBroker:
    while True:
        with _CONSOLE_BROKERS_LOCK:
            broker = _CONSOLE_BROKERS.get(container)
            if broker is None:
                broker = _ConsoleBroker(container)
                _CONSOLE_BROKERS[container] = broker
                broker.start()
            if not broker.closed:
                return broker
        # Do not start a replacement until the previous docker-exec/telnet
        # cleanup has finished, otherwise its best-effort pkill could race
        # with and terminate the new upstream.
        broker._cleanup_done.wait()


def _remove_console_broker(container: str, broker: _ConsoleBroker) -> None:
    with _CONSOLE_BROKERS_LOCK:
        if _CONSOLE_BROKERS.get(container) is broker:
            del _CONSOLE_BROKERS[container]


def _close_console_brokers() -> None:
    with _CONSOLE_BROKERS_LOCK:
        brokers = list(_CONSOLE_BROKERS.values())
    for broker in brokers:
        broker.close()


def _send_line(sock: socket.socket, line: str) -> None:
    sock.sendall((line.rstrip("\n") + "\n").encode())


def _read_request(sock: socket.socket) -> list[str] | None:
    buf = b""
    while b"\n" not in buf and len(buf) < 8192:
        chunk = sock.recv(1024)
        if not chunk:
            return None
        buf += chunk
    line = buf.split(b"\n", 1)[0].decode(errors="replace").strip()
    return shlex.split(line) if line else None


def _authorized(key: str, container: str) -> bool:
    allowed = container in ALLOWED or _matches_lab_container(container)
    return bool(API_KEY) and compare_digest(key, API_KEY) and allowed


def _matches_lab_container(container: str) -> bool:
    """Match only ``<prefix><node>-<node>`` per-VD runtime names.

    Merely checking the prefix would let a lab whose name extends another
    lab's name overlap its relay namespace (for example ``demo`` and
    ``demo-other``).
    """
    if not ALLOWED_PREFIX or not container.startswith(ALLOWED_PREFIX):
        return False
    suffix = container[len(ALLOWED_PREFIX):]
    return any(
        suffix[:index] == suffix[index + 1:]
        for index, char in enumerate(suffix)
        if char == "-" and index > 0 and index + 1 < len(suffix)
    )


def _container_running(container: str) -> bool:
    proc = subprocess.run(
        ["docker", "inspect", "-f", "{{.State.Running}}", container],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    return proc.returncode == 0 and proc.stdout.strip() == "true"


def _discover_console_port(container: str) -> str:
    # Version-aware launchers publish the actual guest console.  XRv9k 25.x,
    # for example, listens on several serial sockets and publishes the one
    # intended for the interactive user console;
    # selecting the first socket would connect users to the Linux console.
    preferred = subprocess.run(
        ["docker", "exec", container, "cat", CONSOLE_PORT_FILE],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    preferred_port = preferred.stdout.strip() if preferred.returncode == 0 else ""
    if preferred_port in CONSOLE_PORTS:
        return preferred_port

    expr = (
        "ss -Htln 2>/dev/null | "
        "awk '$1==\"LISTEN\" && $4 !~ /^127\\.0\\.0\\.11:/ "
        "&& ($4 ~ /^127\\.0\\.0\\.1:/ || $4 ~ /^\\[::1\\]:/ "
        "|| $4 ~ /^\\*:/ || $4 ~ /^0\\.0\\.0\\.0:/ || $4 ~ /^\\[::\\]:/) "
        "{ n=split($4,a,\":\"); if (a[n] ~ /^500[0-7]$/) { print a[n]; exit } }'"
    )
    proc = subprocess.run(
        ["docker", "exec", container, "sh", "-c", expr],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    discovered = proc.stdout.strip() if proc.returncode == 0 else ""
    return discovered if discovered in CONSOLE_PORTS else ""


def _serial_console_expected(container: str) -> bool | None:
    """Distinguish VM images from native containers without image metadata."""
    probe = (
        "for path in /usr/bin/qemu-system-* /usr/local/bin/qemu-system-*; do "
        "[ -x \"$path\" ] && exit 0; done; exit 1"
    )
    proc = subprocess.run(
        ["docker", "exec", container, "sh", "-c", probe],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=5,
        check=False,
    )
    if proc.returncode == 0:
        return True
    if proc.returncode == 1:
        return False
    return None


def _serial_console_ready(container: str) -> bool | None:
    """Return explicit vrnetlab readiness; ``None`` means not published yet."""
    proc = subprocess.run(
        ["docker", "exec", container, "cat", "/health"],
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
        timeout=5,
        check=False,
    )
    if proc.returncode != 0:
        return None
    status, _, message = proc.stdout.strip().partition(" ")
    return status == "0" and message.startswith("running")


def _connect_cmd(container: str) -> tuple[list[str], str | None] | None:
    port = _discover_console_port(container)
    if port:
        console_ready = _serial_console_ready(container)
        if console_ready is not True:
            return None
        return (
            ["docker", "exec", "-it", container, "telnet", "127.0.0.1", port],
            port,
        )
    serial_expected = _serial_console_expected(container)
    if serial_expected is not False:
        # A VM-backed VD is still booting. Keep every downstream attached to
        # the broker and retry discovery instead of exposing its container
        # shell or forcing the user to reopen the console.
        return None
    # Native containers such as FRR do not expose a QEMU serial port.
    return (
        [
            "docker",
            "exec",
            "-it",
            container,
            "sh",
            "-lc",
            "command -v vtysh >/dev/null 2>&1 && exec vtysh || exec sh",
        ],
        None,
    )


def _cleanup_container_telnet(container: str, port: str | None) -> None:
    if not port:
        return
    if port not in CONSOLE_PORTS:
        return
    pattern = f"[t]elnet 127[.]0[.]0[.]1 {port}"
    try:
        subprocess.run(
            [
                "docker",
                "exec",
                container,
                "sh",
                "-c",
                f"pkill -f {shlex.quote(pattern)} || true",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            timeout=3,
            check=False,
        )
    except Exception:
        pass


def _relay_pty(sock: socket.socket, cmd: list[str], container: str, port: str | None) -> None:
    master_fd, slave_fd = pty.openpty()
    proc = subprocess.Popen(
        cmd,
        stdin=slave_fd,
        stdout=slave_fd,
        stderr=slave_fd,
        close_fds=True,
        preexec_fn=os.setsid,
    )
    os.close(slave_fd)
    try:
        while proc.poll() is None:
            r, _, _ = select.select([sock, master_fd], [], [], 0.2)
            if sock in r:
                data = sock.recv(READ_SIZE)
                if not data:
                    break
                os.write(master_fd, data)
            if master_fd in r:
                try:
                    data = os.read(master_fd, READ_SIZE)
                except OSError:
                    break
                if not data:
                    break
                sock.sendall(data)
    finally:
        try:
            os.write(master_fd, b"\x1dquit\r")
        except OSError:
            pass
        if proc.poll() is None:
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                pass
        if proc.poll() is None:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
            except OSError:
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except OSError:
                    pass
        try:
            os.close(master_fd)
        except OSError:
            pass
        _cleanup_container_telnet(container, port)


def _stream_logs(sock: socket.socket, container: str, tail: str, follow: str) -> None:
    args = ["docker", "logs"]
    if follow == "1":
        args.append("-f")
    if tail == "all":
        pass
    else:
        args.append(f"--tail={int(tail)}")
    args.append(container)
    proc = subprocess.Popen(
        args,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.DEVNULL,
    )
    try:
        _send_line(sock, "OK")
        assert proc.stdout is not None
        fd = proc.stdout.fileno()
        while True:
            if proc.poll() is not None:
                remaining = os.read(fd, READ_SIZE)
                if remaining:
                    sock.sendall(remaining)
                break
            readable, _, _ = select.select([fd, sock], [], [], 0.2)
            if not readable:
                continue
            if sock in readable:
                try:
                    probe = sock.recv(1, socket.MSG_PEEK)
                except (BlockingIOError, InterruptedError):
                    probe = b"x"
                except OSError:
                    break
                if not probe:
                    break
            if fd in readable:
                data = os.read(fd, READ_SIZE)
                if not data:
                    break
                try:
                    sock.sendall(data)
                except (BrokenPipeError, ConnectionResetError, OSError):
                    break
    finally:
        if proc.poll() is None:
            proc.terminate()
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                proc.kill()


def _handle(sock: socket.socket, _addr) -> None:
    with sock:
        try:
            parts = _read_request(sock)
            if not parts or len(parts) < 3:
                _send_line(sock, "ERR bad request")
                return
            action, key, container = parts[0], parts[1], parts[2]
            if not _authorized(key, container):
                _send_line(sock, "ERR unauthorized")
                return
            if not _container_running(container):
                _send_line(sock, "ERR container not running")
                return
            if action == "CONNECT":
                _get_console_broker(container).attach(sock)
                return
            if action == "LOG":
                tail = parts[3] if len(parts) > 3 else "200"
                follow = parts[4] if len(parts) > 4 else "0"
                _stream_logs(sock, container, tail, follow)
                return
            _send_line(sock, "ERR unknown action")
        except Exception as exc:
            try:
                _send_line(sock, f"ERR {exc}")
            except Exception:
                pass


def main() -> int:
    if not API_KEY:
        print("RELAY_API_KEY is required", file=sys.stderr)
        return 2
    if not ALLOWED:
        print("RELAY_ALLOWED_CONTAINERS is empty", file=sys.stderr)
    def _terminate(_signum, _frame):
        raise SystemExit(0)

    signal.signal(signal.SIGTERM, _terminate)
    signal.signal(signal.SIGINT, _terminate)
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((HOST, PORT))
        srv.listen(64)
        print(f"dnlab-runtime-relay listening on {HOST}:{PORT} for {len(ALLOWED)} containers", flush=True)
        while True:
            client, addr = srv.accept()
            threading.Thread(target=_handle, args=(client, addr), daemon=True).start()
    finally:
        srv.close()
        _close_console_brokers()


if __name__ == "__main__":
    raise SystemExit(main())
