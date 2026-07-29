"""SSH/SFTP operations via paramiko."""

from __future__ import annotations

import logging
import os
import shlex
import threading
import time
from pathlib import Path

import paramiko

log = logging.getLogger(__name__)

# Timeouts
_CONNECT_TIMEOUT = 10
_CMD_TIMEOUT = 30
_DEPLOY_TIMEOUT = 300


class SSHError(Exception):
    """Raised when an SSH command fails."""
    def __init__(self, host: str, command: str, stderr: str, returncode: int = -1):
        self.host = host
        self.command = command
        self.stderr = stderr
        self.returncode = returncode
        super().__init__(f"[{host}] Command failed (rc={returncode}): {command}\n  stderr: {stderr}")


class SSHClient:
    """Wrapper around paramiko for executing remote commands and SFTP."""

    def __init__(self, host: str, user: str, key_path: str, name: str = ""):
        self.host = host
        self.user = user
        self.key_path = os.path.expanduser(key_path)
        self.name = name or host
        self._client: paramiko.SSHClient | None = None
        self._channels_lock = threading.Lock()
        self._active_channels: set[paramiko.Channel] = set()

    def connect(self) -> None:
        log.debug("[%s] Connecting SSH %s@%s (key=%s)", self.name, self.user, self.host, self.key_path)
        self._client = paramiko.SSHClient()
        self._client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        self._client.connect(
            hostname=self.host,
            username=self.user,
            key_filename=self.key_path,
            timeout=_CONNECT_TIMEOUT,
            look_for_keys=False,
            allow_agent=False,
        )
        log.info("[%s] SSH connected to %s", self.name, self.host)

    def close(self) -> None:
        if self._client:
            self.cancel_active_commands()
            self._client.close()
            self._client = None
            log.debug("[%s] SSH disconnected", self.name)

    def cancel_active_commands(self) -> None:
        """Interrupt commands currently waiting on this SSH connection.

        Closing only their channels keeps the transport usable by the lifecycle
        cleanup that follows a cancelled node start.
        """
        with self._channels_lock:
            channels = list(self._active_channels)
        for channel in channels:
            try:
                channel.close()
            except Exception:
                log.debug("[%s] Failed to close active SSH channel", self.name, exc_info=True)

    def _track_channel(self, channel: paramiko.Channel) -> None:
        with self._channels_lock:
            self._active_channels.add(channel)

    def _untrack_channel(self, channel: paramiko.Channel) -> None:
        with self._channels_lock:
            self._active_channels.discard(channel)

    def run(self, command: str, timeout: int = _CMD_TIMEOUT, check: bool = True) -> str:
        """Execute a command and return stdout. Raises SSHError on non-zero exit if check=True."""
        if not self._client:
            raise RuntimeError(f"[{self.name}] SSH not connected")

        log.debug("[%s] exec: %s", self.name, command)
        _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        channel = stdout.channel
        self._track_channel(channel)
        try:
            rc = channel.recv_exit_status()
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
        finally:
            self._untrack_channel(channel)

        if rc != 0:
            log.warning("[%s] Command rc=%d: %s\n  stderr: %s", self.name, rc, command, err)
            if check:
                raise SSHError(self.host, command, err, rc)

        log.debug("[%s] result rc=%d out_len=%d", self.name, rc, len(out))
        return out

    def run_no_check(self, command: str, timeout: int = _CMD_TIMEOUT) -> tuple[int, str, str]:
        """Execute a command and return (rc, stdout, stderr) without raising."""
        if not self._client:
            raise RuntimeError(f"[{self.name}] SSH not connected")

        log.debug("[%s] exec (no_check): %s", self.name, command)
        _, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        channel = stdout.channel
        self._track_channel(channel)
        try:
            rc = channel.recv_exit_status()
            out = stdout.read().decode(errors="replace").strip()
            err = stderr.read().decode(errors="replace").strip()
        finally:
            self._untrack_channel(channel)
        return rc, out, err

    def upload_text(self, content: str, remote_path: str) -> None:
        """Write text content to a remote file via SFTP."""
        if not self._client:
            raise RuntimeError(f"[{self.name}] SSH not connected")

        log.debug("[%s] SFTP upload → %s (%d bytes)", self.name, remote_path, len(content))
        sftp = self._client.open_sftp()
        try:
            with sftp.file(remote_path, "w") as f:
                f.write(content)
        finally:
            sftp.close()

    def deploy_clab(
        self,
        topology_file: str,
        *,
        reconfigure: bool = False,
        cancel_event=None,
    ) -> str:
        """Run containerlab deploy and return output."""
        cmd = f"containerlab deploy -t {shlex.quote(topology_file)}"
        if reconfigure:
            cmd += " --reconfigure"
        if cancel_event is not None:
            return self._run_cancellable_deploy(
                cmd, topology_file, cancel_event, timeout=_DEPLOY_TIMEOUT,
            )
        return self.run(
            cmd,
            timeout=_DEPLOY_TIMEOUT,
        )

    def _run_cancellable_deploy(
        self, command: str, topology_file: str, cancel_event, *, timeout: int,
    ) -> str:
        if not self._client:
            raise RuntimeError(f"[{self.name}] SSH not connected")
        pid_file = f"{topology_file}.dnlab-deploy.pid"
        quoted_pid = shlex.quote(pid_file)
        wrapper = (
            f"rm -f {quoted_pid}; "
            f"{command} & child=$!; "
            f"printf '%s\\n' \"$child\" > {quoted_pid}; "
            f"wait \"$child\"; rc=$?; rm -f {quoted_pid}; exit $rc"
        )
        _, stdout, stderr = self._client.exec_command(wrapper, timeout=timeout)
        channel = stdout.channel
        deadline = time.monotonic() + timeout
        while not channel.exit_status_ready():
            if cancel_event.is_set():
                kill_cmd = (
                    f"if test -r {quoted_pid}; then "
                    f"pid=$(cat {quoted_pid}); kill -TERM \"$pid\" 2>/dev/null || true; "
                    "sleep 1; kill -KILL \"$pid\" 2>/dev/null || true; "
                    f"rm -f {quoted_pid}; fi"
                )
                _, kill_stdout, _ = self._client.exec_command(kill_cmd, timeout=5)
                kill_stdout.channel.recv_exit_status()
                channel.close()
                return ""
            if time.monotonic() >= deadline:
                channel.close()
                raise TimeoutError(f"[{self.name}] deploy command timed out")
            time.sleep(0.2)
        rc = channel.recv_exit_status()
        out = stdout.read().decode(errors="replace").strip()
        err = stderr.read().decode(errors="replace").strip()
        if rc != 0:
            raise SSHError(self.host, command, err, rc)
        return out

    def destroy_clab(self, topology_file: str) -> str:
        """Destroy one dNLab topology while retaining its shared mgmt network."""
        return self.run(
            f"containerlab destroy -t {shlex.quote(topology_file)} --cleanup --keep-mgmt-net",
            timeout=_DEPLOY_TIMEOUT,
            check=False,
        )

    def __enter__(self) -> SSHClient:
        self.connect()
        return self

    def __exit__(self, *exc) -> None:
        self.close()


def create_clients(hosts: dict) -> dict[str, SSHClient]:
    """Create SSHClient instances from host defs (InfraHost objects)."""
    from dnlab_multinode.models.topology import InfraHost
    clients = {}
    for name, host in hosts.items():
        clients[name] = SSHClient(
            host=host.host,
            user=host.ssh_user,
            key_path=host.ssh_key,
            name=name,
        )
    return clients
