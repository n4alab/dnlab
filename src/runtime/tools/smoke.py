"""Opt-in, local native/image parity smoke. No mutations without --execute."""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

SOURCE = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(SOURCE))

from dnlab_runtime.backend import Backend
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.transport import Client


def command(argv):
    return subprocess.run(argv, check=True, capture_output=True, text=True, timeout=60).stdout.strip()


def wait_for(callback, timeout=20):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            value = callback()
            if value:
                return value
        except (OSError, RuntimeErrorBase):
            pass
        time.sleep(0.05)
    raise RuntimeError("smoke wait timed out")


def operation(client, identity, phase="completed"):
    result = wait_for(lambda: terminal(client.request("GET", f"/v1/operations/{identity}")))
    if result["phase"] != phase:
        raise RuntimeError(f"expected {phase}, got {result}")
    return result


def terminal(value):
    return value if value["phase"] in {"completed", "cancelled", "failed", "recovery_required"} else None


class Service:
    def __init__(self, mode, directory, image, token):
        self.mode, self.image = mode, image
        self.state, self.run = directory / "state", directory / "run"
        self.state.mkdir(mode=0o700)
        self.run.mkdir(mode=0o700)
        self.client = Client(str(self.run / "runtime.sock"))
        self.name = f"dnlab-runtime-spike-service-{mode}-{token}"
        self.process = self.identity = self.log = None

    def start(self):
        if self.mode == "native":
            self.log = (self.state.parent / "service.log").open("ab")
            self.process = subprocess.Popen([sys.executable, "-m", "dnlab_runtime.cli", "--socket", self.client.socket_path, "serve", "--state-dir", str(self.state)], env={**os.environ, "PYTHONPATH": str(SOURCE)}, stdout=self.log, stderr=self.log)
        else:
            self.identity = command(["docker", "run", "-d", "--name", self.name, "--label", "io.dnlab.spike=" + self.name, "--privileged", "--network", "host", "--pid", "host", "--mount", "type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock", "--mount", f"type=bind,src={self.state},dst=/var/lib/dnlab-runtime", "--mount", f"type=bind,src={self.run},dst=/run/dnlab-runtime", self.image])
        wait_for(lambda: self.client.request("GET", "/v1/capabilities"))

    def stop(self):
        if self.process:
            self.process.terminate()
            self.process.wait(timeout=35)
            self.process = None
            self.log.close()
            self.log = None
        if self.identity:
            observed = json.loads(command(["docker", "inspect", self.identity]))[0]
            if observed["Config"]["Labels"].get("io.dnlab.spike") != self.name:
                raise RuntimeError("service ownership mismatch")
            command(["docker", "stop", "--time", "30", self.identity])
            command(["docker", "rm", self.identity])
            self.identity = None


def probe(mode, root, image, runtime_image, token):
    directory = root / mode
    directory.mkdir(mode=0o700)
    service = Service(mode, directory, runtime_image, token)
    client = service.client
    spec = {"kind": "linux", "image": image, "container_name": f"dnlab-runtime-spike-{mode}-{token}", "command": ["python3", "-c", "import signal,sys,time; signal.signal(signal.SIGTERM, lambda *_: sys.exit(0)); print('READY',flush=True); time.sleep(3600)"], "stop_timeout": 1, "endpoints": [{"host_interface": "drsp" + mode[0] + token, "node_interface": "eth1", "mtu": 1500}]}
    start = {"schema_version": 1, "lab_id": f"spike-{mode}-{token}", "node_id": "linux1", "expected_revision": 0, "request_id": "start", "action": "start", "spec": spec}
    checks, ids = [], []
    backend = Backend()
    stubborn = None

    def submit(payload, wanted="completed"):
        result = client.request("POST", "/v1/operations", payload)
        ids.append(result["id"])
        return operation(client, result["id"], wanted)

    def ready():
        return wait_for(lambda: "READY" in command(["docker", "logs", spec["container_name"]]))

    def stop_payload(revision, identity):
        return {k: v for k, v in {**start, "action": "stop", "request_id": identity, "expected_revision": revision}.items() if k != "spec"}

    try:
        service.start()
        assert client.request("POST", "/v1/plan", start)["mutations_performed"] is False
        first = submit(start)
        ready()
        assert client.request("POST", "/v1/operations", start)["id"] == first["id"]
        assert client.request("GET", f"/v1/nodes/{start['lab_id']}/linux1")["container_state"] == "running"
        checks.append("native process + real namespace/veth + duplicate request")
        submit(stop_payload(1, "stop"))
        assert not backend.inspect(start, spec) and not backend.linux.link(spec["endpoints"][0]["host_interface"])
        checks.append("safe SIGTERM stop and verified container/endpoint absence")

        stubborn = {**start, "expected_revision": 2, "request_id": "stubborn", "spec": {**spec, "command": ["python3", "-c", "import signal,time; signal.signal(signal.SIGTERM,signal.SIG_IGN); print('READY',flush=True); time.sleep(3600)"]}}
        submit(stubborn)
        ready()
        timeout = submit(stop_payload(3, "timeout-stop"), "recovery_required")
        assert backend.inspect(stubborn, stubborn["spec"])["State"]["Running"]
        client.request("POST", f"/v1/operations/{timeout['id']}/reconcile", {"force": True})
        assert operation(client, timeout["id"])["recovery_force"]
        checks.append("SIGTERM timeout preserves process; explicit SIGKILL recovery")

        # Stage the exact crash point after create but before start/commit while
        # no daemon owns the journal, then restart the real service to replay it.
        service.stop()
        replay = {**start, "request_id": "replay", "expected_revision": 4}
        journal = Journal(service.state)
        try:
            staged = journal.submit(replay)
            journal.phase(staged["id"], "applying")
            # Use a journal-bound backend for the staged allocation; the
            # outer fixture backend intentionally remains a read/cleanup helper.
            from dnlab_runtime.engine import Engine
            staged_backend=Backend(backend.docker,backend.linux)
            Engine(journal,staged_backend)
            staged_backend.create(replay, spec, staged["id"])
        finally:
            journal.close()
        service.start()
        operation(client, staged["id"])
        ready()
        submit(stop_payload(5, "replay-stop"))
        checks.append("service restart replays a durable staged container create")

        service.stop()
        queued = {**start, "request_id": "cancel-queued", "expected_revision": 6}
        journal = Journal(service.state)
        try:
            staged = journal.submit(queued)
            journal.cancel(staged["id"])
        finally:
            journal.close()
        service.start()
        operation(client, staged["id"], "cancelled")
        assert not backend.inspect(start, spec)
        assert client.request("POST", "/v1/operations", start)["id"] == first["id"]
        checks.append("persisted queued cancellation and old-request deduplication after restart")
        return {"mode": mode, "checks": checks, "operation_ids": ids, "state_path": str(service.state), "status": "passed"}
    finally:
        service.stop()
        # Force is explicit for this isolated smoke's final cleanup only. Labels
        # and spec fingerprint are still checked before any workload mutation.
        observed = backend.docker.inspect(spec["container_name"])
        if observed:
            candidate = stubborn if stubborn and observed["Config"]["Labels"].get("org.dnlab.runtime.spec") == fingerprint(stubborn["spec"]) else start
            backend.stop(candidate, candidate["spec"], force=True)
            backend.delete_endpoints(candidate, candidate["spec"])
            backend.remove(candidate, candidate["spec"])
        link = backend.linux.link(spec["endpoints"][0]["host_interface"])
        if link:
            candidate = stubborn if stubborn and link.get("ifalias") == backend.alias(stubborn, stubborn["spec"]) else start
            backend.delete_endpoints(candidate, candidate["spec"])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--image", default="python:3.13-slim")
    parser.add_argument("--runtime-image", default="dnlab-runtime-spike:local")
    parser.add_argument("--mode", choices=("native", "image", "both"), default="both")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"mutations_performed": False, "planned_modes": args.mode, "creates": ["dedicated daemon", "native Python workload", "drsp veth", "state under /tmp"], "cleans": "only exact test-owned resources", "requires": "explicit --execute on an authorized isolated local host"}))
        return
    if os.geteuid() != 0:
        raise RuntimeError("live probe requires root")
    token = uuid.uuid4().hex[:8]
    root = Path(tempfile.mkdtemp(prefix="dnlab-runtime-smoke-"))
    baseline = set(command(["docker", "ps", "-aq"]).splitlines())
    image = command(["docker", "image", "inspect", "--format", "{{.Id}}", args.image])
    runtime_image = command(["docker", "image", "inspect", "--format", "{{.Id}}", args.runtime_image]) if args.mode != "native" else ""
    report = {"docker_version": command(["docker", "version", "--format", "{{.Server.Version}}"]), "kernel": command(["uname", "-r"]), "image_id": image, "runtime_image_id": runtime_image, "results": []}
    try:
        for mode in (["native", "image"] if args.mode == "both" else [args.mode]):
            report["results"].append(probe(mode, root, image, runtime_image, token))
        assert set(command(["docker", "ps", "-aq"]).splitlines()) == baseline, "container inventory changed after cleanup"
        report["cleanup_verified"] = True
    finally:
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(root / "report.json"), **report}, indent=2))


if __name__ == "__main__":
    main()
