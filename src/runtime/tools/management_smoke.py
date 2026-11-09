"""Opt-in IPv4 stable-interface probe, with a Linux namespace guest analogue."""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import socket
import sys
import tempfile
import urllib.request
import uuid
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from dnlab_runtime.backend import Backend, labels
from dnlab_runtime.journal import Journal
from dnlab_runtime.stable_management import Handoff, StablePort, STABLE
from smoke import command, wait_for


def available_port():
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        return probe.getsockname()[1]


def fixture(token, node, name, image, port):
    program = "import http.server,signal,time; born=time.time(); signal.signal(signal.SIGTERM,lambda *_:exit(0)); "
    program += "exec(\"class Handler(http.server.BaseHTTPRequestHandler):\\n def do_GET(self):\\n  body=('" + node + " '+str(born)).encode(); self.send_response(200); self.end_headers(); self.wfile.write(body)\\n def log_message(self,*args): pass\"); "
    program += f"http.server.HTTPServer(('0.0.0.0',{port}),Handler).serve_forever()"
    spec = {"kind": "linux", "image": image, "container_name": name, "command": ["python3", "-c", program], "stop_timeout": 3}
    request = {"lab_id": token, "node_id": node}
    return request, spec


def response(url):
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(url, timeout=2) as result:
        return result.read().decode()


def run(image):
    token = "mgsp-" + uuid.uuid4().hex[:8]
    root = Path(tempfile.mkdtemp(prefix="dnlab-management-smoke-"))
    backend = Backend()
    journal = Journal(root / "state")
    networks, containers = [], []
    report = {"scope": "IPv4 Linux guest analogue; not NOS/dnlab-vrf qualification", "image_id": image, "checks": []}
    main_request, main_spec = fixture(token, "vd", f"dnlab-{token}-vd", image, 5000)
    guest_request, guest_spec = fixture(token, "guest", f"dnlab-{token}-guest", image, 8000)
    try:
        for color in ("blue", "red"):
            name = f"dnlab-{token}-{color}"
            network_id = command(["docker", "network", "create", "--driver", "bridge", "--label", "io.dnlab.spike=" + token, name])
            networks.append(backend.docker.network(network_id))
        host_ports = {5000: available_port(), 8000: available_port()}
        assert len(set(host_ports.values())) == 2
        bindings = {f"{port}/tcp": [{"HostIp": "127.0.0.1", "HostPort": str(host_ports[port])}] for port in host_ports}
        for request, spec, network in ((main_request, main_spec, networks[0]["Name"]), (guest_request, guest_spec, "none")):
            config = {"Image": image, "Cmd": spec["command"], "Labels": {**labels(request, spec), "io.dnlab.spike": token}, "HostConfig": {"NetworkMode": network, "RestartPolicy": {"Name": "no"}}}
            if request is main_request:
                config["ExposedPorts"] = {key: {} for key in bindings}
                config["HostConfig"]["PortBindings"] = bindings
            created = backend.docker.create(spec["container_name"], config)
            containers.append((request, spec, created["Id"]))
            backend.docker.start(created["Id"])
        port = StablePort(backend, main_request, main_spec, "02:da:ab:00:00:01")
        handoff = Handoff(journal, backend, main_request, main_spec, port, spike_owner=token)
        source = handoff.capture(networks[0])
        identity = port.prepare(source)
        main = port.container()
        guest = backend.inspect(guest_request, guest_spec)
        guest_identity = {"Id": guest["Id"], "Pid": guest["State"]["Pid"], "StartedAt": guest["State"]["StartedAt"]}
        with backend.namespace(main_request, main_spec, main) as main_ns, backend.namespace(guest_request, guest_spec, guest) as guest_ns:
            linux = backend.linux
            linux.command(["link", "add", "tap0", "type", "veth", "peer", "name", "gdata0"], main_ns)
            linux.run(["nsenter", f"--net={main_ns}", "--", "ip", "link", "set", "gdata0", "netns", str(guest_ns)], pass_fds=(main_ns.fd, guest_ns.fd))
            linux.command(["link", "set", "tap0", "up"], main_ns)
            linux.command(["link", "set", "gdata0", "address", port.mac], guest_ns)
            linux.command(["link", "set", "gdata0", "up"], guest_ns)
            guest_link = linux.link("gdata0", guest_ns)
            for args in (["qdisc", "add", "dev", STABLE, "clsact"], ["filter", "add", "dev", STABLE, "ingress", "prio", "1", "protocol", "ip", "flower", "ip_proto", "tcp", "dst_port", "5000-5007", "action", "pass"], ["filter", "add", "dev", STABLE, "ingress", "prio", "2", "protocol", "arp", "flower", "action", "mirred", "egress", "mirror", "dev", "tap0"], ["filter", "add", "dev", STABLE, "ingress", "prio", "3", "flower", "action", "csum", "ip", "and", "tcp", "and", "udp", "and", "icmp", "pipe", "action", "mirred", "egress", "redirect", "dev", "tap0"], ["qdisc", "add", "dev", "tap0", "clsact"], ["filter", "add", "dev", "tap0", "ingress", "flower", "action", "mirred", "egress", "redirect", "dev", STABLE]):
                linux.run(["nsenter", f"--net={main_ns}", "--", "tc", *args], pass_fds=(main_ns.fd,))
            # Suppress the container's duplicate-IP ARP response, as vrnetlab does.
            linux.run(["nsenter", f"--net={main_ns}", "--", "sysctl", "-qw", f"net.ipv4.conf.{STABLE}.arp_ignore=8"], pass_fds=(main_ns.fd,))

        def configure_guest(connection):
            observed = backend.inspect(guest_request, guest_spec)
            assert {"Id": observed["Id"], "Pid": observed["State"]["Pid"], "StartedAt": observed["State"]["StartedAt"]} == guest_identity
            with backend.namespace(guest_request, guest_spec, observed) as ns:
                assert backend.linux.link("gdata0", ns)["ifindex"] == guest_link["ifindex"]
                assert backend.linux.link("gdata0", ns)["address"] == guest_link["address"]
                backend.linux.command(["-4", "addr", "flush", "dev", "gdata0", "scope", "global"], ns)
                backend.linux.command(["addr", "replace", connection["cidr"], "dev", "gdata0"], ns)
                backend.linux.command(["route", "replace", "default", "via", connection["gateway"], "dev", "gdata0"], ns)

        def check_traffic(connection, expected=None):
            ip = str(ipaddress.ip_interface(connection["cidr"]).ip)
            # Each response includes a boot timestamp; unchanged values prove the
            # same processes answered after handoff instead of restarted replicas.
            values = [wait_for(lambda: response(url)) for url in (f"http://{ip}:5000", f"http://{ip}:8000", f"http://127.0.0.1:{host_ports[5000]}", f"http://127.0.0.1:{host_ports[8000]}")]
            if expected is not None:
                assert values == expected, (values, expected)
            assert values[0].startswith("vd ") and values[1].startswith("guest ")
            return values

        configure_guest(source)
        before = check_traffic(source)
        report["checks"].append("initial container console + guest TCP datapath + fixed published ports")
        target_pool = ipaddress.ip_network(networks[1]["IPAM"]["Config"][0]["Subnet"])
        target_ip = str(target_pool.network_address + 10)
        handoff.submit("move", networks[1]["Name"], target_ip)
        moved = handoff.execute(handoff.by_request("move")['id'])
        assert moved["phase"] == "completed", moved
        configure_guest(moved["payload"]["target"])  # Explicit manual guest IP change.
        check_traffic(moved["payload"]["target"], before)
        assert port.snapshot() == identity
        report["checks"].append("Docker endpoint move preserves stable interface/MAC/PID and guest TCP/console/ports")

        old_ip = str(ipaddress.ip_interface(source["cidr"]).ip)
        handoff.submit("rollback", networks[0]["Name"], old_ip)
        def fail_after_detach(phase):
            if phase == "detached":
                raise RuntimeError("injected connection failure")
        rolled = handoff.execute(handoff.by_request("rollback")['id'], checkpoint=fail_after_detach)
        assert rolled["phase"] == "rolled_back", rolled
        check_traffic(rolled["payload"]["source"], before)
        report["checks"].append("injected detach failure restores network/address without guest or stable-port restart")
        report["stable_identity"] = identity
        report["status"] = "passed"
    finally:
        for request, spec, identity in reversed(containers):
            backend.stop(request, spec, force=True)
            backend.remove(request, spec)
        for network in reversed(networks):
            observed = backend.docker.network(network["Id"])
            assert observed["Labels"].get("io.dnlab.spike") == token
            assert not observed.get("Containers")
            backend.docker.request("DELETE", "/networks/" + network["Id"])
        journal.close()
        report["cleanup_verified"] = True
        (root / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        print(json.dumps({"report": str(root / "report.json"), **report}, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--image", default="python:3.13-slim")
    args = parser.parse_args()
    if not args.execute:
        print(json.dumps({"mutations_performed": False, "creates": ["two isolated bridge networks", "two native Python containers", "stable veth/bridge inside VD namespace", "tc redirect to Linux guest analogue"], "checks": ["TCP traffic", "console exception", "fixed published ports", "live move", "rollback", "PID/MAC/interface continuity"]}))
        return
    if os.geteuid() != 0:
        raise RuntimeError("management probe requires root")
    image = command(["docker", "image", "inspect", "--format", "{{.Id}}", args.image])
    run(image)


if __name__ == "__main__":
    main()
