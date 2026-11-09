"""Docker Engine and Linux namespace primitives; no Containerlab dependency."""

from __future__ import annotations

import hashlib
import http.client
import json
import os
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path
from urllib.parse import quote, urlencode
from contextlib import contextmanager

from .manifest import Conflict, RuntimeErrorBase, fingerprint

LABEL = "org.dnlab.runtime"


class UnixConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 30):
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


class Docker:
    def __init__(self, socket_path: str = "/var/run/docker.sock"):
        self.socket_path = socket_path

    def request(self, method: str, path: str, payload=None, *, missing_ok: bool = False):
        connection = UnixConnection(self.socket_path)
        try:
            body = json.dumps(payload).encode() if payload is not None else None
            connection.request(method, path, body=body, headers={"Content-Type": "application/json"})
            response = connection.getresponse()
            data = response.read()
            if response.status == 404 and missing_ok:
                return None
            if response.status >= 400:
                # Docker errors may echo env/command. Keep them out of operation status.
                raise RuntimeErrorBase(f"Docker {method} {path.split('?')[0]} returned HTTP {response.status}")
            return json.loads(data) if data else {}
        finally:
            connection.close()

    def inspect(self, name: str):
        return self.request("GET", f"/containers/{quote(name, safe='')}/json", missing_ok=True)

    def network(self, name: str):
        return self.request("GET", f"/networks/{quote(name, safe='')}")

    def create(self, name: str, config: dict):
        return self.request("POST", "/containers/create?" + urlencode({"name": name}), config)

    def start(self, container_id: str):
        return self.request("POST", f"/containers/{quote(container_id, safe='')}/start")

    def signal(self, container_id: str, signal: str):
        return self.request("POST", f"/containers/{quote(container_id, safe='')}/kill?" + urlencode({"signal": signal}))

    def remove(self, container_id: str):
        # Force is never implicit; volume deletion is never requested.
        return self.request("DELETE", f"/containers/{quote(container_id, safe='')}?force=false", missing_ok=True)

    def exec_checked(self, container_id: str, argv: list[str], *, timeout: float = 10):
        """Run a bounded, output-free helper tracked by Docker's exec API."""
        created = self.request("POST", f"/containers/{quote(container_id, safe='')}/exec", {
            "Cmd": argv, "User": "0", "AttachStdout": False, "AttachStderr": False,
        })
        identity = quote(created["Id"], safe="")
        self.request("POST", f"/exec/{identity}/start", {"Detach": True, "Tty": False})
        deadline = time.monotonic() + timeout
        while True:
            observed = self.request("GET", f"/exec/{identity}/json")
            if not observed["Running"]:
                if observed.get("ExitCode") != 0:
                    raise RuntimeErrorBase(f"container bootstrap helper failed (exec {created['Id']}, exit {observed.get('ExitCode')})")
                return created["Id"]
            if time.monotonic() >= deadline:
                raise RuntimeErrorBase("container bootstrap helper timed out; inspect the tracked Docker exec")
            time.sleep(0.05)

    def require_endpoint_name_support(self):
        version = self.request("GET", "/version").get("ApiVersion", "")
        parts = version.split(".")
        if len(parts) != 2 or not all(part.isdigit() for part in parts) or tuple(map(int, parts)) < (1, 49):
            raise RuntimeErrorBase("reserved management uplink requires Docker Engine API >= 1.49")

    def connect(self, network_id: str, container_id: str, ipv4: str, *, mac: str | None = None, interface_name: str | None = None):
        endpoint = {"IPAMConfig": {"IPv4Address": ipv4}}
        if mac is not None:
            endpoint["MacAddress"] = mac
        if interface_name is not None:
            endpoint["DriverOpts"] = {"com.docker.network.endpoint.ifname": interface_name}
        return self.request("POST", f"/networks/{quote(network_id, safe='')}/connect", {"Container": container_id, "EndpointConfig": endpoint})

    def disconnect(self, network_id: str, container_id: str):
        return self.request("POST", f"/networks/{quote(network_id, safe='')}/disconnect", {"Container": container_id, "Force": False})


class Namespace:
    def __init__(self, fd):
        self.fd = fd

    def __str__(self):
        return f"/proc/self/fd/{self.fd}"


class Linux:
    def namespace_identity(self, namespace):
        info=os.fstat(namespace.fd)
        return {'device':info.st_dev,'inode':info.st_ino}

    def network_identity(self):
        info = os.stat('/proc/self/ns/net')
        path = os.environ.get('DNLAB_RUNTIME_HOST_BOOT_ID_FILE', '/proc/sys/kernel/random/boot_id')
        if not os.path.isabs(path):
            raise Conflict('authoritative host boot ID path must be absolute')
        try:
            with open(path) as stream:
                boot = str(uuid.UUID(stream.read(128).strip()))
        except (OSError, ValueError) as error:
            raise Conflict('authoritative host boot ID unavailable or invalid') from error
        return {'boot_id': boot, 'device': info.st_dev, 'inode': info.st_ino}

    @contextmanager
    def namespace(self, pid: int):
        if type(pid) is not int or pid <= 0:
            raise Conflict("invalid container PID")
        fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
        try:
            yield Namespace(fd)
        finally:
            os.close(fd)

    def run(self, argv: list[str], *, pass_fds=()):
        result = subprocess.run(argv, capture_output=True, text=True, timeout=30, check=False, pass_fds=pass_fds)
        if result.returncode:
            raise RuntimeErrorBase(f"host primitive {argv[0]} failed with exit code {result.returncode}")
        return result.stdout

    def link(self, name: str, pid=None):
        prefix = ["nsenter", f"--net={pid}", "--"] if pid is not None else []
        # List and filter to distinguish missing from permission/subprocess errors.
        links = json.loads(self.run(prefix + ["ip", "-j", "-d", "link", "show"], pass_fds=(pid.fd,) if pid is not None else ()))
        result = next((x for x in links if x["ifname"] == name), None)
        if result and "link_index" not in result and "link" in result:
            peer = next((x for x in links if x["ifname"] == result["link"]), None)
            if peer:
                result["link_index"] = peer["ifindex"]
        return result

    def command(self, args: list[str], pid=None):
        prefix = ["nsenter", f"--net={pid}", "--"] if pid is not None else []
        return self.run(prefix + ["ip", *args], pass_fds=(pid.fd,) if pid is not None else ())

    def move(self, name, namespace):
        return self.run(["ip", "link", "set", name, "netns", str(namespace)], pass_fds=(namespace.fd,))

    def delete_link(self, expected):
        from .kernel_endpoint import signature
        payload={'context':self.network_identity(),'link':signature(expected)}
        result=json.loads(self.run([sys.executable,str(Path(__file__).with_name('kernel_endpoint.py')),json.dumps(payload)]))
        if result.get('status')=='conflict':raise Conflict(result['error'])
        if result.get('status') not in {'absent','deleted'} or result.get('ifindex')!=expected['ifindex']:
            raise RuntimeErrorBase('kernel endpoint deletion failed')


def labels(request: dict, spec: dict) -> dict:
    return {LABEL: "v1", LABEL + ".lab": request["lab_id"], LABEL + ".node": request["node_id"], LABEL + ".spec": fingerprint(spec)}


class Backend:
    def __init__(self, docker=None, linux=None, *, clock=time.monotonic, sleep=time.sleep):
        self.docker = docker or Docker()
        self.linux = linux or Linux()
        self.clock = clock
        self.sleep = sleep

    def owned(self, request: dict, spec: dict, container: dict):
        actual = container.get("Config", {}).get("Labels") or {}
        if any(actual.get(k) != v for k, v in labels(request, spec).items()):
            raise Conflict("container ownership/spec mismatch; refusing mutation")
        journal=getattr(self,'management_journal',None)
        if journal is not None:
            from .workload_generation import verify
            verify(journal,request,spec,container,LABEL)

    def inspect(self, request: dict, spec: dict):
        container = self.docker.inspect(spec["container_name"])
        if container:
            self.owned(request, spec, container)
        from .management_network import check
        check(self,request,spec,container)
        return container

    def create(self, request: dict, spec: dict, operation_id: str, *, initial_interface_name: str | None = None):
        container = self.inspect(request, spec)
        if container:
            return container
        from .endpoint_preflight import checkpoint
        checkpoint(self,request,spec,operation_id)
        from .management_authority import effective
        management = effective(getattr(self,'management_journal',None),request,spec)
        if initial_interface_name is not None and not management:
            raise Conflict('initial named endpoint requires a management network')
        networking = {}
        if management:
            network = self.docker.network(management["network"])
            if network.get("Driver") != "dnlab-vrf" or network.get("IPAM", {}).get("Driver") != "dnlab-vrf" or network.get("Labels", {}).get("io.dnlab.lab") != request["lab_id"] or network.get("Labels", {}).get("io.dnlab.managed") != "mgmt-vrf":
                raise Conflict("management network is not owned by the lab/dnlab-vrf")
            if management.get('network_id') and network.get('Id')!=management['network_id']:
                raise Conflict('restart management network identity differs')
            from .management_network import pin
            network=pin(self,request,spec,operation_id) or network
            ipv4 = management.get("ipv4", "")
            ipv6 = management.get("ipv6", "")
            networking = {"EndpointsConfig": {network["Id"]: {"IPAMConfig": {"IPv4Address": ipv4, "IPv6Address": ipv6}}}}
            if management.get('mac'):
                networking['EndpointsConfig'][network['Id']]['MacAddress']=management['mac']
            if initial_interface_name is not None:
                self.docker.require_endpoint_name_support()
                networking['EndpointsConfig'][network['Id']]['DriverOpts'] = {
                    'com.docker.network.endpoint.ifname': initial_interface_name}
        bindings = {}
        for port in spec.get("ports", []):
            key = f"{port['container_port']}/{port['protocol']}"
            bindings.setdefault(key, []).append({"HostIp": port["host_ip"], "HostPort": str(port["host_port"])})
        config = {
            "Image": spec["image"],
            "Env": [f"{k}={v}" for k, v in sorted(spec.get("env", {}).items())],
            "Labels": {**labels(request, spec), LABEL + ".creator": operation_id},
            "StopSignal": "SIGTERM",
            "ExposedPorts": {key: {} for key in bindings},
            "HostConfig": {"NetworkMode": network["Id"] if management else "none", "PortBindings": bindings, "RestartPolicy": {"Name": "no"}, "AutoRemove": False},
        }
        if "command" in spec:
            config["Cmd"] = spec["command"]
        if networking:
            config["NetworkingConfig"] = networking
        journal=getattr(self,'management_journal',None)
        if journal is not None:
            from .workload_generation import reserve,bind
            birth=reserve(journal,request,spec,operation_id)
            config['Labels'][LABEL+'.birth']=birth['nonce']
        checkpoint(self,request,spec,operation_id)
        response=self.docker.create(spec["container_name"], config)
        if journal is not None:
            bind(journal,request,spec,operation_id,response.get('Id') if isinstance(response,dict) else None)
        container = self.inspect(request, spec)
        if not container:
            raise RuntimeErrorBase("container missing after create")
        return container

    def start(self, request: dict, spec: dict):
        container = self.inspect(request, spec)
        if container is None:
            raise RuntimeErrorBase("container missing before start")
        if not container["State"]["Running"]:
            self.docker.start(container["Id"])
        container = self.inspect(request, spec)
        if not container or not container["State"]["Running"]:
            raise RuntimeErrorBase("container failed to reach running state")
        return container

    def stop(self, request: dict, spec: dict, *, force: bool = False):
        container = self.inspect(request, spec)
        if not container or not container["State"]["Running"]:
            return
        container_id = container["Id"]
        self.docker.signal(container_id, "SIGKILL" if force else "SIGTERM")
        deadline = self.clock() + spec.get("stop_timeout", 30)
        while True:
            observed = self.inspect(request, spec)
            if observed is None:
                raise Conflict("container disappeared while waiting for exit")
            if observed["Id"] != container_id:
                raise Conflict("container identity changed while waiting for exit")
            if not observed["State"]["Running"]:
                return
            if self.clock() >= deadline:
                raise RuntimeErrorBase("process exit timeout; no automatic SIGKILL was sent")
            self.sleep(0.1)

    def remove(self, request: dict, spec: dict):
        container = self.inspect(request, spec)
        if container:
            if container["State"]["Running"]:
                raise Conflict("refusing removal of running container")
            self.docker.remove(container["Id"])
        if self.docker.inspect(spec["container_name"]) is not None:
            raise Conflict("container still exists after removal")
        journal=getattr(self,'management_journal',None)
        if journal is not None:
            from .workload_generation import cleaned
            cleaned(journal,request,spec)

    @staticmethod
    def alias(request: dict, spec: dict):
        return "dnlab-runtime:" + fingerprint({"lab": request["lab_id"], "node": request["node_id"], "spec": fingerprint(spec)})

    @staticmethod
    def endpoint_macs(request, spec, endpoint):
        seed = fingerprint({"owner": Backend.alias(request, spec), "interface": endpoint["host_interface"]})
        host = "02:" + ":".join(seed[i:i+2] for i in range(0, 10, 2))
        peer = "02:" + ":".join(seed[i:i+2] for i in range(10, 20, 2))
        return host, peer

    @staticmethod
    def staging_name(endpoint):
        return "drp" + hashlib.sha256(endpoint["host_interface"].encode()).hexdigest()[:12]

    def owns_unlabelled_pair(self, request, spec, endpoint, host, peer):
        host_mac, peer_mac = self.endpoint_macs(request, spec, endpoint)
        return bool(host and peer and not host.get("ifalias") and host.get("address") == host_mac and peer.get("address") == peer_mac and host.get("link_index") == peer.get("ifindex") and peer.get("link_index") == host.get("ifindex"))

    @contextmanager
    def namespace(self, request: dict, spec: dict, container: dict):
        with self.linux.namespace(container["State"]["Pid"]) as namespace:
            fresh = self.inspect(request, spec)
            if not fresh or not fresh["State"]["Running"] or fresh["Id"] != container["Id"] or fresh["State"]["Pid"] != container["State"]["Pid"]:
                raise Conflict("container identity/PID changed before namespace operation")
            yield namespace

    def ensure_endpoint(self, request: dict, spec: dict, endpoint: dict):
        self._checkpoint_endpoints(request,spec)
        container = self.inspect(request, spec)
        if not container or not container["State"]["Running"]:
            raise Conflict("endpoint requires a running container")
        with self.namespace(request, spec, container) as namespace:
            self._ensure_endpoint(request, spec, endpoint, namespace)

    def _ensure_endpoint(self, request, spec, endpoint, pid):
        host, node = endpoint["host_interface"], endpoint["node_interface"]
        peer = self.staging_name(endpoint)
        alias = self.alias(request, spec)
        host_mac, peer_mac = self.endpoint_macs(request, spec, endpoint)
        existing = self.linux.link(host)
        if existing:
            if existing.get("ifalias") != alias:
                # The MAC pair is atomically assigned at creation. It proves
                # the recorded intent in the gap before setting ifalias.
                staging = self.linux.link(peer)
                if not self.owns_unlabelled_pair(request, spec, endpoint, existing, staging):
                    raise Conflict("host interface ownership mismatch")
        else:
            if self.linux.link(peer) or self.linux.link(node, pid):
                raise Conflict("endpoint peer name already occupied")
            self.linux.command(["link", "add", host, "address", host_mac, "type", "veth", "peer", "name", peer, "address", peer_mac])
            created, staging = self.linux.link(host), self.linux.link(peer)
            if not self.owns_unlabelled_pair(request, spec, endpoint, created, staging):
                raise Conflict("created endpoint identity mismatch")
        self._checkpoint_endpoints(request,spec)
        self.linux.command(["link", "set", host, "alias", alias])
        if self.linux.link(host).get("ifalias") != alias:
            raise Conflict("kernel did not apply endpoint ownership alias")
        guest = self.linux.link(node, pid)
        if guest is None:
            staging = self.linux.link(peer)
            # A crash after netns transfer but before rename is also recoverable.
            moved = self.linux.link(peer, pid)
            if staging:
                host_link = self.linux.link(host)
                if staging.get("link_index") != host_link.get("ifindex") or host_link.get("link_index") != staging.get("ifindex"):
                    raise Conflict("staging peer identity mismatch")
                self.linux.move(peer, pid)
            elif moved is None:
                raise Conflict("owned endpoint has no recoverable peer")
            elif moved.get("link_index") != self.linux.link(host).get("ifindex"):
                raise Conflict("moved peer identity mismatch")
            self.linux.command(["link", "set", peer, "name", node], pid)
        self._verify_pair(host, node, pid)
        for name, namespace in ((host, None), (node, pid)):
            self.linux.command(["link", "set", name, "mtu", str(endpoint.get("mtu", 1500))], namespace)
            self.linux.command(["link", "set", name, "up"], namespace)
        self._checkpoint_endpoints(request,spec)

    def _checkpoint_endpoints(self,request,spec):
        journal=getattr(self,'management_journal',None)
        if journal is None:return
        with journal.lock:
            row=journal.db.execute('SELECT id FROM operations WHERE lab=? AND request_id=?',
                (request['lab_id'],request['request_id'])).fetchone()
        if row:
            from .endpoint_preflight import checkpoint
            checkpoint(self,request,spec,row[0])

    def _verify_pair(self, host: str, node: str, pid: int):
        left, right = self.linux.link(host), self.linux.link(node, pid)
        if not left or not right or left.get("link_index") != right.get("ifindex") or right.get("link_index") != left.get("ifindex"):
            raise Conflict("endpoint peer identity mismatch")

    def delete_endpoints(self, request: dict, spec: dict):
        for endpoint in spec.get("endpoints", []):
            host = endpoint["host_interface"]
            current = self.linux.link(host)
            if current:
                if current.get("ifalias") != self.alias(request, spec):
                    staging = self.linux.link(self.staging_name(endpoint))
                    if not self.owns_unlabelled_pair(request, spec, endpoint, current, staging):
                        raise Conflict("refusing cleanup of foreign interface")
                try:
                    self.linux.delete_link(current)
                except Conflict:
                    raise
                except (RuntimeErrorBase, subprocess.SubprocessError, OSError):
                    # Container namespace teardown may remove this qualified veth
                    # after our read. Absence is success; never retry by name.
                    if self.linux.link(host) is not None:
                        raise
            if self.linux.link(host):
                raise Conflict("endpoint still exists after deletion")

    def verify(self, request: dict, spec: dict):
        container = self.inspect(request, spec)
        if not container or not container["State"]["Running"]:
            raise RuntimeErrorBase("container is not running")
        from .management_authority import effective
        management = effective(getattr(self,'management_journal',None),request,spec,container)
        if management:
            networks = container.get("NetworkSettings", {}).get("Networks", {})
            endpoint = networks.get(management["network"])
            if management.get('network_id') and (set(networks)!={management['network']} or not endpoint or endpoint.get('Gateway')!=management['gateway']):
                raise Conflict('current management attachment or gateway differs')
            if endpoint is not None and management.get('network_id') and endpoint.get('NetworkID')!=management['network_id']:
                raise Conflict('current management network identity differs')
            if endpoint is None:
                raise RuntimeErrorBase("management endpoint is missing")
            for wanted, actual in (("ipv4", "IPAddress"), ("ipv6", "GlobalIPv6Address")):
                if management.get(wanted) and endpoint.get(actual) != management[wanted]:
                    raise RuntimeErrorBase("management address mismatch")
        if spec.get("endpoints"):
            with self.namespace(request, spec, container) as namespace:
                for endpoint in spec["endpoints"]:
                    host = self.linux.link(endpoint["host_interface"])
                    if not host or host.get("ifalias") != self.alias(request, spec):
                        raise Conflict("endpoint ownership mismatch at verification")
                    self._verify_pair(endpoint["host_interface"], endpoint["node_interface"], namespace)
        actual_ports = container.get("NetworkSettings", {}).get("Ports", {})
        for port in spec.get("ports", []):
            key = f"{port['container_port']}/{port['protocol']}"
            binding = {"HostIp": port["host_ip"], "HostPort": str(port["host_port"])}
            if binding not in (actual_ports.get(key) or []):
                raise RuntimeErrorBase("published port mismatch")
        return container
