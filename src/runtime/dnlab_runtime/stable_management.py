"""Experimental stable management datapath and durable endpoint handoff.

Not exposed by the production operation API: real NOS/dnlab-vrf qualification
is required first. The IPv4 probe deliberately rejects globally addressed IPv6.
"""

from __future__ import annotations

import ipaddress
import json
import re
import uuid

from .manifest import Conflict, NotFound, RuntimeErrorBase, canonical, fingerprint, identifier
from .endpoint_uplink import resolve_endpoint

BRIDGE = "dnlab-mgmt"
STABLE = "mgmt0"
PEER = "dmu0"
UPLINK_NAME = "dnmu0"


class StablePort:
    def __init__(self, backend, request, spec, mac):
        if not re.fullmatch(r"02(?::[0-9a-f]{2}){5}", mac):
            raise RuntimeErrorBase("probe requires a locally administered guest MAC")
        self.backend, self.request, self.spec, self.mac = backend, request, spec, mac
        self.owner = "dnlab-stable:" + fingerprint({"lab": request["lab_id"], "node": request["node_id"], "mac": mac})
        seed = fingerprint({"owner": self.owner})
        self.peer_mac = "02:" + ":".join(seed[i:i+2] for i in range(0, 10, 2))
        self.bridge_mac = "02:" + ":".join(seed[i:i+2] for i in range(10, 20, 2))

    def container(self):
        container = self.backend.inspect(self.request, self.spec)
        if not container or not container["State"]["Running"]:
            raise Conflict("stable management requires a running owned container")
        return container

    def _run(self, namespace, args):
        return self.backend.linux.command(args, namespace)

    def snapshot(self):
        container = self.container()
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            result = {"container_id": container["Id"], "pid": container["State"]["Pid"], "started_at": container["State"].get("StartedAt"), "links": {}}
            for name in (BRIDGE, STABLE, PEER):
                link = self.backend.linux.link(name, namespace)
                if not link or link.get("ifalias") != self.owner:
                    raise Conflict("stable management link ownership mismatch")
                result["links"][name] = {"ifindex": link["ifindex"], "address": link["address"]}
            return result

    def prepare(self, connection):
        container = self.container()
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            linux = self.backend.linux
            bridge = linux.link(BRIDGE, namespace)
            if bridge is None:
                self._run(namespace, ["link", "add", BRIDGE, "address", self.bridge_mac, "type", "bridge"])
                bridge = linux.link(BRIDGE, namespace)
            if bridge.get("address") != self.bridge_mac or bridge.get("linkinfo", {}).get("info_kind") != "bridge" or bridge.get("ifalias", "") not in ("", self.owner):
                raise Conflict("refusing to adopt foreign management bridge")
            self._run(namespace, ["link", "set", BRIDGE, "alias", self.owner])
            stable, peer = linux.link(STABLE, namespace), linux.link(PEER, namespace)
            if stable is None and peer is None:
                self._run(namespace, ["link", "add", STABLE, "address", self.mac, "type", "veth", "peer", "name", PEER, "address", self.peer_mac])
                stable, peer = linux.link(STABLE, namespace), linux.link(PEER, namespace)
            if not stable or not peer or stable.get("address") != self.mac or peer.get("address") != self.peer_mac or stable.get("link_index") != peer.get("ifindex") or peer.get("link_index") != stable.get("ifindex"):
                raise Conflict("stable management veth identity mismatch")
            for name, link in ((STABLE, stable), (PEER, peer)):
                if link.get("ifalias", "") not in ("", self.owner):
                    raise Conflict("foreign stable management interface")
                self._run(namespace, ["link", "set", name, "alias", self.owner])
            self._run(namespace, ["link", "set", PEER, "master", BRIDGE])
            for name in (BRIDGE, STABLE, PEER):
                self._run(namespace, ["link", "set", name, "up"])
        self.bind(connection)
        return self.snapshot()

    def uplink(self, connection, namespace=None):
        container = self.container()
        network = self.backend.docker.network(connection['network_id'])
        if namespace is None:
            with self.backend.namespace(self.request, self.spec, container) as ns:
                return self.uplink(connection, ns)
        host_links = json.loads(self.backend.linux.command(['-j', '-d', 'link', 'show']))
        links = json.loads(self.backend.linux.command(['-j', '-d', 'link', 'show'], namespace))
        return resolve_endpoint(network, container, connection, host_links, links)

    def check_uplink_name(self, connections):
        container = self.container()
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            occupied = self.backend.linux.link(UPLINK_NAME, namespace)
            if occupied is None:
                return
            endpoints = container["NetworkSettings"]["Networks"]
            attached = [connection for connection in connections if connection["network_name"] in endpoints]
            if len(attached) != 1:
                raise Conflict("reserved management uplink name is occupied")
            uplink = self.uplink(attached[0], namespace)
            if uplink["name"] != UPLINK_NAME or uplink["ifindex"] != occupied["ifindex"]:
                raise Conflict("reserved management uplink name belongs to another interface")

    def ensure_forwarding(self, namespace, uplink_name):
        # An endpoint with the guest MAC creates a bridge-local FDB entry.
        # Replace that owned entry with forwarding to the permanent peer.
        prefix = ["nsenter", f"--net={namespace}", "--", "bridge"]
        bridge = self.backend.linux.link(BRIDGE, namespace)
        if bridge.get("linkinfo", {}).get("info_kind") != "bridge" or bridge.get("linkinfo", {}).get("info_data", {}).get("vlan_filtering", 0):
            raise Conflict("stable guest forwarding requires the owned untagged bridge")
        rows = json.loads(self.backend.linux.run(prefix + ["-j", "fdb", "show", "br", BRIDGE], pass_fds=(namespace.fd,)))
        if any(row.get("mac") == self.mac and row.get("ifname") not in {uplink_name, PEER} for row in rows):
            raise Conflict("guest MAC collides with another bridge resource")
        self.backend.linux.run(prefix + ["fdb", "replace", self.mac, "dev", PEER, "master", "static"], pass_fds=(namespace.fd,))
        rows = json.loads(self.backend.linux.run(prefix + ["-j", "fdb", "show", "br", BRIDGE], pass_fds=(namespace.fd,)))
        forwarding = [row for row in rows if row.get("mac") == self.mac and not row.get("vlan")]
        if len(forwarding) != 1 or forwarding[0].get("ifname") != PEER or forwarding[0].get("state") != "static":
            raise Conflict("guest MAC is not forwarded to the stable management peer")

    def verify_uplink_mac(self, mac, connection):
        uplink = self.uplink(connection)
        if uplink['mac'] != mac:
            raise Conflict("kernel uplink MAC differs from stable guest MAC")
        return uplink

    def bind(self, connection, *, uplink=None):
        self.snapshot()  # Validate permanent link ownership before any mutation.
        container = self.container()
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            actual = self.uplink(connection, namespace)
            if uplink is not None and actual != uplink:
                raise Conflict('management endpoint changed before address relocation')
            name = actual['name']
            # Never expose an old address on the new segment. Docker's addresses
            # move to the stable interface; endpoint/IPAM metadata remains Docker's.
            self._run(namespace, ["-4", "addr", "flush", "dev", STABLE, "scope", "global"])
            self._run(namespace, ["-4", "addr", "flush", "dev", name, "scope", "global"])
            self._run(namespace, ["link", "set", name, "master", BRIDGE])
            self._run(namespace, ["link", "set", name, "up"])
            self.ensure_forwarding(namespace, name)
            self._run(namespace, ["addr", "replace", connection["cidr"], "dev", STABLE])
            self._run(namespace, ["route", "replace", "default", "via", connection["gateway"], "dev", STABLE])
            if self.uplink(connection, namespace) != actual:
                raise Conflict('management endpoint changed during address relocation')

    def clear_address(self):
        self.snapshot()
        container = self.container()
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            # A reconnect to the same CIDR otherwise conflicts with the connected
            # route left on mgmt0 when Docker programs the replacement eth0.
            self._run(namespace, ["-4", "addr", "flush", "dev", STABLE, "scope", "global"])
            self._run(namespace, ["-4", "route", "flush", "dev", STABLE])

    def verify(self, identity, connection):
        if self.snapshot() != identity:
            raise Conflict("container or stable guest-facing interface changed during move")
        container = self.container()
        with self.backend.namespace(self.request, self.spec, container) as namespace:
            output = self.backend.linux.run(["nsenter", f"--net={namespace}", "--", "ip", "-j", "addr", "show", "dev", STABLE], pass_fds=(namespace.fd,))
            addresses = json.loads(output)[0]["addr_info"]
            wanted = ipaddress.ip_interface(connection["cidr"])
            if not any(a.get("local") == str(wanted.ip) and a.get("prefixlen") == wanted.network.prefixlen for a in addresses):
                raise Conflict("stable management address mismatch")


class Handoff:
    """Recorded move/rollback; only one outstanding handoff per container."""

    def __init__(self, journal, backend, request, spec, port, *, spike_owner=None, name_probe=None):
        self.journal, self.backend = journal, backend
        self.request, self.spec, self.port = request, spec, port
        self.spike_owner = spike_owner
        self.name_probe = name_probe
        if name_probe is not None and getattr(name_probe, "journal", None) is journal:
            raise Conflict("endpoint capability probe requires a separate journal")
        from .management_authority import bind_backend
        bind_backend(backend,journal)
        with journal.transaction():
            journal.db.execute("""CREATE TABLE IF NOT EXISTS management_moves (
                id TEXT PRIMARY KEY, container_id TEXT NOT NULL, payload TEXT NOT NULL,
                phase TEXT NOT NULL, error TEXT NOT NULL DEFAULT '')""")
            journal.db.execute("""CREATE TABLE IF NOT EXISTS management_move_requests (
                lab TEXT NOT NULL, request_id TEXT NOT NULL, node TEXT NOT NULL,
                operation_id TEXT NOT NULL UNIQUE, PRIMARY KEY(lab,request_id))""")

    def network(self, name):
        network = self.backend.docker.network(name)
        labels = network.get("Labels") or {}
        if self.spike_owner:
            owned = network.get("Driver") == "bridge" and labels.get("io.dnlab.spike") == self.spike_owner
        else:
            owned = network.get("Driver") == "dnlab-vrf" and network.get("IPAM", {}).get("Driver") == "dnlab-vrf" and labels.get("io.dnlab.lab") == self.request["lab_id"] and labels.get("io.dnlab.managed") == "mgmt-vrf"
        if not owned:
            raise Conflict("management handoff network ownership mismatch")
        if network.get("EnableIPv6"):
            raise RuntimeErrorBase("IPv6 handoff is not implemented in this probe")
        return network

    def capture(self, network):
        container = self.port.container()
        endpoints = container["NetworkSettings"]["Networks"]
        if set(endpoints) != {network["Name"]}:
            raise Conflict("probe requires exactly one management Docker endpoint")
        endpoint = endpoints[network["Name"]]
        if endpoint.get("GlobalIPv6Address"):
            raise RuntimeErrorBase("globally addressed IPv6 is unsupported in this probe")
        return {"network_id": network["Id"], "network_name": network["Name"], "cidr": f"{endpoint['IPAddress']}/{endpoint['IPPrefixLen']}", "gateway": endpoint["Gateway"]}

    def submit(self, request_id, target_name, target_ip, *, expected_node_revision=None, lab_generation=1):
        with self.journal.execution_lock:
            return self._submit(request_id,target_name,target_ip,expected_node_revision=expected_node_revision,lab_generation=lab_generation)

    def _submit(self, request_id, target_name, target_ip, *, expected_node_revision,lab_generation):
        identifier(request_id,'request_id')
        lab=identifier(self.request['lab_id'],'lab_id')
        node=identifier(self.request['node_id'],'node_id')
        container = self.port.container()
        target = self.network(target_name)
        address = ipaddress.ip_address(target_ip)
        pools = [p for p in target["IPAM"]["Config"] if ipaddress.ip_network(p["Subnet"]).version == 4]
        if address.version != 4 or len(pools) != 1 or address not in ipaddress.ip_network(pools[0]["Subnet"]) or target_ip in {pools[0]["Gateway"], str(ipaddress.ip_network(pools[0]["Subnet"]).network_address), str(ipaddress.ip_network(pools[0]["Subnet"]).broadcast_address)}:
            raise RuntimeErrorBase("invalid target management IPv4 address")
        scope={'lab':lab,'node':node,'birth_fingerprint':fingerprint(self.spec)}
        intent = {"scope":scope,"target_id": target["Id"], "target_ip": target_ip, "container_id": container["Id"], "owner": self.port.owner}
        if expected_node_revision is not None:intent['expected_node_revision']=expected_node_revision
        digest = fingerprint(intent)
        with self.journal.transaction():
            existing = self.journal.db.execute("SELECT operation_id FROM management_move_requests WHERE lab=? AND request_id=?", (lab,request_id)).fetchone()
            if existing:
                previous=self.get(existing[0])
                if previous['payload']["intent"] != intent:
                    raise Conflict("handoff request_id already used with different content")
                return previous
            from .lab_closure import check
            check(self.journal,{'lab_id':lab,'lab_generation':lab_generation})
            busy = self.journal.db.execute("SELECT phase FROM management_moves WHERE container_id=?", (container["Id"],)).fetchall()
            if any(row[0] not in {"completed", "rolled_back", "rejected"} for row in busy):
                raise Conflict("container has an outstanding handoff")
            names = list(container["NetworkSettings"]["Networks"])
            if len(names) != 1 or names[0] == target_name:
                raise Conflict("handoff requires a different target and exactly one source endpoint")
            source = self.capture(self.network(names[0]))
            snapshot = self.port.snapshot()
            destination = {"network_id": target["Id"], "network_name": target["Name"], "cidr": f"{target_ip}/{ipaddress.ip_network(pools[0]['Subnet']).prefixlen}", "gateway": pools[0]["Gateway"]}
            from .management_authority import reserve
            operation_id=uuid.uuid4().hex
            binding=reserve(self,operation_id,container,source,expected_node_revision)
            observations = self.preflight([source, destination])
            payload = {"node_binding":binding,"capability_observations": observations, "uplink_name": UPLINK_NAME, "intent": intent, "source": source, "target": destination, "identity": snapshot, "fingerprint": digest}
            self.journal.db.execute("INSERT INTO management_moves VALUES(?,?,?,?,?)", (operation_id, container["Id"], canonical(payload), "queued", ""))
            self.journal.db.execute("INSERT INTO management_move_requests VALUES(?,?,?,?)", (lab,request_id,node,operation_id))
        return self.get(operation_id)

    def by_request(self, request_id):
        """Resolve an idempotency key only within this lab and VD context."""
        with self.journal.lock:
            row=self.journal.db.execute('SELECT operation_id FROM management_move_requests WHERE lab=? AND request_id=?',
                                        (self.request['lab_id'],request_id)).fetchone()
        if row is None:raise NotFound('handoff request not found')
        return self.get(row[0])

    def get(self, identity):
        with self.journal.lock:
            row = self.journal.db.execute("SELECT * FROM management_moves WHERE id=?", (identity,)).fetchone()
        if row is None:
            raise NotFound("handoff not found")
        result = dict(row)
        result["payload"] = json.loads(result["payload"])
        scope={'lab':self.request['lab_id'],'node':self.request['node_id'],'birth_fingerprint':fingerprint(self.spec)}
        if result['payload']['intent'].get('scope')!=scope or result['payload']['intent']['owner']!=self.port.owner:
            raise Conflict('handoff lab/node or birth ownership mismatch; unqualified legacy operations are not adopted')
        with self.journal.lock:
            request=self.journal.db.execute('SELECT request_id,node FROM management_move_requests WHERE lab=? AND operation_id=?',
                                            (self.request['lab_id'],identity)).fetchone()
        if request is None or request['node']!=self.request['node_id']:raise Conflict('handoff request ownership missing')
        result['request_id']=request['request_id']
        return result

    def phase(self, identity, phase, error=""):
        with self.journal.transaction():
            move=self.get(identity)
            if phase in ('completed','rolled_back','rejected'):
                from .management_authority import finish
                payload=move['payload']
                finish(self.journal,identity,payload,phase)
            self.journal.db.execute("UPDATE management_moves SET phase=?,error=? WHERE id=?", (phase, error, identity))

    def preflight(self, connections):
        self.backend.docker.require_endpoint_name_support()
        self.port.check_uplink_name(connections)
        if not self.spike_owner:
            if self.name_probe is None:
                raise Conflict("remote endpoint naming requires a live native capability probe")
            observations = []
            for connection in connections:
                network = self.network(connection['network_id'])
                observed = self.name_probe.check(network, UPLINK_NAME)
                if observed.get('network_id') != network['Id'] or observed.get('name') != UPLINK_NAME or observed.get('cleanup_verified') is not True or not observed.get('canary_container_id') or observed['canary_container_id'] == self.port.container()['Id']:
                    raise Conflict("invalid remote endpoint naming capability observation")
                observations.append(observed)
            return observations
        return []

    def ensure_connection(self, connection, identity, *, operation_id):
        self.get(operation_id)
        container = self.port.container()
        if self.port.snapshot() != identity:
            raise Conflict("stable port or container identity changed")
        network = self.network(connection["network_id"])
        if network["Id"] != connection["network_id"]:
            raise Conflict("network identity changed")
        endpoints = container["NetworkSettings"]["Networks"]
        if any(name != connection["network_name"] for name in endpoints):
            raise Conflict("unexpected extra endpoint; refusing connection")
        if connection["network_name"] not in endpoints:
            self.port.clear_address()
            self.backend.docker.connect(connection["network_id"], container["Id"], str(ipaddress.ip_interface(connection["cidr"]).ip), mac=identity["links"][STABLE]["address"], interface_name=UPLINK_NAME)
        endpoint = self.port.container()["NetworkSettings"]["Networks"].get(connection["network_name"], {})
        mac = identity["links"][STABLE]["address"]
        if endpoint.get("MacAddress", "").lower() != mac:
            raise Conflict("Docker endpoint did not retain the stable guest MAC")
        uplink = self.port.verify_uplink_mac(mac, connection)
        if uplink['name'] != UPLINK_NAME:
            raise Conflict("Docker endpoint did not use the reserved management uplink name")
        with self.journal.transaction():
            row = self.journal.db.execute('SELECT payload FROM management_moves WHERE id=?', (operation_id,)).fetchone()
            payload = json.loads(row[0])
            payload.setdefault('endpoint_observations', {})[connection['network_id']] = uplink
            self.journal.db.execute('UPDATE management_moves SET payload=? WHERE id=?', (canonical(payload), operation_id))
        self.port.bind(connection, uplink=uplink)
        self.port.verify(identity, connection)
        actual = self.capture(network)
        if actual != connection:
            raise Conflict("Docker endpoint metadata differs from handoff intent")

    def execute(self, request_id, *, checkpoint=lambda phase: None):
        with self.journal.management_execution_lock:
            return self._execute(request_id, checkpoint=checkpoint)

    def _execute(self, request_id, *, checkpoint):
        move = self.get(request_id)
        if move["phase"] in {"completed", "rolled_back", "rejected"}:
            return move
        payload = move["payload"]
        identity = payload["identity"]
        if payload["intent"]["owner"] != self.port.owner:
            raise Conflict("handoff owner mismatch")
        try:
            from .management_authority import check
            check(self,payload,request_id)
        except RuntimeErrorBase as exc:
            self.phase(request_id,'recovery_required',str(exc))
            return self.get(request_id)
        # Recheck before any mutation. A queued rejection needs no compensation:
        # its original endpoint and guest address are still intact.
        try:
            if payload.get("uplink_name") != UPLINK_NAME:
                raise Conflict("handoff lacks the qualified uplink naming policy")
            observations = self.preflight([payload["source"], payload["target"]])
            if observations:
                with self.journal.transaction():
                    payload['capability_observations'] = observations
                    self.journal.db.execute('UPDATE management_moves SET payload=? WHERE id=?', (canonical(payload), request_id))
        except RuntimeErrorBase as exc:
            if move["phase"] == "queued":
                self.phase(request_id, "rejected", str(exc))
                return self.get(request_id)
            raise
        try:
            if move["phase"] in {"rolling_back", "recovery_required"}:
                self.rollback(request_id)
                return self.get(request_id)
            if self.port.snapshot() != identity:
                raise Conflict("stable identity changed before handoff")
            self.network(payload["source"]["network_id"])
            self.network(payload["target"]["network_id"])
            container = self.port.container()
            endpoints = container["NetworkSettings"]["Networks"]
            expected = {payload["source"]["network_name"], payload["target"]["network_name"]}
            if set(endpoints) - expected or len(endpoints) > 1:
                raise Conflict("unexpected management attachment")
            self.phase(request_id, "detaching")
            if payload["source"]["network_name"] in endpoints:
                self.backend.docker.disconnect(payload["source"]["network_id"], container["Id"])
            checkpoint("detached")
            self.phase(request_id, "connecting")
            self.ensure_connection(payload["target"], identity, operation_id=request_id)
            checkpoint("connected")
            self.phase(request_id, "completed")
        except Exception as exc:
            error = str(exc) if isinstance(exc, RuntimeErrorBase) else f"handoff failed ({type(exc).__name__})"
            self.phase(request_id, "rolling_back", error)
            self.rollback(request_id)
        return self.get(request_id)

    def rollback(self, request_id):
        with self.journal.execution_lock:return self._rollback(request_id)

    def _rollback(self, request_id):
        move = self.get(request_id)
        if move['phase'] in {'completed','rolled_back','rejected'}:return move
        payload = move["payload"]
        try:
            from .management_authority import check
            check(self,payload,request_id)
            if self.port.snapshot() != payload["identity"]:
                raise Conflict("stable identity changed before rollback")
            self.preflight([payload["source"], payload["target"]])
            container = self.port.container()
            endpoints = container["NetworkSettings"]["Networks"]
            if set(endpoints) - {payload["source"]["network_name"], payload["target"]["network_name"]} or len(endpoints) > 1:
                raise Conflict("unexpected endpoint before rollback")
            if payload["target"]["network_name"] in endpoints:
                self.network(payload["target"]["network_id"])
                self.backend.docker.disconnect(payload["target"]["network_id"], container["Id"])
            self.ensure_connection(payload["source"], payload["identity"], operation_id=request_id)
            self.phase(request_id, "rolled_back", move["error"])
        except Exception as exc:
            error = str(exc) if isinstance(exc, RuntimeErrorBase) else type(exc).__name__
            self.phase(request_id, "recovery_required", move["error"] + "; rollback: " + error)
