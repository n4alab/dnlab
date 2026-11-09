from copy import deepcopy
import ipaddress

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase
from dnlab_runtime.stable_management import Handoff


class NetworkDocker:
    def __init__(self):
        self.networks = {name: {"Name": name, "Id": name, "Driver": "bridge", "Labels": {"io.dnlab.spike": "test"}, "IPAM": {"Config": [{"Subnet": subnet, "Gateway": gateway}]}} for name, subnet, gateway in [("blue", "192.0.2.0/24", "192.0.2.1"), ("red", "198.51.100.0/24", "198.51.100.1")]}
        self.endpoints = {"blue": self.endpoint("blue", "192.0.2.2")}
        self.calls = []
        self.failure = None
        self.stable_prefix = "192.0.2.0/24"

    def endpoint(self, network, ip):
        pool = self.networks[network]["IPAM"]["Config"][0]
        return {"NetworkID":self.networks[network]["Id"],"IPAddress": ip, "IPPrefixLen": 24, "Gateway": pool["Gateway"], "MacAddress": "02:00:00:00:00:01"}

    def network(self, name):
        return deepcopy(self.networks[name])

    def connect(self, network, container, ip, *, mac=None, interface_name=None):
        self.calls.append(("connect", network))
        if self.failure == network:
            raise RuntimeErrorBase("connect failed")
        assert not self.endpoints, "source must be detached before target connect"
        if self.stable_prefix == self.networks[network]["IPAM"]["Config"][0]["Subnet"]:
            raise RuntimeErrorBase("connected route already exists on stable interface")
        self.endpoints[network] = self.endpoint(network, ip)
        self.endpoints[network]["MacAddress"] = mac

    def require_endpoint_name_support(self):
        pass

    def disconnect(self, network, container):
        self.calls.append(("disconnect", network))
        del self.endpoints[network]


class Port:
    owner = "owned-port"

    def __init__(self, docker):
        self.docker = docker
        self.identity = {"container_id": "vd", "pid": 100, "links": {"mgmt0": {"ifindex": 4, "address": "02:00:00:00:00:01"}}}
        self.connection = None
        self.fail_bind = False

    def container(self):
        return {"Id": "vd", "State": {"Running": True, "Pid": self.identity["pid"]}, "NetworkSettings": {"Networks": deepcopy(self.docker.endpoints)}}

    def snapshot(self):
        return deepcopy(self.identity)

    def check_uplink_name(self, connections):
        pass

    def verify_uplink_mac(self, mac, connection):
        assert mac == self.identity["links"]["mgmt0"]["address"]
        return {'network_id': connection['network_id'], 'endpoint_id': 'fake-endpoint', 'name': 'dnmu0', 'ifindex': 8, 'peer_name': 'fake-peer', 'peer_ifindex': 9, 'mac': mac}

    def bind(self, connection, *, uplink=None):
        if self.fail_bind and connection["network_name"] == "red":
            raise RuntimeErrorBase("address relocation failed")
        self.connection = connection
        self.docker.stable_prefix = str(ipaddress.ip_interface(connection["cidr"]).network)

    def clear_address(self):
        self.connection = None
        self.docker.stable_prefix = None

    def verify(self, identity, connection):
        assert identity == self.identity
        assert self.connection == connection


@pytest.fixture
def transfer(tmp_path):
    journal = Journal(tmp_path / "state")
    docker = NetworkDocker()
    port = Port(docker)
    backend = type("Backend", (), {"docker": docker})()
    handoff = Handoff(journal, backend, {"lab_id": "lab", "node_id": "R1"}, {}, port, spike_owner="test")
    yield handoff, port, docker, journal
    journal.close()


def test_move_preserves_identity_and_has_no_dual_connection(transfer):
    handoff, port, docker, _ = transfer
    identity = port.snapshot()
    handoff.submit("move", "red", "198.51.100.2")
    result = handoff.execute(handoff.by_request("move")['id'])
    assert result["phase"] == "completed"
    assert result['payload']['endpoint_observations']['red']['name'] == 'dnmu0'
    assert port.snapshot() == identity
    assert docker.calls == [("disconnect", "blue"), ("connect", "red")]
    assert set(docker.endpoints) == {"red"}
    assert handoff.execute(handoff.by_request("move")['id'])["phase"] == "completed"
    assert len(docker.calls) == 2


def test_request_deduplication_and_conflicting_content(transfer):
    handoff, _, _, _ = transfer
    original = handoff.submit("move", "red", "198.51.100.2")
    assert handoff.submit("move", "red", "198.51.100.2") == original
    with pytest.raises(Conflict, match="different content"):
        handoff.submit("move", "red", "198.51.100.3")
    with pytest.raises(Conflict, match="outstanding"):
        handoff.submit("another", "red", "198.51.100.3")


@pytest.mark.parametrize("address", ["198.51.100.1", "198.51.100.0", "198.51.100.255", "192.0.2.2", "2001:db8::1"])
def test_invalid_address_rejected_before_detach(transfer, address):
    handoff, _, docker, _ = transfer
    with pytest.raises(RuntimeErrorBase):
        handoff.submit("move", "red", address)
    assert docker.calls == []


@pytest.mark.parametrize("phase", ["detached", "connected"])
def test_restart_replays_move_from_side_effect_crash_point(transfer, phase):
    handoff, port, docker, journal = transfer
    handoff.submit("move", "red", "198.51.100.2")
    def crash(step):
        if step == phase:
            raise SystemExit("daemon died")
    with pytest.raises(SystemExit):
        handoff.execute(handoff.by_request("move")['id'], checkpoint=crash)
    restored = Handoff(journal, handoff.backend, handoff.request, {}, port, spike_owner="test")
    assert restored.execute(restored.by_request("move")['id'])["phase"] == "completed"
    assert docker.calls.count(("connect", "red")) == 1
    assert set(docker.endpoints) == {"red"}


@pytest.mark.parametrize("failure", ["connect", "bind"])
def test_failure_restores_old_network_address_and_interface(transfer, failure):
    handoff, port, docker, _ = transfer
    handoff.submit("move", "red", "198.51.100.2")
    if failure == "connect":
        docker.failure = "red"
    else:
        port.fail_bind = True
    result = handoff.execute(handoff.by_request("move")['id'])
    assert result["phase"] == "rolled_back"
    assert set(docker.endpoints) == {"blue"}
    assert port.connection["cidr"] == "192.0.2.2/24"
    assert port.snapshot() == result["payload"]["identity"]


def test_failure_of_rollback_retains_recovery_intent(transfer):
    handoff, port, docker, _ = transfer
    handoff.submit("move", "red", "198.51.100.2")
    port.fail_bind = True
    docker.failure = "blue"
    assert handoff.execute(handoff.by_request("move")['id'])["phase"] == "recovery_required"
    docker.failure = None
    assert handoff.execute(handoff.by_request("move")['id'])["phase"] == "rolled_back"
    assert set(docker.endpoints) == {"blue"}


def test_foreign_network_is_never_attached(transfer):
    handoff, _, docker, _ = transfer
    docker.networks["red"]["Labels"]["io.dnlab.spike"] = "other"
    with pytest.raises(Conflict, match="ownership"):
        handoff.submit("move", "red", "198.51.100.2")
    assert docker.calls == []


def test_changed_container_identity_blocks_both_move_and_unsafe_rollback(transfer):
    handoff, port, docker, _ = transfer
    handoff.submit("move", "red", "198.51.100.2")
    port.identity["pid"] = 200
    assert handoff.execute(handoff.by_request("move")['id'])["phase"] == "recovery_required"
    assert docker.calls == []


def test_unexpected_second_endpoint_is_not_removed(transfer):
    handoff, _, docker, _ = transfer
    handoff.submit("move", "red", "198.51.100.2")
    docker.endpoints["unowned"] = {}
    assert handoff.execute(handoff.by_request("move")['id'])["phase"] == "recovery_required"
    assert "unowned" in docker.endpoints and docker.calls == []


def test_connect_requests_same_mac_on_move_and_rollback(transfer):
    handoff, port, docker, _ = transfer
    seen = []
    original = docker.connect
    def connect(network, container, ip, *, mac=None, interface_name=None):
        seen.append((network, mac))
        return original(network, container, ip, mac=mac, interface_name=interface_name)
    docker.connect = connect
    handoff.submit("move", "red", "198.51.100.2")
    port.fail_bind = True
    assert handoff.execute(handoff.by_request("move")['id'])["phase"] == "rolled_back"
    assert seen == [("red", "02:00:00:00:00:01"), ("blue", "02:00:00:00:00:01")]


def test_driver_ignoring_requested_mac_cannot_complete_handoff(transfer):
    handoff, _, docker, _ = transfer
    original = docker.connect
    def connect(network, container, ip, *, mac=None, interface_name=None):
        original(network, container, ip, mac="02:00:00:00:00:99" if network == "red" else mac, interface_name=interface_name)
    docker.connect = connect
    handoff.submit("move", "red", "198.51.100.2")
    assert handoff.execute(handoff.by_request("move")['id'])["phase"] == "rolled_back"
    assert set(docker.endpoints) == {"blue"}


def test_docker_mac_request_is_optional_for_other_callers():
    from dnlab_runtime.backend import Docker
    docker = Docker()
    calls = []
    docker.request = lambda method, path, payload: calls.append(payload)
    docker.connect("network", "container", "192.0.2.2", mac="02:00:00:00:00:01")
    docker.connect("network", "container", "192.0.2.2")
    assert calls[0]["EndpointConfig"]["MacAddress"] == "02:00:00:00:00:01"
    assert "MacAddress" not in calls[1]["EndpointConfig"]


@pytest.mark.parametrize('mode', ['success', 'local-entry-retained', 'foreign-mac'])
def test_fdb_must_forward_guest_mac_without_overwriting_other_resources(mode):
    import json
    from types import SimpleNamespace
    from dnlab_runtime.stable_management import StablePort
    mac = '02:00:00:00:00:01'
    calls = []
    before = [{'mac': mac, 'ifname': 'eth1' if mode == 'foreign-mac' else 'eth17', 'state': 'permanent'}]
    after = [{'mac': mac, 'ifname': 'eth17' if mode == 'local-entry-retained' else 'dmu0', 'state': 'permanent' if mode == 'local-entry-retained' else 'static'}]
    def run(args, **kwargs):
        calls.append(args)
        if 'replace' in args:
            return ''
        return json.dumps(after if any('replace' in row for row in calls) else before)
    linux = SimpleNamespace(run=run, link=lambda *args: {'linkinfo': {'info_kind': 'bridge', 'info_data': {'vlan_filtering': 0}}})
    port = StablePort(SimpleNamespace(linux=linux), {'lab_id': 'lab', 'node_id': 'vd'}, {}, mac)
    if mode == 'success':
        port.ensure_forwarding(SimpleNamespace(fd=3), 'eth17')
    else:
        with pytest.raises(Conflict):
            port.ensure_forwarding(SimpleNamespace(fd=3), 'eth17')
    if mode == 'foreign-mac':
        assert not any('replace' in args for args in calls)


@pytest.mark.parametrize('version, supported', [('1.48', False), ('1.49', True), ('1.56', True), ('1.100', True), ('', False), ('unknown', False)])
def test_reserved_uplink_api_version_gate(version, supported):
    from dnlab_runtime.backend import Docker
    docker = Docker()
    docker.request = lambda *args: {'ApiVersion': version}
    if supported:
        docker.require_endpoint_name_support()
    else:
        with pytest.raises(RuntimeErrorBase, match='API >= 1.49'):
            docker.require_endpoint_name_support()


def test_reserved_name_payload_is_optional():
    from dnlab_runtime.backend import Docker
    docker = Docker()
    calls = []
    docker.request = lambda method, path, payload: calls.append(payload)
    docker.connect('network', 'vd', '192.0.2.2', interface_name='dnmu0')
    docker.connect('network', 'vd', '192.0.2.2')
    assert calls[0]['EndpointConfig']['DriverOpts'] == {'com.docker.network.endpoint.ifname': 'dnmu0'}
    assert 'DriverOpts' not in calls[1]['EndpointConfig']


@pytest.mark.parametrize('failure', ['version', 'occupied'])
def test_preflight_rejects_submit_without_detach(transfer, failure):
    handoff, port, docker, journal = transfer
    def refuse(*args):
        raise Conflict('preflight unavailable')
    if failure == 'version':
        docker.require_endpoint_name_support = refuse
    else:
        port.check_uplink_name = refuse
    with pytest.raises(Conflict, match='preflight'):
        handoff.submit('move', 'red', '198.51.100.2')
    assert docker.calls == [] and set(docker.endpoints) == {'blue'}
    assert journal.db.execute('SELECT count(*) FROM management_moves').fetchone()[0] == 0


def test_execute_rechecks_support_without_rollback_of_untouched_source(transfer):
    handoff, _, docker, _ = transfer
    handoff.submit('move', 'red', '198.51.100.2')
    def refuse():
        raise RuntimeErrorBase('unsupported API')
    docker.require_endpoint_name_support = refuse
    assert handoff.execute(handoff.by_request('move')['id'])['phase'] == 'rejected'
    assert docker.calls == [] and set(docker.endpoints) == {'blue'}
    assert handoff.execute(handoff.by_request('move')['id'])['phase'] == 'rejected'


def test_policy_persisted_and_used_for_target_and_rollback(transfer):
    handoff, port, docker, _ = transfer
    seen = []
    original = docker.connect
    def connect(*args, **kwargs):
        seen.append(kwargs['interface_name'])
        return original(*args, **kwargs)
    docker.connect = connect
    assert handoff.submit('move', 'red', '198.51.100.2')['payload']['uplink_name'] == 'dnmu0'
    port.fail_bind = True
    assert handoff.execute(handoff.by_request('move')['id'])['phase'] == 'rolled_back'
    assert seen == ['dnmu0', 'dnmu0']


def test_driver_ignoring_name_rolls_back_before_binding(transfer):
    handoff, port, _, _ = transfer
    original = port.verify_uplink_mac
    def observed(mac, connection):
        result = original(mac, connection)
        if connection['network_name'] == 'red':
            result['name'] = 'eth2'
        return result
    port.verify_uplink_mac = observed
    handoff.submit('move', 'red', '198.51.100.2')
    result = handoff.execute(handoff.by_request('move')['id'])
    assert result['phase'] == 'rolled_back'
    assert 'reserved management uplink name' in result['error']
    assert port.connection['network_name'] == 'blue'


@pytest.mark.parametrize('occupied, actual_name, actual_index, allowed', [(False, 'eth0', 8, True), (True, 'dnmu0', 8, True), (True, 'eth0', 8, False), (True, 'dnmu0', 9, False)])
def test_reserved_name_only_adopts_proven_current_endpoint(occupied, actual_name, actual_index, allowed):
    from contextlib import nullcontext
    from types import SimpleNamespace
    from dnlab_runtime.stable_management import StablePort
    backend = SimpleNamespace(linux=SimpleNamespace(link=lambda *args: {'ifindex': 8} if occupied else None), namespace=lambda *args: nullcontext('ns'))
    port = StablePort(backend, {'lab_id': 'lab', 'node_id': 'vd'}, {}, '02:00:00:00:00:01')
    port.container = lambda: {'NetworkSettings': {'Networks': {'blue': {}}}}
    port.uplink = lambda *args: {'name': actual_name, 'ifindex': actual_index}
    if allowed:
        port.check_uplink_name([{'network_name': 'blue'}])
    else:
        with pytest.raises(Conflict, match='another interface'):
            port.check_uplink_name([{'network_name': 'blue'}])


def make_remote(transfer):
    handoff, port, docker, journal = transfer
    handoff.spike_owner = None
    for network in docker.networks.values():
        network['Driver'] = 'dnlab-vrf'
        network['IPAM']['Driver'] = 'dnlab-vrf'
        network['Labels'] = {'io.dnlab.lab': 'lab', 'io.dnlab.managed': 'mgmt-vrf'}
    return handoff, port, docker, journal


def test_missing_remote_capability_probe_blocks_before_detach(transfer):
    handoff, _, docker, _ = make_remote(transfer)
    with pytest.raises(Conflict, match='live native capability probe'):
        handoff.submit('move', 'red', '198.51.100.2')
    assert docker.calls == []


@pytest.mark.parametrize('bad', ['name', 'cleanup', 'same-vd', 'network', 'absent-id'])
def test_invalid_remote_probe_observation_cannot_authorize_move(transfer, bad):
    from types import SimpleNamespace
    handoff, _, docker, _ = make_remote(transfer)
    def check(network, name):
        result = {'network_id': network['Id'], 'name': name, 'canary_container_id': 'canary', 'cleanup_verified': True}
        if bad == 'name': result['name'] = 'eth1'
        if bad == 'cleanup': result['cleanup_verified'] = False
        if bad == 'same-vd': result['canary_container_id'] = 'vd'
        if bad == 'network': result['network_id'] = 'foreign'
        if bad == 'absent-id': del result['canary_container_id']
        return result
    handoff.name_probe = SimpleNamespace(check=check)
    with pytest.raises(Conflict, match='capability observation'):
        handoff.submit('move', 'red', '198.51.100.2')
    assert docker.calls == []


def test_remote_capability_is_rechecked_before_detach_and_recorded(transfer):
    from types import SimpleNamespace
    handoff, _, docker, _ = make_remote(transfer)
    seen = []
    def check(network, name):
        seen.append(network['Id'])
        return {'network_id': network['Id'], 'name': name, 'canary_container_id': 'canary', 'cleanup_verified': True}
    handoff.name_probe = SimpleNamespace(check=check)
    assert len(handoff.submit('move', 'red', '198.51.100.2')['payload']['capability_observations']) == 2
    assert seen == ['blue', 'red'] and docker.calls == []
    def reject(*args):
        raise Conflict('driver lost naming support')
    handoff.name_probe.check = reject
    result = handoff.execute(handoff.by_request('move')['id'])
    assert result['phase'] == 'rejected' and docker.calls == []
    assert set(docker.endpoints) == {'blue'}


def test_probe_must_not_share_handoff_transaction_journal(transfer):
    from types import SimpleNamespace
    handoff, port, _, journal = transfer
    with pytest.raises(Conflict, match='separate journal'):
        Handoff(journal, handoff.backend, handoff.request, {}, port, name_probe=SimpleNamespace(journal=journal))


def test_completed_handoff_updates_authority_and_keeps_data_birth_spec(transfer):
    """Interop diagnosis: successful handoff is not committed into node authority."""
    import json
    import threading
    from contextlib import contextmanager
    from types import SimpleNamespace
    from dnlab_runtime.backend import Backend,labels
    from dnlab_runtime.link_engine import LinkEngine
    from dnlab_runtime.vxlan import VxlanManager
    from test_vxlan import Linux
    handoff,port,docker,journal=transfer
    request={'lab_id':'lab','node_id':'R1'};linux=Linux()
    linux.link=lambda name:next((value for value in linux.links() if value['ifname']==name),None)
    spec={'kind':'linux','container_name':'vd','image':'sha256:'+'a'*64,
          'management':{'network':'blue','ipv4':'192.0.2.2'},
          'endpoints':[{'host_interface':linux.source['ifname'],'node_interface':'eth1'}]}
    handoff.spike_owner=None
    handoff.name_probe=SimpleNamespace(check=lambda network,name:{'network_id':network['Id'],'name':name,'cleanup_verified':True,'canary_container_id':'separate-canary'})
    for network in docker.networks.values():
        network.update(Driver='dnlab-vrf',Labels={'io.dnlab.lab':'lab','io.dnlab.managed':'mgmt-vrf'})
        network['IPAM']['Driver']='dnlab-vrf'
    fixture_container=port.container();fixture_container['Config']={'Labels':labels(request,spec)}
    from fakes import seed_birth
    seed_birth(journal,request,spec,fixture_container)
    def inspect(name):
        assert name=='vd'
        value=port.container();value['Config']=deepcopy(fixture_container['Config'])
        return value
    docker.inspect=inspect;backend=Backend(docker=docker,linux=linux)
    @contextmanager
    def namespace(*args):yield SimpleNamespace(pid=100)
    # Endpoint pair verification is covered by primitive gates; keep the real
    # management and container verification in this interoperability regression.
    backend.namespace=namespace;backend._verify_pair=lambda *args:None
    linux.source['ifalias']=Backend.alias(request,spec)
    backend.verify(request,spec)
    journal.db.execute('INSERT INTO nodes VALUES(?,?,?,?,?)',('lab','R1',1,json.dumps(spec),'running'))
    from test_management_authority import seed_management_network
    seed_management_network(journal,request,docker.networks['blue'])
    handoff.spec=spec;handoff.backend=backend;backend.management_journal=journal
    handoff.submit('interop-move','red','198.51.100.2',expected_node_revision=1)
    assert handoff.execute(handoff.by_request('interop-move')['id'])['phase']=='completed'
    assert set(docker.endpoints)=={'red'} and journal.node('lab','R1')['spec']==spec
    manager=VxlanManager(journal,linux)
    engine=SimpleNamespace(journal=journal,backend=backend,execution_lock=threading.Lock())
    links=LinkEngine(engine,manager)
    operation=links.submit({'schema_version':1,'action':'create','request_id':'after-move','lab_id':'lab','node_id':'R1',
        'link_id':'l0','host_interface':linux.source['ifname'],'expected_node_revision':2,
        'spec':{'vni':3001,'underlay':'underlay0','local':'198.18.201.1','remote':'198.18.201.2','mtu':1450}})
    result=links.execute(operation['id'])
    assert result['phase']=='completed',result
    assert journal.node('lab','R1')['revision']==2
    assert linux.source['ifalias']==Backend.alias(request,spec)
    assert set(docker.endpoints)=={'red'}
