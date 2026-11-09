"""Real lifecycle construction selects management parsing from saved ownership."""
from copy import deepcopy
from dataclasses import replace
import hashlib
import yaml
import pytest

from dnlab_multinode.controllers.node import NodeLifecycleController, NodeLifecycleError
from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.models.state import HostScheduleState
from dnlab_multinode.models.schedule import SchedulePlan, HostAssignment
from dnlab_multinode.services import native_public, runtime_cleanup
from dnlab_multinode.services.config import parse_topology, ConfigError
from dnlab_multinode.services.management_segments import resolve
from dnlab_multinode.services.state import save_state, load_state
from tests.test_mgmt_subnet import _hosts_file
from tests.test_runtime_publication import publication
from tests.test_runtime_initial_deploy import world
from dnlab_multinode.controllers.runtime_publication import publish
from dnlab_multinode.controllers import status as status_module
from dnlab_runtime.endpoint_uplink import vrf_host_peer


@pytest.fixture
def segmented(tmp_path):
    hosts = _hosts_file(tmp_path)
    path = tmp_path / 'demo.yml'
    data = {'name': 'demo', 'management_networks': {
        'default': {'ipv4-subnet': '198.18.1.0/24', 'ipv6-subnet': '2001:db8:1::/64'},
        'blue': {'ipv4-subnet': '198.18.2.0/24', 'ipv6-subnet': '2001:db8:2::/64'}},
        'topology': {'nodes': {'R1': {'kind': 'linux', 'image': 'sha256:' + 'a' * 64,
                                    'management_network': 'blue'}}}}
    path.write_text(yaml.safe_dump(data))
    topo, model = resolve(parse_topology(path, hosts_file=hosts, native_management=True))
    state = DeploymentState(lab_name='demo', topology_file=str(path), runtime_mode='custom',
                            dnlab_deployed=False, management_plan=model)
    save_state(state, tmp_path)
    return path, hosts, data, state, topo


def test_saved_custom_owner_loads_original_segment_ledger_without_fabricating_nodes(segmented):
    path, hosts, data, state, topo = segmented
    before = path.read_bytes()
    controller = NodeLifecycleController(str(path), hosts_file=str(hosts))
    assert controller.state.to_dict() == state.to_dict()
    assert controller.state.node_runtime == {}
    assert controller.topo.nodes['R1'].mgmt_ipv4 == topo.nodes['R1'].mgmt_ipv4
    assert controller.topo.nodes['R1'].mgmt_ipv6 == topo.nodes['R1'].mgmt_ipv6
    assert controller.topo.nodes['R1'].mgmt_mac == topo.nodes['R1'].mgmt_mac
    assert path.read_bytes() == before


@pytest.mark.parametrize('mode', ['', 'legacy', 'per-vd', 'unknown'])
def test_management_yaml_never_selects_or_converts_saved_backend(segmented, mode):
    path, hosts, data, state, topo = segmented
    state.runtime_mode = mode
    save_state(state, path.parent)
    before = load_state('demo', path.parent).to_dict()
    with pytest.raises((ConfigError, native_public.NativeOwnershipError)):
        NodeLifecycleController(str(path), hosts_file=str(hosts))
    assert load_state('demo', path.parent).to_dict() == before


@pytest.mark.parametrize('change', ['foreign-ledger', 'no-ledger', 'subnet', 'assignment', 'ipv4', 'mac', 'new-network', 'new-node'])
def test_untracked_management_changes_refused_without_writing_state(segmented, change):
    path, hosts, data, state, topo = segmented
    if change == 'foreign-ledger': state.management_plan['lab'] = 'foreign'
    elif change == 'no-ledger': state.management_plan = {}
    elif change == 'subnet': data['management_networks']['blue']['ipv4-subnet'] = '198.18.3.0/24'
    elif change == 'assignment': data['topology']['nodes']['R1']['management_network'] = 'default'
    elif change == 'ipv4': data['topology']['nodes']['R1']['mgmt-ipv4'] = '198.18.2.99'
    elif change == 'mac': data['topology']['nodes']['R1']['mgmt-mac'] = '02:00:00:00:00:99'
    elif change == 'new-network': data['management_networks']['green'] = {'ipv4-subnet': '198.18.3.0/24', 'ipv6-subnet': '2001:db8:3::/64'}
    elif change == 'new-node': data['topology']['nodes']['R2'] = {'kind': 'linux', 'image': 'sha256:' + 'a' * 64}
    path.write_text(yaml.safe_dump(data)); save_state(state, path.parent)
    before = load_state('demo', path.parent).to_dict()
    with pytest.raises((ConfigError, NodeLifecycleError)):
        NodeLifecycleController(str(path), hosts_file=str(hosts))
    assert load_state('demo', path.parent).to_dict() == before


def test_missing_owner_does_not_enable_native_parsing(segmented):
    path, hosts, data, state, topo = segmented
    (path.parent / '.demo.multinode.json').unlink()
    with pytest.raises(NodeLifecycleError, match='not deployed'):
        NodeLifecycleController(str(path), hosts_file=str(hosts))


def test_published_bindings_work_through_real_constructor_and_public_stop_start(publication, tmp_path, monkeypatch):
    world, state, load, save = publication
    batch, store, clients, engines, members = world
    path = tmp_path / 'demo.yml'; hosts = _hosts_file(tmp_path)
    inventory = yaml.safe_load(hosts.read_text())
    inventory['infrastructure']['workers'] = {'worker': {'host': '192.0.2.2', 'ssh_user': 'root', 'ssh_key': '/nonexistent/fixture'}}
    hosts.write_text(yaml.safe_dump(inventory))
    path.write_text(yaml.safe_dump({'name': 'demo', 'topology': {'nodes': {
        m['request']['node_id']: {'kind': 'linux', 'image': m['request']['spec']['image']}
        for m in members}}}))
    state.topology_file = str(path); save(state)
    published = publish(batch, 'demo', 'deploy', state, load, save)
    original = deepcopy(published.node_runtime['vd0'].runtime_binding)
    other = deepcopy(clients['worker'].inspect_node('demo', 'vd1'))
    monkeypatch.setattr(runtime_cleanup, 'PATHS', replace(runtime_cleanup.PATHS, runtime_operations_dir=str(store.directory)))
    class SSH:
        def __init__(self, host): self.host = host
        def connect(self): pass
        def close(self): pass
        def cancel_active_commands(self): pass
        def __getattr__(self, name): raise AssertionError('unexpected legacy operation: ' + name)
    monkeypatch.setattr(native_public, 'RuntimeClient', lambda ssh, **kw: clients[ssh.host])
    def controller():
        result = NodeLifecycleController(str(path), hosts_file=str(hosts))
        result._native_clients_factory = lambda hosts: {host: SSH(host) for host in hosts}
        return result
    stopped = controller().stop('vd0', request_id='public-stop')
    assert stopped.node_runtime['vd0'].state == 'stopped'
    assert stopped.node_runtime['vd0'].runtime_binding['container_id'] == original['container_id']
    started = controller().start('vd0', request_id='public-start')
    assert started.node_runtime['vd0'].state == 'running'
    assert started.node_runtime['vd0'].runtime_binding['generation'] > original['generation']
    assert clients['worker'].inspect_node('demo', 'vd1') == other
    assert ('signal', 'SIGTERM') in engines['master'].backend.docker.calls
    assert all(('signal', 'SIGKILL') not in e.backend.docker.calls for e in engines.values())


def configure_segment_runtime(engine, cfg):
    docker = engine.backend.docker; linux = engine.backend.linux
    docker.networks[cfg['network']] = {
        'Id': 'e' * 64, 'Name': cfg['network'], 'Driver': 'dnlab-vrf', 'EnableIPv6': True,
        'Labels': {'io.dnlab.lab': 'demo', 'io.dnlab.managed': 'mgmt-vrf'},
        'Options': {'dnlab.bridge': cfg['bridge'], 'dnlab.vrf': 'vrf-demo', 'dnlab.lab': 'demo'},
        'IPAM': {'Driver': 'dnlab-vrf', 'Options': {'dnlab.tenant': cfg['network']}, 'Config': [
            {'Subnet': cfg['ipv4_subnet'], 'Gateway': cfg['docker_ipv4_gw']},
            {'Subnet': cfg['ipv6_subnet'], 'Gateway': cfg['ipv6_gw']}]}}
    inspect = docker.inspect
    docker.inspect = lambda identity: inspect(identity) or next((deepcopy(c) for c in docker.containers.values() if c['Id'] == identity), None)
    def started(event):
        if event != 'start': return
        for container in docker.containers.values():
            for network, endpoint in container['NetworkSettings']['Networks'].items():
                endpoint['EndpointID'] = hashlib.sha256(container['Id'].encode()).hexdigest()
                peer = vrf_host_peer(docker.networks[network]['Id'], endpoint['EndpointID'])
                linux.links[(None, peer)] = {'ifname': peer, 'ifindex': 11, 'link_index': 12, 'master': cfg['bridge'], 'linkinfo': {'info_kind': 'veth'}}
                linux.links[(100, 'mgmt-native')] = {'ifname': 'mgmt-native', 'ifindex': 12, 'link_index': 11, 'address': endpoint['MacAddress'], 'linkinfo': {'info_kind': 'veth'}}
    docker.hook = started


def test_segmented_compilation_publication_and_public_restart_keep_original_management(world, segmented, monkeypatch):
    batch, store, clients, engines, members = world
    path, hosts, data, state, topo = segmented
    cfg = state.management_plan['networks']['blue']
    configure_segment_runtime(engines['master'], cfg)
    docker = engines['master'].backend.docker
    plan = SchedulePlan(lab_name='demo', assignments={'master': HostAssignment('master', 'fixture', ['R1'])})
    batch.prepare_topology(topo, plan, 'segments', targets={'master': members[0]['target']}, management_plan=state.management_plan)
    assert batch.advance('demo', 'segments')['phase'] == 'completed'
    state.scheduling = {'master': HostScheduleState(host='fixture', topology_file='', vd=['R1'])}
    save_state(state, path.parent)
    load = lambda: load_state('demo', path.parent)
    save = lambda value: save_state(value, path.parent)
    published = publish(batch, 'demo', 'segments', state, load, save)
    original = deepcopy(published.node_runtime['R1'].runtime_binding)
    network = deepcopy(docker.networks[cfg['network']])
    monkeypatch.setattr(runtime_cleanup, 'PATHS', replace(runtime_cleanup.PATHS, runtime_operations_dir=str(store.directory)))
    class SSH:
        def connect(self): pass
        def close(self): pass
        def cancel_active_commands(self): pass
        def run_no_check(self, command, **kwargs):
            assert command.startswith('docker ps -a ')
            return 0, '', ''  # Names are deliberately absent; use original ID.
        def __getattr__(self, name): raise AssertionError('legacy mutation: ' + name)
    monkeypatch.setattr(native_public, 'RuntimeClient', lambda ssh, **kw: clients['master'])
    def controller():
        result = NodeLifecycleController(str(path), hosts_file=str(hosts))
        result._native_clients_factory = lambda hosts: {host: SSH() for host in hosts}
        return result
    stopped = controller().stop('R1', request_id='stop-blue')
    assert stopped.node_runtime['R1'].state == 'stopped'
    monkeypatch.setattr(status_module, 'create_clients', lambda hosts: {host: SSH() for host in hosts})
    report = status_module.StatusController(str(path), hosts_file=str(hosts)).run()
    assert report.nodes['R1'].state == 'stopped' and report.nodes['R1'].can_start
    assert report.nodes['R1'].runtime_status['qualified'] is True
    running = controller().start('R1', request_id='start-blue')
    assert running.node_runtime['R1'].runtime_binding['generation'] > original['generation']
    current = clients['master'].inspect_node('demo', 'R1')
    container = docker.inspect(current['container_id'])
    endpoint = container['NetworkSettings']['Networks'][cfg['network']]
    assert endpoint['NetworkID'] == network['Id']
    assert endpoint['IPAddress'] == topo.nodes['R1'].mgmt_ipv4
    assert endpoint['GlobalIPv6Address'] == topo.nodes['R1'].mgmt_ipv6
    assert endpoint['MacAddress'] == topo.nodes['R1'].mgmt_mac
    assert running.management_plan == state.management_plan
    assert docker.networks[cfg['network']] == network
    assert not engines['worker'].backend.docker.calls
    before = deepcopy(docker.calls)
    state_bytes = (path.parent / '.demo.multinode.json').read_bytes()
    report = status_module.StatusController(str(path), hosts_file=str(hosts)).run()
    assert report.nodes['R1'].state == 'running' and report.nodes['R1'].can_stop
    assert report.nodes['R1'].mgmt_ipv4 == topo.nodes['R1'].mgmt_ipv4
    assert report.nodes['R1'].runtime_status['workload']['container_id'] == current['container_id']
    assert docker.calls == before
    assert (path.parent / '.demo.multinode.json').read_bytes() == state_bytes


@pytest.mark.parametrize('fault', ['subnet', 'new-network', 'no-ledger', 'legacy', 'unknown'])
def test_status_rejects_unqualified_segment_context_before_connections(segmented, monkeypatch, fault):
    path, hosts, data, state, topo = segmented
    if fault == 'subnet': data['management_networks']['blue']['ipv4-subnet'] = '198.18.3.0/24'
    elif fault == 'new-network': data['management_networks']['green'] = {'ipv4-subnet': '198.18.3.0/24', 'ipv6-subnet': '2001:db8:3::/64'}
    elif fault == 'no-ledger': state.management_plan = {}
    else: state.runtime_mode = fault
    path.write_text(yaml.safe_dump(data)); save_state(state, path.parent)
    original = (path.parent / '.demo.multinode.json').read_bytes()
    def forbidden(*args): raise AssertionError('must reject before any connection')
    monkeypatch.setattr(status_module, 'create_clients', forbidden)
    with pytest.raises((ConfigError, native_public.NativeOwnershipError)):
        status_module.StatusController(str(path), hosts_file=str(hosts)).run()
    assert (path.parent / '.demo.multinode.json').read_bytes() == original
