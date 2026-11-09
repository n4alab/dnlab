"""Shared external-network ownership, uncertain birth and durable recovery."""
import copy
import json
from unittest.mock import MagicMock

import pytest

from dnlab_multinode.services.jumphost_network_host import Worker, NetworkError, Docker, DockerError

CONFIG = dict(network='drsp-jh-external', bridge='drspjhex', subnet='198.19.245.0/24', gateway='198.19.245.1')
CONTEXT = dict(boot_id='fixture', device=1, inode=2)


class Environment:
    def __init__(self):
        self.value = None; self.links = []; self.creates = []; self.other = []
        self.error = None; self.failure = None; self.gateway = CONFIG['gateway']

    def inventory(self):
        if self.error: raise self.error
        return copy.deepcopy(self.other + ([self.value] if self.value else []))

    def inspect(self, identity):
        if self.error: raise self.error
        return copy.deepcopy(self.value) if self.value and identity in (self.value['Name'], self.value['Id']) else None

    def create(self, payload):
        self.creates.append(copy.deepcopy(payload))
        if self.failure == 'before': raise NetworkError('create transport failed before allocation')
        self.value = {k: copy.deepcopy(v) for k, v in payload.items() if k != 'CheckDuplicate'}
        self.value.update(Id='a'*64, Scope='local', ConfigOnly=False, Containers={})
        self.links = [dict(ifname=CONFIG['bridge'], ifindex=10, address='02:42:00:00:00:01', ifalias='', linkinfo={'info_kind':'bridge'})]
        if self.failure == 'after': raise NetworkError('lost response after create')
        return self.value['Id']

    def run(self, args):
        if args[:4] == ['ip','-j','-d','link']: return copy.deepcopy(self.links)
        assert args[:3] == ['ip','-j','address']
        return [{'addr_info':[dict(family='inet', local=self.gateway, prefixlen=24)]}]


@pytest.fixture
def fixture(tmp_path):
    env = Environment()
    worker = Worker(CONFIG, directory=tmp_path/'journal', docker=env, run=env.run, host_context=lambda: CONTEXT)
    return worker, env


def test_readonly_preflight_then_stable_shared_reuse_with_consumers(fixture):
    worker, env = fixture
    assert worker.preflight() == {'status':'verified','network_id':None}
    assert not worker.directory.exists() and not env.creates
    result = worker.operate(); before = worker.path.read_bytes()
    env.value['Containers'] = {'first-lab': {}, 'second-lab': {}}
    assert worker.operate() == result
    assert worker.preflight()['network_id'] == result['network_id']
    assert len(env.creates) == 1 and worker.path.read_bytes() == before
    with pytest.raises(NetworkError, match='unsupported'): worker.operate('delete')
    assert env.value['Containers'] == {'first-lab': {}, 'second-lab': {}}


@pytest.mark.parametrize('error', [DockerError(403,'GET','/networks'), NetworkError('transport unavailable'), NetworkError('malformed response')])
def test_inspection_error_never_authorizes_creation(fixture, error):
    worker, env = fixture; env.error = error
    with pytest.raises(NetworkError): worker.operate()
    assert not env.creates and not worker.path.exists()


@pytest.mark.parametrize('failure', ['before','after'])
def test_uncertain_birth_recovers_stably_only_on_explicit_request(fixture, failure):
    worker, env = fixture; env.failure = failure
    with pytest.raises(NetworkError): worker.operate()
    record = worker.read(); assert record['phase'] == 'recovery_required'
    assert record['id'] is None
    with pytest.raises(NetworkError, match='explicit recovery'): worker.operate()
    env.failure = None; count = len(env.creates)
    fresh = Worker(CONFIG, directory=worker.directory, docker=env, run=env.run, host_context=lambda: CONTEXT)
    assert fresh.operate('recover')['network_id'] == 'a'*64
    assert len(env.creates) == count + (failure == 'before')
    assert fresh.read()['nonce'] == record['nonce']


@pytest.mark.parametrize('change', ['id','labels','driver','subnet','gateway','ipam-options','ipam-driver','options',
                                  'scope','ipv6','internal','bridge-mac','bridge-index','bridge-kind','kernel-gateway'])
def test_active_conflicts_preserve_original_journal_and_never_create(fixture, change):
    worker, env = fixture; worker.operate(); before = worker.path.read_bytes()
    if change == 'id': env.value['Id'] = 'b'*64
    elif change == 'labels': env.value['Labels'] = {}
    elif change == 'driver': env.value['Driver'] = 'dnlab-vrf'
    elif change == 'subnet': env.value['IPAM']['Config'][0]['Subnet'] = '192.0.2.0/24'
    elif change == 'gateway': env.value['IPAM']['Config'][0]['Gateway'] = '198.19.245.2'
    elif change == 'ipam-options': env.value['IPAM']['Options'] = {'foreign':'yes'}
    elif change == 'ipam-driver': env.value['IPAM']['Driver'] = 'foreign'
    elif change == 'options': env.value['Options'] = {}
    elif change == 'scope': env.value['Scope'] = 'swarm'
    elif change == 'ipv6': env.value['EnableIPv6'] = True
    elif change == 'internal': env.value['Internal'] = True
    elif change == 'bridge-mac': env.links[0]['address'] = '02:00:ff:ff:ff:ff'
    elif change == 'bridge-index': env.links[0]['ifindex'] += 1
    elif change == 'bridge-kind': env.links[0]['linkinfo']['info_kind'] = 'dummy'
    elif change == 'kernel-gateway': env.gateway = '198.19.245.2'
    for action in ('ensure', 'recover'):
        with pytest.raises(NetworkError): worker.operate(action)
    assert len(env.creates) == 1 and worker.path.read_bytes() == before


def test_missing_active_network_not_recreated(fixture):
    worker, env = fixture; worker.operate(); env.value = None; env.links = []
    for action in ('ensure','recover'):
        with pytest.raises(NetworkError, match='absent'): worker.operate(action)
    assert len(env.creates) == 1


def test_matching_existing_network_without_intent_is_not_adopted(fixture):
    worker, env = fixture; worker.operate(); worker.path.unlink()
    with pytest.raises(NetworkError, match='refusing adoption'): worker.operate()
    assert len(env.creates) == 1


def test_recovery_refuses_replacement_after_lost_create_response(fixture):
    worker, env = fixture; env.failure = 'after'
    with pytest.raises(NetworkError): worker.operate()
    env.value['Labels']['org.dnlab.jumphost.network.creator'] = 'f'*32
    with pytest.raises(NetworkError): worker.operate('recover')
    assert len(env.creates) == 1 and worker.read()['phase'] == 'recovery_required'


@pytest.mark.parametrize('conflict', ['bridge','subnet','reserved-bridge'])
def test_complete_preflight_refuses_conflicts_before_birth_intent(fixture, conflict):
    worker, env = fixture
    if conflict == 'bridge': env.links = [dict(ifname=CONFIG['bridge'])]
    else:
        row = dict(Id='b'*64, Name='foreign', Options={}, IPAM={'Config':[]})
        if conflict == 'subnet': row['IPAM']['Config'] = [{'Subnet':CONFIG['subnet']}]
        else: row['Options']['com.docker.network.bridge.name'] = CONFIG['bridge']
        env.other = [row]
    with pytest.raises(NetworkError): worker.operate()
    assert not env.creates and not worker.path.exists()


@pytest.mark.parametrize('options', [None, {}])
def test_empty_ipam_options_are_equivalent(fixture, options):
    worker, env = fixture; worker.operate(); env.value['IPAM']['Options'] = options
    assert worker.operate()['status'] == 'active' and len(env.creates) == 1


@pytest.mark.parametrize('stage', ['intent','id','active'])
def test_save_failure_never_claims_success_or_recreates_bound_network(fixture, monkeypatch, stage):
    worker, env = fixture; original = worker.save
    def save(record):
        matches = (stage == 'intent' and not record['id'] or stage == 'id' and record['id'] and not record['bridge']
                   or stage == 'active' and record['phase'] == 'active')
        if matches: raise OSError('fsync failed')
        original(record)
    monkeypatch.setattr(worker,'save',save)
    with pytest.raises(OSError): worker.operate()
    assert len(env.creates) == (stage != 'intent')
    monkeypatch.setattr(worker,'save',original)
    if stage == 'intent': assert not worker.path.exists()
    else:
        assert worker.read()['phase'] in ('creating', 'recovery_required')
        with pytest.raises(NetworkError, match='explicit recovery'): worker.operate()
        assert worker.operate('recover')['network_id'] == 'a'*64
        assert len(env.creates) == 1


@pytest.mark.parametrize('status,body,accepted', [(404,{'message':'not found'},True),(403,{'message':'denied'},False),
    (500,{'message':'failure'},False),(404,{},False),(200,{},False)])
def test_only_structured_404_establishes_absence(monkeypatch, status, body, accepted):
    connection = MagicMock(); response = connection.getresponse.return_value
    response.status = status; response.read.return_value = json.dumps(body).encode()
    monkeypatch.setattr('dnlab_multinode.services.jumphost_network_host.http.client.HTTPConnection', lambda *a, **k: connection)
    monkeypatch.setattr('dnlab_multinode.services.jumphost_network_host.socket.socket', lambda *a, **k: MagicMock())
    if accepted: assert Docker().inspect('missing') is None
    else:
        with pytest.raises(NetworkError): Docker().inspect('missing')


def test_namespace_or_desired_config_change_cannot_rebind_shared_network(fixture):
    worker, env = fixture; worker.operate()
    for cfg, ctx in [(dict(CONFIG, gateway='198.19.245.2'), CONTEXT), (CONFIG, dict(CONTEXT, inode=99))]:
        with pytest.raises(NetworkError, match='configuration/context'):
            Worker(cfg, directory=worker.directory, docker=env, run=env.run, host_context=lambda: ctx).operate()
    assert len(env.creates) == 1


def test_concurrent_infrastructure_operation_is_refused(fixture):
    import fcntl
    import os
    worker, env = fixture; worker.operate()
    fd = os.open(worker.directory / '.lock', os.O_RDWR)
    try:
        fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(NetworkError, match='busy'): worker.operate()
    finally: os.close(fd)
    assert len(env.creates) == 1


def test_existing_jumphost_api_uses_guard_stdin_without_shell_fallback(fixture):
    from dnlab_multinode.models.topology import JumphostNet
    from dnlab_multinode.services.jumphost import ensure_jumphost_network
    worker, env = fixture; client = MagicMock()
    def run_input(command, payload, timeout):
        request = json.loads(payload)
        assert request['config'] == CONFIG and request['socket'].startswith('/')
        return json.dumps(worker.preflight() if request['action'] == 'preflight' else worker.operate(request['action']))
    client.run_input.side_effect = run_input
    net = JumphostNet(CONFIG['network'], CONFIG['bridge'], CONFIG['subnet'], CONFIG['gateway'])
    assert ensure_jumphost_network(client, net, action='preflight')['network_id'] is None
    assert ensure_jumphost_network(client, net)['network_id'] == 'a'*64
    env.error = DockerError(403, 'GET', '/networks')
    with pytest.raises(RuntimeError): ensure_jumphost_network(client, net)
    client.run.assert_not_called(); client.run_no_check.assert_not_called()
    assert len(env.creates) == 1


def test_deploy_rejects_shared_network_before_any_resource_phase(topo_factory, tmp_path, monkeypatch):
    from types import SimpleNamespace
    from dnlab_multinode.controllers import deploy
    topo = topo_factory(name='shared-check', num_workers=0)
    planner = SimpleNamespace(topo=topo, run=lambda: SimpleNamespace(cross_host_links=[], vrf_table_id=100))
    monkeypatch.setattr(deploy, 'PlanController', lambda *a, **k: planner)
    monkeypatch.setattr(deploy.state_svc, 'load_state', lambda *a: None)
    client = MagicMock()
    monkeypatch.setattr(deploy, 'create_clients', lambda *a: {'master':client})
    def reject(*args, **kwargs):
        assert kwargs == {'action':'preflight'}
        raise NetworkError('foreign external network')
    monkeypatch.setattr(deploy.jumphost, 'ensure_jumphost_network', reject)
    controller = deploy.DeployController(str(tmp_path/'lab.yml'))
    mutating_phase = MagicMock()
    monkeypatch.setattr(controller, '_inspect_image_capabilities', mutating_phase)
    rollback = []
    monkeypatch.setattr(controller, '_rollback', lambda *a: rollback.append(list(controller._state.phases_completed)))
    with pytest.raises(deploy.DeployError, match='foreign external network'): controller.run()
    mutating_phase.assert_not_called()
    assert rollback == [[]]
    client.close.assert_called_once()
