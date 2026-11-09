"""Reproduce managed initial admission without management usage handoff.

Real coordinator, Engine, publication and management journals; Docker, plugin
and kernel are stateful in-memory adapters. No installed service is contacted.
The normal admission and pre-marked control must both preserve the invariant.
"""
from copy import deepcopy

import pytest

from tests.test_runtime_initial_deploy import world
from tests.test_native_lifecycle_parser import segmented
from tests.test_runtime_management_parent import managed
from tests.test_managed_initial_publication import http_fixture, fixture_state
from dnlab_multinode.services.management_network_host import NetworkGuard, NetworkError
from dnlab_multinode.services import management_barrier as barrier, state as states
from dnlab_multinode.controllers.runtime_publication import publish


@pytest.mark.parametrize('mark_before', [False, True], ids=['missing-handoff', 'marked-control'])
@pytest.mark.parametrize('managed', [{'single_host': True, 'container_name': None}], indirect=True)
def test_initial_management_endpoint_requires_usage_before_birth(managed, tmp_path, monkeypatch, mark_before):
    (batch, store, clients, engines, _), topo, schedule, options = managed
    workload, topo, schedule, options, node, management = http_fixture(managed, tmp_path)
    model = barrier.get(store, 'demo')['plan']['services']['management_plan']
    segment = node.management_network
    config = model['networks'][segment]
    metadata=barrier.get(store,'demo')['infrastructure']['snapshot']['infrastructure']
    expected=metadata['networks']['master'][segment]
    transport=clients['master'].ssh;worker=transport.worker(metadata['plans']['master']);networks=transport.docker
    guard=worker.network_factory(worker,metadata['networks']['master'])
    original = deepcopy(worker.read()['networks'][segment])
    assert original['used'] is False
    if mark_before:
        guard.operate('mark-used')  # Controlled diagnostic journal only.
    docker = engines['master'].backend.docker
    docker.networks[expected['network']] = deepcopy(networks.networks[original['id']])
    create = docker.create; observations = []

    def born(name, payload):
        observations.append(worker.read()['networks'][segment]['used'])
        result = create(name, payload)
        # Model Docker's original endpoint inventory after its create API.
        networks.networks[original['id']]['Containers'][result['Id']] = {'Name': name}
        return result

    monkeypatch.setattr(docker, 'create', born)
    assert workload.drive(workload.start)['phase'] == 'completed'
    state = fixture_state(tmp_path, schedule, management_plan=model,
                          publish_service_inventory=True, managed_initial_batch=True)
    states.save_state(state, tmp_path)
    load = lambda: states.load_state(topo.name, tmp_path)
    checkpoint = lambda value: states.save_state(value, tmp_path)
    public = publish(workload.batch, topo.name, workload.key, state, load, checkpoint)
    cid = public.node_runtime['R1'].runtime_binding['container_id']
    assert list(networks.networks[original['id']]['Containers']) == [cid]
    assert clients['master'].inspect_node(topo.name, 'R1')['container_state'] == 'running'
    assert publish(workload.batch, topo.name, workload.key, load(), load, checkpoint) == public
    refusal = None
    try:
        guard.operate('verify-ready')
    except NetworkError as error:
        refusal = str(error)
    assert observations == [True] and worker.read()['networks'][segment]['used'] is True and refusal is None, {
        'used_at_container_birth': observations,
        'used_after_publication': worker.read()['networks'][segment]['used'],
        'original_endpoint_and_binding_match': True,
        'management_guard_refusal': refusal,
    }
