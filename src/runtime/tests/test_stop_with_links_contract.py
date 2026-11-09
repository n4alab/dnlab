"""Legacy requests retain their guard; phased stop is an explicit protocol."""
from copy import deepcopy

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.manifest import Conflict
from fakes import FakeClock, FakeDocker
from test_bridge_link_engine import fixture, execute, request as link_request


def test_legacy_stop_guard_does_not_adopt_phased_protocol_implicitly(fixture):
    links, linux, setup, verified = fixture
    assert execute(links, link_request())['phase'] == 'completed'
    docker, clock = FakeDocker(), FakeClock()
    backend = Backend(docker, linux, clock=clock.clock, sleep=clock.sleep)
    for node in ('vd1', 'vd2'):
        owner = {'lab_id': 'lab', 'node_id': node}
        spec = setup.journal.node('lab', node)['spec']
        backend.create(owner, spec, 'diagnostic-' + node)
        backend.start(owner, spec)
        from fakes import seed_birth
        seed_birth(setup.journal,owner,spec,docker.containers[node])
    engine = Engine(setup.journal, backend)
    engine.links = links
    links.engine = engine
    stopped = {'schema_version': 1, 'request_id': 'stop1', 'lab_id': 'lab',
               'node_id': 'vd1', 'expected_revision': 1, 'action': 'stop'}
    calls = deepcopy(docker.calls)
    with pytest.raises(Conflict, match='before stopping'):
        engine.plan(stopped)
    assert docker.calls == calls  # No SIGTERM is possible through this path yet.
    assert links.inspect('lab', 'l0', 'rt-left')['committed_state'] == 'active'

    # Model the order demanded by the current stop guard, then a real Backend
    # SIGTERM timeout against the stateful fake Docker implementation.
    assert execute(links, link_request(request_id='delete', action='delete'))['phase'] == 'completed'
    other = deepcopy(docker.inspect('vd2'))
    docker.resist_term = True
    operation = engine.journal.submit(stopped)
    result = engine.execute(operation['id'])
    assert result['phase'] == 'recovery_required'
    assert docker.inspect('vd1')['State']['Running'] is True
    assert docker.inspect('vd2') == other
    assert ('signal', 'SIGTERM') in docker.calls and ('signal', 'SIGKILL') not in docker.calls
    assert links.inspect('lab', 'l0', 'rt-left')['committed_state'] == 'deleted'
    assert engine.journal.node('lab', 'vd1')['state'] == 'running'
