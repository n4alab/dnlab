"""A live gate cannot outrun or trust an unqualified cleanup daemon."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_compatibility import CleanupCompatibilityError, require_qualified_cleanup


class Engine:
    def __init__(self, inventory):
        self.inventory = inventory
        self.calls = []

    def request(self, method, path):
        self.calls.append((method, path))
        assert (method, path) == ('GET', '/containers/json?all=1')
        return deepcopy(self.inventory)


def daemon(**changes):
    return dict({'Id': 'a' * 64, 'Names': ['/dnlab-lab-cleanup-1'],
                 'Labels': {'com.docker.compose.service': 'lab-cleanup'},
                 'Command': 'python -m dnlab_multinode.services.lab_cleanup'}, **changes)


@pytest.mark.parametrize('item', [daemon(), daemon(State='exited'),
    daemon(Labels={'cleanup.capabilities': 'qualified'}, Names=['/renamed']),
    daemon(Command='', Labels={}), daemon(Command='', Names=['/renamed'])])
def test_daemon_identity_or_self_declared_capability_never_authorizes_gate(item):
    api = Engine([item])
    with pytest.raises(CleanupCompatibilityError, match='not qualified') as caught:
        require_qualified_cleanup(api)
    assert caught.value.evidence['qualified'] is False
    assert caught.value.evidence['candidates'] == [
        {'container_id': 'a' * 64, 'names': item['Names']}]
    assert api.calls == [('GET', '/containers/json?all=1')]
    assert 'Command' not in str(caught.value.evidence)


def test_no_local_daemon_does_not_prove_remote_cleanup_safety():
    with pytest.raises(CleanupCompatibilityError, match='not qualified') as caught:
        require_qualified_cleanup(Engine([]))
    assert caught.value.evidence['candidates'] == []
    assert caught.value.evidence['scope'] == 'local-engine-only'


@pytest.mark.parametrize('inventory', [None, {}, [None], [daemon(Id='short')],
    [daemon(), daemon()], [daemon(Labels=None)], [daemon(Names=[1])],
    [daemon(Command=None)]])
def test_incomplete_observation_is_not_treated_as_absence(inventory):
    with pytest.raises(CleanupCompatibilityError, match='unavailable or incomplete'):
        require_qualified_cleanup(Engine(inventory))


def test_engine_failure_is_preserved_without_success_or_retry():
    class Failed(Engine):
        def request(self, method, path):
            raise TimeoutError('inert observation timeout')
    with pytest.raises(CleanupCompatibilityError) as caught:
        require_qualified_cleanup(Failed([]))
    assert isinstance(caught.value.__cause__, TimeoutError)


@pytest.mark.parametrize('runner', ['management', 'relay'])
def test_actual_entrypoint_blocks_before_output_or_candidate_audit(tmp_path, monkeypatch, runner):
    import management_services_smoke as management
    import relay_console_smoke as relay
    api = Engine([daemon()])
    module = management if runner == 'management' else relay
    monkeypatch.setattr(module, 'Docker', lambda: api)
    output = tmp_path / 'must-not-exist'
    with pytest.raises(CleanupCompatibilityError, match='not qualified'):
        if runner == 'management':
            management.run(output, 'not-read', 'not-audited', 'not-created')
        else:
            relay.run(output, 'not-audited', 'not-created')
    assert not output.exists()
    assert api.calls == [('GET', '/containers/json?all=1')]
