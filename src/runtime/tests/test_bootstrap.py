import copy
from types import SimpleNamespace

import pytest

from dnlab_runtime.backend import Docker
from dnlab_runtime.bootstrap import Bootstrap, RELEASE
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase


class Port:
    def __init__(self):
        self.value = {'Id': 'owned', 'Image': 'sha256:fixture', 'Config': {'Env': ['DNLAB_RUNTIME_BOOT_WAIT=true', 'DNLAB_RUNTIME_MGMT_INTF=mgmt0']}}
        self.checked = 0
        self.drift = False
    def container(self):
        return copy.deepcopy(self.value)
    def verify(self, identity, connection):
        self.checked += 1
        if self.drift:
            raise Conflict('interface identity changed')


class FakeDocker:
    def __init__(self):
        self.labels = {'org.dnlab.capabilities': 'runtime-management-v1', 'org.dnlab.runtime-management.status': 'experimental-unqualified', 'org.dnlab.runtime-management.python': 'system'}
        self.executed = []
    def request(self, *args):
        return {'Config': {'Labels': self.labels}}
    def exec_checked(self, container_id, args):
        self.executed.append((container_id, args))
        assert args[:2] == ['python3', '-c'] or args[:5] == ['uv', 'run', '--offline', 'python3', '-c']
        compile(args[-1], 'bootstrap-helper', 'exec')
        return 'exec-fixture'


def gate():
    port, docker = Port(), FakeDocker()
    return Bootstrap(SimpleNamespace(docker=docker), {}, {}, port), port, docker


def test_release_checks_identity_before_and_after_and_keeps_readiness_unknown():
    bootstrap, port, docker = gate()
    result = bootstrap.release({'container_id': 'owned'}, {})
    assert port.checked == 2
    assert result['guest_readiness'] == 'unknown'
    assert result['exec_id'] == 'exec-fixture'
    assert len(docker.executed) == 1


def test_uv_candidate_releases_through_offline_virtual_environment():
    bootstrap, port, docker = gate()
    docker.labels['org.dnlab.runtime-management.python'] = 'uv'
    bootstrap.release({'container_id': 'owned'}, {})
    assert docker.executed[0][1][:5] == ['uv', 'run', '--offline', 'python3', '-c']
    assert port.checked == 2


@pytest.mark.parametrize('profile', [None, '', 'shell', ['python3']])
def test_unknown_interpreter_never_releases_bootstrap(profile):
    bootstrap, port, docker = gate()
    docker.labels['org.dnlab.runtime-management.python'] = profile
    with pytest.raises(Conflict):
        bootstrap.release({'container_id': 'owned'}, {})
    assert docker.executed == []


@pytest.mark.parametrize('bad', ['container', 'capability', 'status', 'env', 'identity'])
def test_invalid_candidate_never_releases_guest(bad):
    bootstrap, port, docker = gate()
    if bad == 'container':
        port.value['Id'] = 'foreign'
    elif bad == 'capability':
        docker.labels['org.dnlab.capabilities'] = 'warm-links-v1'
    elif bad == 'status':
        docker.labels['org.dnlab.runtime-management.status'] = 'qualified'
    elif bad == 'env':
        port.value['Config']['Env'] = []
    else:
        port.drift = True
    with pytest.raises(Conflict):
        bootstrap.release({'container_id': 'owned'}, {})
    assert docker.executed == []


@pytest.mark.parametrize('exit_code', [0, 1])
def test_exec_is_tracked_and_checks_exit_status(exit_code):
    docker = Docker()
    calls = []
    def request(method, path, payload=None):
        calls.append((method, path, payload))
        if path.endswith('/exec'):
            return {'Id': 'exec-id'}
        if path.endswith('/json'):
            return {'Running': False, 'ExitCode': exit_code}
        return {}
    docker.request = request
    if exit_code:
        with pytest.raises(RuntimeErrorBase, match='failed'):
            docker.exec_checked('owned', ['python3', '-c', RELEASE])
    else:
        assert docker.exec_checked('owned', ['python3', '-c', RELEASE]) == 'exec-id'
    assert calls[0][2]['AttachStdout'] is False
    assert calls[1][2]['Detach'] is True


def test_exec_timeout_does_not_claim_success():
    docker = Docker()
    docker.request = lambda method, path, payload=None: {'Id': 'exec-id'} if path.endswith('/exec') else {'Running': True}
    with pytest.raises(RuntimeErrorBase, match='timed out'):
        docker.exec_checked('owned', ['sleep', '10'], timeout=0)
