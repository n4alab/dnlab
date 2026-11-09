"""Fixture job teardown must preserve foreign containers, including on timeout."""
import copy
from pathlib import Path
import subprocess
import tempfile

import pytest

from dnlab_runtime.manifest import Conflict


class Docker:
    def __init__(self, *, foreign=False, timeout=False):
        self.foreign, self.timeout = foreign, timeout
        self.observed = None
        self.killed = []
        self.removed = []
        self.started = []
        self.config = None

    def request(self, method, path):
        if path.startswith('/images/'):
            return {'Id': 'sha256:' + 'b'*64}
        if path.endswith('wait?condition=not-running'):
            if self.timeout:
                self.timeout = False
                raise TimeoutError('worker wait timeout')
            self.observed['State']['Running'] = False
            return {'StatusCode': 0}
        raise AssertionError(path)

    def create(self, name, config):
        self.config = config
        self.observed = {'Id': 'a'*64, 'Config': copy.deepcopy(config), 'State': {'Running': False}}
        if self.foreign:
            self.observed['Config']['Labels']['org.dnlab.runtime.fixture-worker'] = 'foreign'
        return {'Id': 'a'*64}

    def inspect(self, identity):
        return copy.deepcopy(self.observed)

    def start(self, identity):
        self.started.append(identity)
        self.observed['State']['Running'] = True

    def signal(self, identity, signal):
        self.killed.append((identity, signal))
        self.observed['State']['Running'] = False

    def remove(self, identity):
        self.removed.append(identity)
        self.observed = None


@pytest.fixture
def job(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1]/'tools'))
    from vxlan_container_worker import run_image_worker
    with tempfile.TemporaryDirectory(prefix='dnlab-vxlan-traffic-') as directory:
        root = Path(directory)
        config = {'executor_image': 'sha256:' + 'b'*64, 'identity': {'lab_id': 'fixture-test'}}
        yield run_image_worker, root/'request.json', config


def logs(identity):
    return subprocess.CompletedProcess(['logs', identity], 0, '{"phase":"cleaned"}\n', '')


def test_finished_job_removes_only_its_container_and_mounts_no_socket(job):
    run, path, config = job
    docker = Docker()
    result = run(path, config, docker=docker, read_logs=logs)
    assert result.returncode == 0
    assert docker.removed == ['a'*64] and not docker.killed
    assert all('docker.sock' not in mount for mount in docker.config['HostConfig']['Binds'])
    assert docker.config['Image'] == config['executor_image']
    assert docker.config['Env'] == ['DNLAB_RUNTIME_HOST_BOOT_ID_FILE=/run/dnlab-runtime/host-boot-id']
    assert '/proc/sys/kernel/random/boot_id:/run/dnlab-runtime/host-boot-id:ro' in docker.config['HostConfig']['Binds']


def test_timeout_explicitly_kills_only_owned_fixture_and_removes_it(job):
    run, path, config = job
    docker = Docker(timeout=True)
    with pytest.raises(TimeoutError):
        run(path, config, docker=docker, read_logs=logs)
    assert docker.killed == [('a'*64, 'SIGKILL')]
    assert docker.removed == ['a'*64]


def test_foreign_ownership_is_never_started_killed_or_removed(job):
    run, path, config = job
    docker = Docker(foreign=True)
    with pytest.raises(Conflict, match='ownership'):
        run(path, config, docker=docker, read_logs=logs)
    assert not docker.started and not docker.killed and not docker.removed


def test_mutable_image_is_rejected_before_create(job):
    run, path, config = job
    config['executor_image'] = 'runtime:latest'
    docker = Docker()
    with pytest.raises(Conflict, match='immutable'):
        run(path, config, docker=docker, read_logs=logs)
    assert docker.config is None


def test_bridge_worker_uses_only_its_fixed_harness_and_fixture_root(job):
    run,_,config=job
    with tempfile.TemporaryDirectory(prefix='dnlab-custom-bridge-') as directory:
        docker=Docker()
        result=run(Path(directory)/'request.json',config,docker=docker,read_logs=logs,harness='bridge_crash_probe.py')
        assert result.returncode==0 and docker.removed==['a'*64]
        assert Path(docker.config['Cmd'][0]).name=='bridge_crash_probe.py'


@pytest.mark.parametrize('harness',['bridge_crash_probe.py','../../arbitrary.py'])
def test_mismatched_or_unqualified_harness_is_rejected_before_create(job,harness):
    run,path,config=job;docker=Docker()
    with pytest.raises(Conflict,match='isolated'):
        run(path,config,docker=docker,read_logs=logs,harness=harness)
    assert docker.config is None
