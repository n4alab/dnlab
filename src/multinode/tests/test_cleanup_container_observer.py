"""Container provenance with fake Docker/process capture and private temp files."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_container_observer import config_digest, observe_container, source_at
from cleanup_execution import canonical_digest


@pytest.fixture
def world():
    image = 'sha256:' + 'd' * 64
    sources = {name: {'path': '/usr/local/lib/python3.13/site-packages/dnlab_multinode/' + relative,
                      'sha256': '1' * 64}
               for name, relative in (('cleanup', 'services/lab_cleanup.py'), ('daemon_cli', 'lab_cleanup_cli.py'))}
    copies = {row['path']: row['sha256'] for row in sources.values()}
    copies.update({'/opt/dnlab-multinode/dnlab_multinode/' + row['path'].split('/dnlab_multinode/')[1]: row['sha256']
                   for row in sources.values()})
    copies['/usr/local/bin/dnlab-lab-cleanup'] = '2' * 64
    container = {'Id': 'a' * 64, 'Image': image, 'Config': {'Env': ['SECRET=not-recorded']},
                 'HostConfig': {'NetworkMode': 'host'}, 'Mounts': [],
                 'Path': 'dnlab-lab-cleanup', 'Args': ['start'], 'RestartCount': 0,
                 'State': {'Pid': 42, 'StartedAt': 'original', 'Running': True, 'Status': 'running'}}
    profile = {'container_id': container['Id'], 'config_sha256': config_digest(container),
               'exe': '/usr/local/bin/python3.13', 'exe_sha256': '3' * 64,
               'cmdline_sha256': '4' * 64, 'cwd': '/opt/dnlab-multinode',
               'import_env_sha256': '5' * 64, 'copies': copies}
    descriptor = {'kind': 'container', 'image': image, 'sources': sources}
    proof = {'process': {'pid': 42, 'start_ticks': '123', 'cmdline_sha256': '4' * 64,
                         'exe': profile['exe'], 'cwd': profile['cwd'], 'import_env_sha256': '5' * 64, 'cgroup': '/docker/' + container['Id'],
                         'namespaces': {'net': 'namespace-1'}},
             'sources': {path: {'sha256': value, 'metadata': [1, 2]} for path, value in copies.items()},
             'executable': {'sha256': profile['exe_sha256'], 'metadata': [1, 3]}}
    class Docker:
        def __init__(self): self.calls = []; self.after = None
        def inspect(self, identity):
            self.calls.append(identity)
            return deepcopy(self.after if len(self.calls) > 1 and self.after is not None else container)
    class Process:
        def __init__(self): self.calls = []; self.post_error = None; self.closed = False
        @contextmanager
        def capture(self, pid, cid, paths):
            self.calls.append((pid, cid, set(paths)))
            try:
                yield proof
                if self.post_error: raise self.post_error
            finally:
                self.closed = True
    return Docker(), Process(), container, profile, descriptor, proof


def call(world):
    api, process, _, profile, descriptor, _ = world
    return observe_container(api, 'daemon', profile, descriptor, process=process)


def test_snapshot_qualifies_both_copies_and_keeps_raw_config_private(world):
    result = call(world)
    api, process, _, profile, descriptor, _ = world
    assert result['artifact_sha256'] == canonical_digest(descriptor)
    assert len(api.calls) == 2 and set(api.calls) == {'a' * 64}
    assert process.calls == [(42, 'a' * 64, set(profile['copies']))]
    assert process.closed is True
    assert 'SECRET' not in str(result) and 'Config' not in result['evidence']
    world[5]['process']['start_ticks'] = 'new'
    assert call(world)['generation_sha256'] != result['generation_sha256']


@pytest.mark.parametrize('change', ['image', 'id', 'config', 'stopped'])
def test_initial_conflicts_prevent_process_reads(world, change):
    api, process, container, *_ = world
    if change == 'image': container['Image'] = 'sha256:' + 'e' * 64
    elif change == 'id': container['Id'] = 'b' * 64
    elif change == 'config': container['Config']['Env'] = ['CHANGED=true']
    else: container['State']['Running'] = False
    with pytest.raises(ValueError): call(world)
    assert process.calls == [] and len(api.calls) == 1


@pytest.mark.parametrize('change', ['image', 'config', 'pid', 'started', 'restart', 'absent'])
def test_docker_change_during_capture_is_rejected(world, change):
    api, process, container, *_ = world
    after = deepcopy(container)
    if change == 'image': after['Image'] = 'sha256:' + 'e' * 64
    elif change == 'config': after['HostConfig']['NetworkMode'] = 'other'
    elif change == 'pid': after['State']['Pid'] = 43
    elif change == 'started': after['State']['StartedAt'] = 'new'
    elif change == 'restart': after['RestartCount'] = 1
    else: after = {}
    api.after = after
    with pytest.raises(ValueError): call(world)
    assert process.closed is True


@pytest.mark.parametrize('change', ['source', 'missing-source', 'binary', 'command', 'exe', 'cwd', 'environment'])
def test_process_or_execution_asset_conflict_is_rejected(world, change):
    proof = world[5]
    path = next(iter(proof['sources']))
    if change == 'source': proof['sources'][path]['sha256'] = 'f' * 64
    elif change == 'missing-source': proof['sources'].pop(path)
    elif change == 'binary': proof['executable']['sha256'] = 'f' * 64
    elif change == 'command': proof['process']['cmdline_sha256'] = 'f' * 64
    elif change == 'cwd': proof['process']['cwd'] = '/other'
    elif change == 'environment': proof['process']['import_env_sha256'] = 'f' * 64
    else: proof['process']['exe'] = '/other/python'
    with pytest.raises(ValueError): call(world)
    assert world[1].closed is True


def test_process_exit_or_post_observation_failure_prevents_evidence(world):
    world[1].post_error = ValueError('original process exited')
    with pytest.raises(ValueError, match='original process exited'): call(world)
    assert world[1].closed is True


@pytest.mark.parametrize('missing', ['copy', 'bootstrap'])
def test_incomplete_import_profile_is_rejected_before_docker(world, missing):
    copies = world[3]['copies']
    path = '/usr/local/bin/dnlab-lab-cleanup' if missing == 'bootstrap' else next(p for p in copies if p.startswith('/opt/'))
    copies.pop(path)
    with pytest.raises(ValueError): call(world)
    assert world[0].calls == []


@pytest.mark.skipif(os.geteuid() != 0, reason='root-owned execution source profile')
def test_real_file_reader_rejects_symlinks_and_unsafe_mode_in_private_tree(tmp_path):
    directory = tmp_path / 'package'; directory.mkdir()
    source = directory / 'source.py'; source.write_bytes(b'opaque source, never executed')
    source.chmod(0o644)
    (directory / 'alias.py').symlink_to(source.name)
    fd = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        result = source_at(fd, '/package/source.py')
        assert result['sha256'] == hashlib.sha256(source.read_bytes()).hexdigest()
        with pytest.raises(OSError): source_at(fd, '/package/alias.py')
        source.chmod(0o666)
        with pytest.raises(ValueError, match='unsafe executable/source metadata'):
            source_at(fd, '/package/source.py')
    finally:
        os.close(fd)


@pytest.mark.parametrize('event', ['POLLIN', 'POLLERR', 'POLLNVAL'])
def test_pidfd_events_refuse_before_any_proc_read_and_close_descriptor(tmp_path, monkeypatch, event):
    import select
    import cleanup_container_observer as module
    source = tmp_path / 'fake-pidfd'; source.write_text('never execute')
    held = os.open(source, os.O_RDONLY)
    issued = []
    def fake_pidfd(pid, flags):
        assert pid == 42 and flags == 0
        issued.append(os.dup(held))
        return issued[-1]
    class Poll:
        def register(self, fd, mask): assert fd == issued[0] and mask == select.POLLIN
        def poll(self, timeout): return [(issued[0], getattr(select, event))]
    monkeypatch.setattr(module.os, 'pidfd_open', fake_pidfd)
    monkeypatch.setattr(module.select, 'poll', Poll)
    process = module.LinuxProcess()
    def no_proc(*args): raise AssertionError('proc must not be read')
    monkeypatch.setattr(process, '_view', no_proc)
    try:
        with pytest.raises(ValueError, match='exited or pidfd observation failed'):
            with process.capture(42, 'a' * 64, {}):
                raise AssertionError('must not yield')
        with pytest.raises(OSError): os.fstat(issued[0])
    finally:
        os.close(held)


def test_import_environment_covers_python_loader_and_paths_without_retaining_secrets():
    from cleanup_container_observer import import_environment_digest
    raw = b'PATH=/usr/bin\0HOME=/root\0PYTHONPATH=/qualified\0LD_LIBRARY_PATH=/lib\0PASSWORD=private\0'
    expected = {'PATH': '/usr/bin', 'HOME': '/root', 'PYTHONPATH': '/qualified', 'LD_LIBRARY_PATH': '/lib'}
    assert import_environment_digest(raw) == canonical_digest(expected)
    assert import_environment_digest(raw.replace(b'PASSWORD=private', b'PASSWORD=other')) == canonical_digest(expected)
    with pytest.raises(ValueError, match='duplicate import environment'):
        import_environment_digest(raw + b'PYTHONPATH=/other\0')
