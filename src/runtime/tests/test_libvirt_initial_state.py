"""Initial libvirt state checks on temporary directories only."""

from copy import deepcopy
import os

import pytest

from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict
from test_libvirt_service_observer import service, install, request_profile
from tools.libvirt_initial_state import InitialSessionState
from tools.libvirt_service_generation import directory_identity


@pytest.fixture
def state(service, tmp_path):
    source, _ = service
    source = deepcopy(source)
    source['request']['activation_policy'] = 'requisite-after-v1'
    source['profile'] = render_profile(**source['request'])
    profile = source['profile']
    profile['session'].update(uid=os.getuid(), gid=os.getgid())
    directories = [item for item in source['items'] if item['spec']['kind'] == 'directory'
                   and item['phase'] == 'created']
    for item in directories:
        path = tmp_path / item['spec']['path'].lstrip('/')
        path.mkdir(parents=True, exist_ok=True)
        item['proof']['identity'] = directory_identity(path.stat())
    (tmp_path / profile['driver_layout']['qemu_config'].lstrip('/')).touch()
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        observer = InitialSessionState(root, source)
        receipts = dict.fromkeys(profile['service_order'])
        yield observer, receipts, tmp_path
    finally:
        os.close(root)


def test_original_pristine_state_and_acknowledged_helper(state):
    observer, receipts, root = state
    observer(receipts)
    path = root / observer.runtime.lstrip('/') / 'virtlogd.pid'
    path.touch(mode=0o600)
    with pytest.raises(Conflict, match='pre-existing libvirt state'):
        observer(receipts)
    receipts['dnlab-virtlogd.service'] = {'qualified': True}
    observer(receipts)
    path.chmod(0o644)
    with pytest.raises(Conflict, match='unqualified helper runtime entry'):
        observer(receipts)


@pytest.mark.parametrize('entry', ['autostart', 'stopped.xml', 'save', 'runtime-qemu', 'socket-link'])
def test_preexisting_driver_state_blocks_before_daemon_start(state, entry):
    observer, receipts, root = state
    config = next(path for path in observer.contents if path.endswith('/libvirt/qemu'))
    target = root / (config if entry in ('autostart', 'stopped.xml', 'save') else observer.runtime).lstrip('/')
    if entry == 'socket-link':
        (target / 'libvirt-sock').symlink_to('/unrelated/socket')
    else:
        (target / entry).touch()
    with pytest.raises(Conflict, match='pre-existing libvirt state'):
        observer(receipts)


def test_substituted_empty_driver_directory_is_rejected(state):
    observer, receipts, root = state
    config = next(path for path in observer.contents if path.endswith('/libvirt/qemu'))
    path = root / config.lstrip('/')
    path.rename(path.with_name('original'))
    path.mkdir()
    with pytest.raises(Conflict, match='pre-existing libvirt state|original initial libvirt directory differs'):
        observer(receipts)


def test_original_daemon_receipt_allows_driver_initialized_state(state):
    observer, receipts, root = state
    (root / observer.runtime.lstrip('/') / 'qemu').mkdir()
    receipts['dnlab-libvirtd.service'] = {'qualified': True}
    observer(receipts)
