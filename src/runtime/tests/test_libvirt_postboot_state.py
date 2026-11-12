"""Bounded postboot tree admission using synthetic lineage and temp files."""
from copy import deepcopy
import os

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_activation import activation
from test_libvirt_install import request_profile
from tools.libvirt_postboot_state import PostBootEmptyState
from tools.libvirt_service_generation import directory_identity


@pytest.fixture
def tree(activation, tmp_path):
    driver, _, value, _ = activation
    previous = deepcopy(driver.apply(value['id']))
    old = previous['installation']
    # Filesystem-only fixture uses the invoking test UID/GID; journal tests
    # independently exercise the dedicated non-root profile contract.
    old['profile']['session'].update(uid=os.getuid(), gid=os.getgid())
    for item in old['items']:
        if item['spec']['kind'] == 'directory' and item['phase'] == 'created':
            path = tmp_path / item['spec']['path'].lstrip('/')
            path.mkdir(parents=True, exist_ok=True, mode=0o700)
            path.chmod(0o700)
            item['proof']['identity'] = directory_identity(path.stat())
    profile = old['profile']
    (tmp_path / profile['driver_layout']['qemu_config'].lstrip('/')).touch()
    previous['installation_sha256'] = fingerprint(old)
    previous['empty_proof']['installation_sha256'] = fingerprint(old)
    source = deepcopy(old)
    source['context'] = dict(boot_id='new-boot')
    source['postboot'] = dict(kind='postboot-session-view-v1', source_sha256=fingerprint(old),
                              qualification_id='new-qualification', recovery_id='new-recovery')
    mutable = tmp_path / profile['driver_layout']['mutable_root'].lstrip('/')
    for name in ('checkpoint','dump','lib','nvram','ram','save','snapshot'):
        (mutable/name).mkdir(mode=0o700)
    caps = tmp_path / profile['client_environment']['XDG_CACHE_HOME'].lstrip('/') / 'libvirt/qemu/cache/capabilities'
    caps.mkdir(parents=True, mode=0o700)
    for parent in (caps.parent, caps.parent.parent, caps.parent.parent.parent):parent.chmod(0o700)
    cache = caps / ('a'*64+'.xml')
    cache.write_text('<qemuCaps><emulator>/usr/bin/qemu-system-x86_64</emulator></qemuCaps>')
    cache.chmod(0o600)
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    def observer(approved=None):return PostBootEmptyState(root, source, previous, approved=approved)
    try:yield observer, mutable, cache, dict.fromkeys(profile['service_order']), source
    finally:os.close(root)


def test_capture_is_explicit_and_approved_tree_rechecked(tree):
    observer, _, _, receipts, _ = tree
    with pytest.raises(Conflict, match='approved'):observer()(receipts)
    approved = observer().capture()
    observer(approved)(receipts)
    assert observer().capture() == approved


@pytest.mark.parametrize('name', ['guest.xml', 'autostart', 'save/guest.save', 'nvram/guest.fd', 'lib/guest'])
def test_any_domain_or_state_entry_refused(tree, name):
    observer, mutable, _, _, _ = tree
    (mutable/name).touch()
    with pytest.raises(Conflict, match='unexpected postboot'):observer().capture()


@pytest.mark.parametrize('change', ['content', 'replace', 'mode', 'symlink', 'hardlink', 'fifo', 'entity', 'root'])
def test_unqualified_cache_or_changed_approval_refused(tree, change):
    observer, _, cache, receipts, _ = tree
    approved = observer().capture()
    if change == 'content':cache.write_text('<qemuCaps><changed/></qemuCaps>')
    elif change == 'replace':
        cache.rename(cache.with_suffix('.original'))
        cache.write_text('<qemuCaps/>');cache.chmod(0o600)
    elif change == 'mode':cache.chmod(0o644)
    elif change == 'symlink':cache.unlink();cache.symlink_to('/unrelated')
    elif change == 'hardlink':os.link(cache,cache.with_name('b'*64+'.xml'))
    elif change == 'fifo':cache.unlink();os.mkfifo(cache,0o600)
    elif change == 'entity':cache.write_text('<!DOCTYPE qemuCaps><qemuCaps/>')
    else:cache.write_text('<domain/>')
    with pytest.raises((Conflict,OSError)):observer(approved)(receipts)


def test_admission_is_bound_to_exact_successor_source(tree):
    observer, _, _, receipts, source = tree
    approved = observer().capture()
    source['context']['boot_id'] = 'different-new-boot'
    with pytest.raises(Conflict, match='admission differs'):observer(approved)(receipts)


def test_approved_tree_still_rejects_runtime_domain_state(tree):
    observer, _, _, receipts, source = tree
    approved = observer().capture()
    root = observer().root
    runtime = source['profile']['session']['runtime_root']+'/libvirt'
    fd=os.open(runtime.lstrip('/'), os.O_RDONLY|os.O_DIRECTORY, dir_fd=root)
    try:
        os.mkdir('qemu', dir_fd=fd)
        with pytest.raises(Conflict, match='pre-existing libvirt state'):observer(approved)(receipts)
    finally:os.close(fd)
