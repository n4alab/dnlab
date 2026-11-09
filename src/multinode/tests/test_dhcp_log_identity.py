"""Digest-qualified DHCP logs must remain bound to their original writer."""
import copy
import hashlib
import os
from contextlib import ExitStack

import pytest
from dnlab_multinode.services.jumphost_host import (
    DHCPHostService, DHCP_LOG_PROFILES, JumphostError, dhcp_validate_log,
)


MAIN = 'log-facility=/run/dnlab-dhcp.log\nlog-dhcp\n'


def log_proof(image=None):
    service = {'container': {}, 'profile': {'uid': 65534}, 'host_pid': 123, 'start': '2345'}
    image = image or next(iter(DHCP_LOG_PROFILES))
    profile = DHCP_LOG_PROFILES[image]
    service['container']['image'] = image
    service['binary_sha256'] = profile['binary_sha256']
    value = {'directories': [dict(device=9, inode=i, uid=0, gid=0, mode=0o755, directory=True) for i in (1, 2)],
             'file': dict(device=9, inode=33, uid=65534, gid=0, mode=0o660, regular=True, nlink=1),
             'writer': dict(host_pid=service['host_pid'], start=service['start']),
             'configuration_sha256': hashlib.sha256(MAIN.encode()).hexdigest()}
    return service, value


@pytest.mark.parametrize('image',list(DHCP_LOG_PROFILES))
def test_exact_qualified_group_writable_profile_accepted(image):
    service, value = log_proof(image)
    assert dhcp_validate_log(value, service, MAIN, copy.deepcopy(value)) == value


@pytest.mark.parametrize('change', ['image', 'binary', 'config', 'owner', 'group', 'world-write',
    'mode', 'type', 'hardlink', 'directory-owner', 'directory-write', 'directory-type',
    'missing-directory', 'writer-pid', 'writer-start', 'config-hash'])
@pytest.mark.parametrize('image',list(DHCP_LOG_PROFILES))
def test_log_profile_rejects_unqualified_resources(change,image):
    service, value = log_proof(image); main = MAIN
    if change == 'image': service['container']['image'] = 'sha256:' + 'f' * 64
    if change == 'binary': service['binary_sha256'] = 'f' * 64
    if change == 'config': main += 'log-facility=/tmp/other\n'
    if change == 'owner': value['file']['uid'] = 0
    if change == 'group': value['file']['gid'] = 30
    if change == 'world-write': value['file']['mode'] = 0o666
    if change == 'mode': value['file']['mode'] = 0o664
    if change == 'type': value['file']['regular'] = False
    if change == 'hardlink': value['file']['nlink'] = 2
    if change == 'directory-owner': value['directories'][1]['uid'] = 65534
    if change == 'directory-write': value['directories'][1]['mode'] = 0o775
    if change == 'directory-type': value['directories'][1]['directory'] = False
    if change == 'missing-directory': value['directories'].pop()
    if change == 'writer-pid': value['writer']['host_pid'] += 1
    if change == 'writer-start': value['writer']['start'] = 'reused'
    if change == 'config-hash': value['configuration_sha256'] = 'f' * 64
    with pytest.raises(JumphostError): dhcp_validate_log(value, service, main)


@pytest.mark.parametrize('change', ['inode', 'device', 'parent-inode'])
@pytest.mark.parametrize('image',list(DHCP_LOG_PROFILES))
def test_same_metadata_new_generation_rejected(change,image):
    service, old = log_proof(image); current = copy.deepcopy(old)
    if change == 'parent-inode': current['directories'][1]['inode'] += 1
    else: current['file'][change] += 1
    with pytest.raises(JumphostError, match='generation changed'):
        dhcp_validate_log(current, service, MAIN, old)


@pytest.mark.parametrize('writer', ['missing', 'readonly', 'other-inode', 'writable'])
def test_host_reader_requires_actual_writable_descriptor(tmp_path, monkeypatch, writer):
    service, _ = log_proof()
    root = tmp_path / 'root'; run = root / 'run'; run.mkdir(parents=True)
    log = run / 'dnlab-dhcp.log'; log.write_text('log'); log.chmod(0o660)
    proc = tmp_path / 'proc'; (proc / 'fd').mkdir(parents=True); (proc / 'fdinfo').mkdir()
    if writer != 'missing':
        target = log
        if writer == 'other-inode': target = run / 'other'; target.write_text('other')
        (proc / 'fd' / '7').symlink_to(target)
        (proc / 'fdinfo' / '7').write_text('flags:\t' + ('0100000' if writer == 'readonly' else '0102001') + '\n')
    scope = DHCPHostService(None, {'dhcp_assets': {'files': {'main': {'content': MAIN}}}}, None)
    with ExitStack() as stack:
        stack.callback(scope.stack.close)
        scope.root = scope.open(str(root), directory=True)
        scope.run_dir = scope.open('run', parent=scope.root, directory=True)
        pfd = scope.open(str(proc), directory=True)
        # Exercise actual directory traversal/stat/fdinfo; profile validation is
        # covered separately without requiring root-owned test files.
        monkeypatch.setattr('dnlab_multinode.services.jumphost_host.dhcp_validate_log', lambda v, *_: v)
        if writer == 'writable': assert scope.log_identity(service, pfd)['writer']['host_pid'] == service['host_pid']
        else:
            with pytest.raises(JumphostError, match='no qualified service writer'): scope.log_identity(service, pfd)
