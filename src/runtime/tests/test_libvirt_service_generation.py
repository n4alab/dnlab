"""Dedicated daemon process and socket observation without a host libvirt connection."""

from contextlib import contextmanager
from copy import deepcopy
import os
import stat
import struct
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_install import install, request_profile
from test_libvirt_service_observer import service
from tools.libvirt_service_generation import NativeServiceObserver, ServiceSocketReader, directory_identity


@pytest.mark.parametrize('fault', [None, 'peer', 'replacement'])
def test_socket_probe_binds_original_parent_endpoint_and_peer(tmp_path, monkeypatch, fault):
    runtime = '/run/dnlab/libvirt-session'
    library = tmp_path / runtime.lstrip('/') / 'libvirt'
    library.mkdir(parents=True)
    installation = dict(profile=dict(session=dict(runtime_root=runtime, socket=runtime + '/libvirt/libvirt-sock')),
                        items=[])
    for path in (runtime, runtime + '/libvirt'):
        proof = directory_identity((tmp_path / path.lstrip('/')).stat())
        installation['items'].append(dict(
            spec=dict(kind='directory', path=path), phase='created', proof=dict(identity=proof)))
    info = SimpleNamespace(st_dev=library.stat().st_dev, st_ino=91, st_mode=stat.S_IFSOCK | 0o700,
                           st_uid=1001, st_gid=1002, st_size=0, st_mtime_ns=0, st_ctime_ns=0)
    real_stat = os.stat

    def stat_socket(path, *args, **kwargs):
        if path == 'virtlogd-sock' and kwargs.get('dir_fd') is not None:
            assert os.fstat(kwargs['dir_fd']).st_ino == library.stat().st_ino
            return deepcopy(info)
        return real_stat(path, *args, **kwargs)

    class Stream:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, seconds):
            assert seconds == 5

        def connect(self, path):
            assert path.startswith('/proc/self/fd/') and path.endswith('/virtlogd-sock')
            assert os.fstat(int(path.split('/')[4])).st_ino == library.stat().st_ino
            if fault == 'replacement':
                info.st_ino += 1

        def getsockopt(self, *_):
            return struct.pack('iII', 99 if fault == 'peer' else 42, 1001, 1002)

    monkeypatch.setattr(os, 'stat', stat_socket)
    root = os.open(tmp_path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        reader = ServiceSocketReader(root, installation, socket_factory=lambda *_: Stream())
        spec = dict(role='virtlogd', unit='dnlab-virtlogd.service', uid=1001, gid=1002)
        if fault:
            with pytest.raises(Conflict, match='peer differs|path changed'):
                reader(spec, 42)
        else:
            result = reader(spec, 42)
            assert result['path'] == runtime + '/libvirt/virtlogd-sock'
            assert result['peer_pid'] == 42 and result['inode'] == 91
    finally:
        os.close(root)


def test_daemon_observation_links_original_unit_process_and_peer(service):
    installation, make = service
    _, witness, _, item, _ = make('libvirtd')
    spec = item['spec']
    unit = witness['unit']
    units = {spec['unit']: dict(load_state='loaded', unit=unit, files=witness['files'])}
    request = dict(installation_sha256=fingerprint(installation), context=installation['context'], spec=spec)
    invocation = dict(pid=unit['pid'], invocation_id=unit['invocation_id'],
                      process_reference=dict(pid=unit['pid'], invocation_id=unit['invocation_id']))
    calls = []

    class Processes:
        @contextmanager
        def observe(self, reference, original_request):
            assert reference == invocation['process_reference'] and original_request == request
            calls.append('pin-enter')
            yield witness['process']
            calls.append('pin-exit')

    def socket_reader(original_spec, pid):
        assert original_spec == spec and pid == invocation['pid']
        calls.append('socket')
        return witness['socket']

    observer = NativeServiceObserver(installation, unit_reader=lambda: units,
                                     processes=Processes(), socket_reader=socket_reader)
    assert observer(request, invocation) == witness
    assert calls == ['pin-enter', 'socket', 'pin-exit']
    unit['invocation_id'] = 'f' * 32
    with pytest.raises(Conflict, match='original service invocation'):
        observer(request, invocation)
    assert calls == ['pin-enter', 'socket', 'pin-exit']
