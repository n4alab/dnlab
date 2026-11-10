"""Original service pin tests using an isolated procfs fixture."""

from copy import deepcopy
import os
import select

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from tools.libvirt_service_process import NAMESPACES, open_service_process_pins


INVOCATION = 'a1' * 16


@pytest.fixture
def process(tmp_path):
    proc = tmp_path / 'proc'
    local = proc / str(os.getpid())
    pid = os.getpid() + 1
    target = proc / str(pid)
    for directory in (local / 'ns', target / 'ns', proc / 'sys/kernel/random'):
        directory.mkdir(parents=True)
    (proc / 'self').symlink_to(local.name)
    (proc / 'sys/kernel/random/boot_id').write_text('boot-fixture\n')
    spaces = {}
    for name in NAMESPACES:
        path = local / 'ns' / name
        path.touch()
        os.link(path, target / 'ns' / name)
        info = path.stat()
        spaces[name] = dict(device=info.st_dev, inode=info.st_ino)
    context = dict(host_id='fixture', boot_id='boot-fixture', namespaces=spaces)
    request = dict(context=context, spec=dict(unit='dnlab-virtlogd.service', uid=1001, gid=1002))
    subscription = dict(request_sha256=fingerprint(request), context_sha256=fingerprint(context))
    (target / 'stat').write_text(f'{pid} (daemon ) fixture) S ' + '0 ' * 18 + '1234\n')
    (target / 'status').write_text('Uid:\t1001 1001 1001 1001\nGid:\t1002 1002 1002 1002\n')
    (target / 'environ').write_bytes(f'INVOCATION_ID={INVOCATION}\0'.encode())
    state = dict(exited=False, opened=[])
    reader, writer = os.pipe()

    def pidfd_open(process_pid, flags):
        assert process_pid == pid and flags == 0
        fd = os.dup(reader)
        state['opened'].append(fd)
        return fd

    class Poll:
        def register(self, fd, mask):
            assert mask == select.POLLIN
            self.fd = fd

        def poll(self, timeout):
            assert timeout == 0
            return [(self.fd, select.POLLIN)] if state['exited'] else []

    def keeper():
        return open_service_process_pins(context, read_context=lambda: deepcopy(context),
                                         proc_root=proc, pidfd_open=pidfd_open, poll_factory=Poll)

    try:
        yield keeper, request, subscription, pid, target, state
    finally:
        os.close(reader)
        os.close(writer)


@pytest.mark.parametrize('change', ['exit', 'reused-pid', 'changed-invocation'])
def test_pin_remains_bound_to_first_generation(process, change):
    keeper, request, subscription, pid, target, state = process
    with keeper() as pins:
        reference = pins.pin(request, subscription, pid, INVOCATION)
        assert reference['start_ticks'] == 1234
        assert pins.verify(reference, request, subscription)
        fd, = state['opened']
        os.fstat(fd)
        if change == 'exit':
            state['exited'] = True
        elif change == 'reused-pid':
            target.rename(target.with_name('original'))
            target.mkdir()
        else:
            (target / 'environ').write_bytes(b'INVOCATION_ID=foreign\0')
        assert not pins.verify(reference, request, subscription)
        with pytest.raises(Conflict, match='dedicated service invocation'):
            pins.pin(request, subscription, pid, INVOCATION)
        assert state['opened'] == [fd]
    with pytest.raises(OSError):
        os.fstat(fd)
    assert not pins.verify(reference, request, subscription)
    with keeper() as replacement:
        assert not replacement.verify(reference, request, subscription)
    assert state['opened'] == [fd]


def test_wrong_invocation_releases_uncommitted_descriptor(process):
    keeper, request, subscription, pid, _, state = process
    with keeper() as pins:
        with pytest.raises(Conflict, match='invocation ID differs'):
            pins.pin(request, subscription, pid, 'b2' * 16)
        fd, = state['opened']
        with pytest.raises(OSError):
            os.fstat(fd)
        assert not pins.live
