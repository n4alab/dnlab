"""Constrained formatter protocol on temporary bytes, without executing QEMU."""
from copy import deepcopy
import hashlib
import io
import json
import os

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_overlay_worker import MARKER, command_plan, file_identity, serve, validate_command
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def formatter(tmp_path):
    executable = tmp_path / 'fake-qemu-img'
    data = b'\x7fELFsynthetic executable'
    executable.write_bytes(data);executable.chmod(0o755)
    target = tmp_path / 'overlay.qcow2'
    target.touch(mode=0o600)
    binary = os.open(executable, os.O_RDONLY);fd = os.open(target, os.O_RDWR)
    spec = dict(id='boot', path=str(target), base_path=str(tmp_path / 'base.qcow2'), base_format='qcow2',
                base_sha256='e' * 64, uid=os.getuid(), gid=os.getgid(), mode=0o600)
    request = dict(operation_id='a' * 32, nonce='b' * 32, spec=spec)
    command = command_plan(request, dict(path='/usr/bin/qemu-img', sha256=hashlib.sha256(data).hexdigest()), fd, file_identity(os.fstat(fd)))
    os.setxattr(fd, MARKER, fingerprint(request).encode('ascii'))
    try:yield command, binary, fd
    finally:os.close(fd);os.close(binary)


def stream(command, *, released=True):
    packet = json.dumps(dict(token='c' * 32, command=command)) + '\n'
    if released:packet += json.dumps(dict(release='c' * 32, command_sha256=fingerprint(command))) + '\n'
    return io.StringIO(packet)


def test_eof_never_executes_formatter(formatter):
    command, binary, fd = formatter;called = []
    with pytest.raises(Conflict):serve(stream(command, released=False), io.StringIO(), binary, fd, execute=lambda *args:called.append(args))
    assert called == [] and os.fstat(fd).st_size == 0


def test_exact_release_hands_original_empty_inode_to_same_pid_exec(formatter):
    command, binary, fd = formatter;sink = io.StringIO();called = []
    def execute(*args):
        called.append(args)
        raise SystemExit(0)
    with pytest.raises(SystemExit):serve(stream(command), sink, binary, fd, execute=execute)
    assert called == [(binary, command['argv'], command['environment'])]
    assert json.loads(sink.getvalue()) == dict(ready='c' * 32, command_sha256=fingerprint(command))
    assert os.fstat(fd).st_size == 0


@pytest.mark.parametrize('fault', ['nonempty', 'marker', 'credentials', 'link'])
def test_foreign_or_written_target_is_rejected_before_exec(formatter, tmp_path, fault):
    command, binary, fd = formatter;called = []
    if fault == 'nonempty':os.write(fd, b'already formatted')
    elif fault == 'marker':os.setxattr(fd, MARKER, b'foreign')
    elif fault == 'credentials':command['target']['identity']['uid'] += 1
    else:os.link(tmp_path/'overlay.qcow2', tmp_path/'alias')
    with pytest.raises(TemplateError):serve(stream(command), io.StringIO(), binary, fd, execute=lambda *args:called.append(args))
    assert called == []


def test_target_is_rechecked_after_release_frame(formatter):
    command, binary, fd = formatter;called = []
    class Changed(io.StringIO):
        def readline(self, *args):
            line = super().readline(*args)
            if 'release' in line:os.write(fd, b'concurrent writer')
            return line
    with pytest.raises(TemplateError, match='empty VM overlay'):
        serve(Changed(stream(command).getvalue()), io.StringIO(), binary, fd, execute=lambda *args:called.append(args))
    assert called == []


@pytest.mark.parametrize('fault', ['overwrite-path', 'repair', 'environment', 'base-format'])
def test_no_arbitrary_qemu_command_or_path_can_reach_exec(formatter, fault):
    original, _, _ = formatter;command = deepcopy(original)
    if fault == 'overwrite-path':command['argv'][-1] = '/foreign/vm.qcow2'
    elif fault == 'repair':command['argv'][1] = 'check'
    elif fault == 'environment':command['environment']['LD_PRELOAD'] = '/foreign.so'
    else:command['target']['base_format'] = 'auto'
    with pytest.raises(TemplateError):validate_command(command)
