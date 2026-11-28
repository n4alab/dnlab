"""Exact SSH profile with synthetic systemd/proc/pidfd providers only."""
from copy import deepcopy
import hashlib
from pathlib import Path
import sys
from types import SimpleNamespace as N

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'tools'))
import cleanup_gate_ssh_baseline as module


@pytest.mark.parametrize('fault', [None, 'directive', 'unit', 'namespace', 'uid', 'exited', 'generation'])
def test_exact_session_profile_and_identity_boundaries(monkeypatch, fault):
    sid = 'c35'
    scope = 'session-c35.scope'
    context = dict(boot_id='original', namespaces={'net': dict(device=4, inode=42)})
    raw = module.definition(sid)
    row = dict(source_id='/run/systemd/transient/'+scope, kind='file',
        metadata=[57, 35, 0o100644, 0, 0, len(raw), 10, 10], sha256=hashlib.sha256(raw).hexdigest())
    session = dict(Id=sid, Name='root', User='0', Service='sshd', Remote='yes', Class='user',
        Type='tty', State='active', Scope=scope, Leader='123', TimestampMonotonic='42')
    unit = dict(Id=scope, LoadState='loaded', ActiveState='active', SubState='running',
        FragmentPath=row['source_id'], ControlGroup='/user.slice/user-0.slice/'+scope,
        Transient='yes', Slice='user-0.slice', InvocationID='a'*32)
    reads = []

    def query(binary, args, digest):
        assert digest == 'f'*64
        reads.append(binary)
        if 'loginctl' in binary:
            return deepcopy(session)
        result = deepcopy(unit)
        if fault == 'unit':
            result['Transient'] = 'no'
        if fault == 'generation' and len(reads) > 2:
            result['InvocationID'] = 'b'*32
        return result

    def read(path, limit):
        path = str(path)
        if path.endswith('/stat'):
            return b'123 (sshd-session) '+b'S '+b'0 '*18+b'100 0\n', []
        if path.endswith('/status'):
            return (b'Uid:\t1\t1\t1\t1\n' if fault == 'uid' else b'Uid:\t0\t0\t0\t0\n'), []
        if path.endswith('/cgroup'):
            return ('0::'+unit['ControlGroup']+'\n').encode(), []
        if path.endswith('/cmdline'):
            return b'sshd-session\0', []
        assert path == row['source_id']
        return (raw+b'Other=yes\n' if fault == 'directive' else raw), row['metadata']

    closed = []
    monkeypatch.setattr(module, 'query', query)
    monkeypatch.setattr(module, 'read_regular', read)
    monkeypatch.setattr(module.os, 'pidfd_open', lambda pid, flags: 999)
    monkeypatch.setattr(module.os, 'close', closed.append)
    monkeypatch.setattr(module.os, 'lstat', lambda path: N(st_nlink=1))
    monkeypatch.setattr(module.select, 'poll', lambda: N(register=lambda *args: None,
        poll=lambda timeout: [(999, 1)] if fault == 'exited' else []))
    monkeypatch.setattr(Path, 'stat', lambda path: N(st_dev=4, st_ino=43 if fault == 'namespace' else 42))
    if fault:
        with pytest.raises(ValueError):
            module.qualify(sid, row, context=context, systemctl_sha256='f'*64, loginctl_sha256='f'*64)
    else:
        result = module.qualify(sid, row, context=context, systemctl_sha256='f'*64, loginctl_sha256='f'*64)
        assert result['source_sha256'] == module.canonical_digest(row)
        assert result['session_id'] == sid and len(reads) == 4
    assert closed == ([] if fault == 'unit' else [999])
