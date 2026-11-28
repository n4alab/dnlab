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


@pytest.mark.parametrize('fault', [None, 'unwitnessed', 'pidfd_error', 'live', 'scope_present', 'unit_present', 'context'])
def test_original_exit_requires_retained_pidfd_and_unit_absence(monkeypatch, fault):
    context = dict(boot_id='original', namespaces={})
    row = dict(source_id='/run/systemd/transient/session-c35.scope')
    proof = dict(session_id='c35', context_sha256=module.canonical_digest(context),
        source_sha256=module.canonical_digest(row), qualification_sha256='a'*64)
    state = dict(context=deepcopy(context), events=[])
    recorded, closed = [], []

    def qualify(sid, value, *, retain, **kwargs):
        assert value == row and sid == 'c35'
        retain(99, deepcopy(proof))
        return deepcopy(proof)

    monkeypatch.setattr(module, 'qualify', qualify)
    monkeypatch.setattr(module.os, 'dup', lambda fd: 100)
    monkeypatch.setattr(module.os, 'close', closed.append)
    monkeypatch.setattr(module.select, 'poll', lambda: N(register=lambda *args: None,
        poll=lambda timeout: state['events']))
    monkeypatch.setattr(module.os.path, 'lexists', lambda path: fault == 'scope_present')
    monkeypatch.setattr(module, 'query', lambda *args: dict(Id='session-c35.scope',
        LoadState='loaded' if fault == 'unit_present' else 'not-found',
        ActiveState='inactive', SubState='dead', InvocationID=''))
    witness = module.SessionWitnesses(context=context, read_context=lambda: state['context'],
        systemctl_sha256='f'*64, loginctl_sha256='f'*64, record=recorded.append)
    if fault != 'unwitnessed':
        assert witness.qualify('c35', row) == proof
    state['events'] = [] if fault == 'live' else [(100, 8 if fault == 'pidfd_error' else 1)]
    if fault == 'context':
        state['context']['boot_id'] = 'different'
    try:
        if fault:
            with pytest.raises(ValueError):
                witness.removed('c35', row)
            assert recorded == []
        else:
            result = witness.removed('c35', row)
            assert result == witness.removed('c35', row)
            assert len(recorded) == 1 and result['qualification_sha256'] == proof['qualification_sha256']
            witness.check_exits(dict(candidates=[]))
            with pytest.raises(ValueError, match='retired'):
                witness.qualify('c35', row)
    finally:
        witness.close()
        witness.close()
    assert closed == ([] if fault == 'unwitnessed' else [100])
