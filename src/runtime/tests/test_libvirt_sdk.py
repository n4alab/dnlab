"""SDK boundary tests; no socket, libvirt daemon or guest is started."""
from contextlib import contextmanager
from copy import deepcopy
from types import SimpleNamespace
import stat

import pytest

from dnlab_runtime import libvirt_sdk as client
from dnlab_runtime.libvirt_session import DedicatedSession
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint

UUID = '00000000-0000-4000-8000-000000000001'
XML = f'<domain type="kvm"><name>sample</name><uuid>{UUID}</uuid></domain>'


@pytest.fixture
def case(monkeypatch):
    profile = dict(host_id='master', uid=1001, gid=1002, uri='qemu:///session',
                   socket='/run/dnlab/libvirt-sock', runtime_root='/run/dnlab', state_root='/var/lib/dnlab')
    def resource(kind, inode):return dict(device=4, inode=inode, uid=1001, gid=1002, mode=kind | 0o700)
    proof = dict(profile_sha256=fingerprint(profile), config_sha256='a'*64,
                 daemon=dict(uid=1001, gid=1002, boot_id='synthetic', pid=123, start_ticks=1, executable_sha256='b'*64),
                 socket=resource(stat.S_IFSOCK, 10),
                 directories=dict(state=resource(stat.S_IFDIR, 11), runtime=resource(stat.S_IFDIR, 12)))
    session = DedicatedSession(profile, lambda: deepcopy(proof))
    calls = []
    class Domain:
        uuid = UUID
        def UUIDString(self):return self.uuid
        def name(self):return 'sample'
        def createWithFlags(self, flags):calls.append(('start', flags))
        def resume(self):calls.append(('resume',))
        def autostart(self):return 0
        def snapshotNum(self, flags):assert flags == 0;return 0
        def listAllCheckpoints(self, flags):assert flags == 0;return []
        def undefineFlags(self, flags):calls.append(('undefine',flags));return 0
    domain = Domain()
    class Raw:
        uri = None
        error = None
        hook = None
        def isAlive(self):return 1
        def getURI(self):return self.uri if self.uri is not None else self.requested_uri
        def close(self):calls.append(('close',))
        def listAllDomains(self, flags):return [domain]
        def lookupByUUIDString(self, uuid):
            if self.error:raise self.error
            return domain
        def defineXMLFlags(self, xml, flags):
            calls.append(('define', xml, flags))
            if self.hook:self.hook()
            if self.error:raise self.error
            return domain
    raw = Raw()
    def open_auth(uri, credentials, flags):
        calls.append(('open', uri, flags))
        raw.requested_uri = uri
        assert credentials[0] == [] and credentials[1]([], None) == -1
        return raw
    sdk = SimpleNamespace(VIR_CONNECT_RO=1, VIR_CONNECT_NO_ALIASES=2, openAuth=open_auth)
    endpoint = dict(path=profile['socket'], **proof['socket'], peer_pid=123, peer_uid=1001, peer_gid=1002)
    @contextmanager
    def pin(original):
        assert original == session.proof()
        yield 17, endpoint
    metadata = SimpleNamespace(**{'st_'+key:value for key,value in
        dict(dev=4, ino=10, uid=1001, gid=1002, mode=stat.S_IFSOCK|0o700).items()})
    monkeypatch.setattr(client.os, 'fstat', lambda fd: metadata)
    monkeypatch.setenv('LIBVIRT_AUTOSTART', '0')
    def connect(readonly=True):return client.open_connection(session, pin_socket=pin, readonly=readonly, sdk=sdk)
    return SimpleNamespace(connect=connect, calls=calls, raw=raw, domain=domain, proof=proof,
                           endpoint=endpoint, metadata=metadata)


def test_pinned_readonly_connection_expires_domain_handles(case):
    with case.connect() as connection:
        domain = connection.listAllDomains()[0]
        assert domain.UUIDString() == UUID
    assert case.calls == [('open', 'qemu+unix:///session?socket=%2Fproc%2Fself%2Ffd%2F17&mode=legacy', 3), ('close',)]
    with pytest.raises(RuntimeErrorBase, match='expired'):domain.name()


def test_write_connection_defines_once_and_starts_paused(case):
    with case.connect(False) as connection:
        domain = connection.defineXMLFlags(XML, 1)
        domain.createWithFlags(1)
        domain.resume()
    assert case.calls[0][-1] == 2
    assert [call[0] for call in case.calls] == ['open', 'define', 'start', 'resume', 'close']


@pytest.mark.parametrize('action', ['define', 'start', 'resume', 'undefine'])
def test_readonly_mutation_rejected_before_sdk(case, action):
    with case.connect() as connection:
        domain = connection.lookupByUUIDString(UUID)
        with pytest.raises(Conflict, match='readonly'):
            if action == 'define':connection.defineXMLFlags(XML, 1)
            elif action == 'start':domain.createWithFlags(1)
            elif action == 'resume':domain.resume()
            else:domain.undefineFlags(0)
    assert [call[0] for call in case.calls] == ['open', 'close']


@pytest.mark.parametrize('change', ['peer', 'fd'])
def test_foreign_socket_rejected_before_open(case, change):
    if change == 'peer':case.endpoint['peer_pid'] += 1
    else:case.metadata.st_ino += 1
    with pytest.raises(RuntimeErrorBase):
        with case.connect():pytest.fail('foreign socket accepted')
    assert case.calls == []


def test_autostart_must_be_disabled(case, monkeypatch):
    monkeypatch.delenv('LIBVIRT_AUTOSTART')
    with pytest.raises(RuntimeErrorBase, match='autostart'):
        with case.connect():pass
    assert case.calls == []


@pytest.mark.parametrize('uri', ['qemu:///system', 'qemu:///session', 'qemu+unix:///session?socket=/foreign&mode=legacy'])
def test_uri_mismatch_closes_without_fallback(case, uri):
    case.raw.uri = uri
    with pytest.raises(RuntimeErrorBase, match='URI'):
        with case.connect():pass
    assert [call[0] for call in case.calls] == ['open', 'close']


def test_error_identity_is_preserved_and_no_define_retry(case):
    error = OSError('lost reply')
    case.raw.error = error
    with case.connect(False) as connection:
        with pytest.raises(OSError) as caught:connection.defineXMLFlags(XML, 1)
        assert caught.value is error
    assert sum(call[0] == 'define' for call in case.calls) == 1


def test_generation_changed_during_define_latches_connection(case):
    case.raw.hook = lambda:case.proof['daemon'].update(start_ticks=2)
    with case.connect(False) as connection:
        with pytest.raises(Conflict):connection.defineXMLFlags(XML, 1)
        with pytest.raises(RuntimeErrorBase, match='unavailable'):connection.getURI()
    assert sum(call[0] == 'define' for call in case.calls) == 1


def test_replaced_domain_uuid_refused(case):
    with case.connect(False) as connection:
        domain = connection.lookupByUUIDString(UUID)
        case.domain.uuid = '00000000-0000-4000-8000-000000000002'
        with pytest.raises(Conflict, match='UUID'):domain.resume()
    assert not any(call[0] == 'resume' for call in case.calls)


@pytest.mark.parametrize('flags', [0, 2, True])
def test_unpaused_start_refused(case, flags):
    with case.connect(False) as connection:
        with pytest.raises(RuntimeErrorBase, match='pause'):connection.lookupByUUIDString(UUID).createWithFlags(flags)
    assert not any(call[0] == 'start' for call in case.calls)


def test_retained_state_queries_and_definition_only_undefine(case):
    with case.connect(False) as connection:
        domain = connection.lookupByUUIDString(UUID)
        assert domain.autostart() == domain.snapshotNum(0) == domain.checkpointCount() == 0
        assert domain.undefineFlags(0) == 0
    assert ('undefine',0) in case.calls


@pytest.mark.parametrize('flags', [1, 2, False])
def test_undefine_cannot_delete_external_state_through_flags(case, flags):
    with case.connect(False) as connection:
        with pytest.raises(RuntimeErrorBase, match='definition-only'):
            connection.lookupByUUIDString(UUID).undefineFlags(flags)
    assert not any(call[0] == 'undefine' for call in case.calls)
