"""Dedicated session inventory with synthetic process, socket and virsh results."""

from contextlib import contextmanager
from copy import deepcopy
import subprocess
from urllib.parse import parse_qs, urlsplit

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_service_observer import service, install, request_profile
from tools import libvirt_empty_session as empty


@pytest.fixture
def inventory(service, monkeypatch):
    source, make = service
    _, witness, _, _, _ = make('libvirtd')
    items = [dict(spec=spec, phase='confirmed', proof=dict(identity=dict(service=witness)))
             for spec in steps(source['profile'])]
    value = dict(installation=source, installation_sha256=fingerprint(source), items=items)
    receipts = {item['spec']['key']: deepcopy(item['proof']) for item in items}
    calls = []
    state = dict(result=subprocess.CompletedProcess([], 0, b'', b''), socket=witness['socket'],
                 generation=deepcopy(witness), replace_after=False)

    def read_generation(activation, item, receipt):
        assert activation == value and item == items[-1] and receipt == item['proof']

        def read():
            calls.append('generation')
            return deepcopy(state['generation'])

        return read

    class Sockets:
        @contextmanager
        def pin(self, spec, pid):
            assert spec == items[-1]['spec'] and pid == witness['process']['pid']
            calls.append('pin')
            yield 25, deepcopy(state['socket'])
            calls.append('recheck')

    @contextmanager
    def opener(path):
        assert path == '/usr/bin/virsh'
        yield 24

    def run(argv, **kwargs):
        calls.append('virsh')
        assert argv[:4] == ['/usr/bin/virsh', '--readonly', '--quiet', '--connect']
        assert argv[5:] == ['list', '--all', '--uuid']
        uri = urlsplit(argv[4])
        assert (uri.scheme, uri.netloc, uri.path) == ('qemu+unix', '', '/session')
        assert parse_qs(uri.query) == dict(socket=['/proc/self/fd/25'], mode=['legacy'])
        assert kwargs['executable'] == '/proc/self/fd/24' and kwargs['pass_fds'] == (24, 25)
        assert kwargs['timeout'] == 5 and kwargs['stdin'] == subprocess.DEVNULL
        assert kwargs['env']['LIBVIRT_AUTOSTART'] == '0'
        if state['replace_after']:
            state['generation']['process']['start_ticks'] += 1
        if isinstance(state['result'], Exception):
            raise state['result']
        return state['result']

    def binary_proof(fd, digest):
        assert fd == 24 and digest == 'a' * 64
        calls.append('binary')

    monkeypatch.setattr(empty, 'binary_proof', binary_proof)
    probe = empty.EmptySessionInventory(source, binary=dict(path='/usr/bin/virsh', sha256='a' * 64),
                                        sockets=Sockets(), read_generation=read_generation,
                                        opener=opener, run=run)
    return probe, value, receipts, state, calls


def test_empty_proof_is_bound_to_original_confirmed_services(inventory):
    probe, value, receipts, _, calls = inventory
    assert probe(value, receipts) == dict(installation_sha256=value['installation_sha256'], domains=[],
                                         service_proofs_sha256=fingerprint([item['proof'] for item in value['items']]))
    assert calls == ['generation', 'pin', 'binary', 'virsh', 'recheck', 'generation']


@pytest.mark.parametrize('fault', ['unconfirmed', 'wrong-peer', 'new-generation', 'nonempty', 'failed', 'stderr', 'timeout'])
def test_refuses_unqualified_empty_proof(inventory, fault):
    probe, value, receipts, state, calls = inventory
    if fault == 'unconfirmed':
        value['items'][-1]['phase'] = 'requested'
    elif fault == 'wrong-peer':
        state['socket'] = dict(state['socket'], peer_pid=12345)
    elif fault == 'new-generation':
        state['replace_after'] = True
    elif fault == 'nonempty':
        state['result'].stdout = b'42ad5f36-de41-4276-a5ad-7a5994ab75d9\n'
    elif fault == 'failed':
        state['result'].returncode = 1
    elif fault == 'stderr':
        state['result'].stderr = b'unqualified response'
    else:
        state['result'] = subprocess.TimeoutExpired('/usr/bin/virsh', 5)
    with pytest.raises(Conflict):
        probe(value, receipts)
    if fault in ('unconfirmed', 'wrong-peer'):
        assert 'virsh' not in calls
