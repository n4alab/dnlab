"""VM connector composition; unit/process/socket/root/SDK effects are synthetic."""
from contextlib import contextmanager
from copy import deepcopy
import os
import stat
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from test_libvirt_service_observer import service, install, request_profile
from tools.libvirt_vm_session import NativeVMSession


@pytest.fixture
def vm_session(service, tmp_path, monkeypatch):
    source, make = service
    source['context']['host_id'] = source['profile']['session']['host_id']
    directories = {}
    for index, item in enumerate(source['items']):
        if item['spec']['kind'] == 'directory':
            identity = dict(device=2, inode=200+index, uid=1001, gid=1002,
                            mode=0o700, kind='directory')
            item['proof']['identity'] = identity
            directories[item['spec']['path']] = deepcopy(identity)
    originals = {}
    items = []
    for index, spec in enumerate(steps(source['profile'])):
        item = dict(spec=spec, nonce=f'{index+1:032x}', phase='confirmed')
        if spec['kind'] == 'reload':
            item['proof'] = dict(activation_id='activation', nonce=item['nonce'],
                spec_sha256=fingerprint(spec), identity=dict(configuration_sha256='a'*64))
        else:
            _, witness, receipt, _, _ = make(spec['role'])
            pid = 1234+index
            witness['unit'].update(pid=pid, invocation_id=f'{index+1:032x}')
            witness['process']['pid'] = pid
            witness['socket'].update(peer_pid=pid, inode=100+index)
            originals[spec['unit']] = deepcopy(witness)
            receipt.update(nonce=item['nonce'], identity={**receipt['identity'], 'service':witness})
            item['proof'] = receipt
        items.append(item)
    activation = dict(id='activation', installation=deepcopy(source),
        installation_sha256=fingerprint(source), phase='ready_empty', items=items)
    activation['empty_proof'] = dict(installation_sha256=activation['installation_sha256'],
        domains=[], service_proofs_sha256=fingerprint([item['proof'] for item in items]))
    state = dict(activation=activation, services=originals, pins=[], sdk=[], source_ok=True,
                 directories=directories, socket_pin_hook=lambda:None, socket_unpins=0)

    class Pins:
        def pin(self, request, subscription, pid, invocation_id):
            assert subscription == dict(request_sha256=fingerprint(request),
                                        context_sha256=fingerprint(source['context']))
            state['pins'].append(pid)
            return dict(pid=pid, invocation_id=invocation_id)

        @contextmanager
        def observe(self, reference, request):
            value = state['services'][request['spec']['unit']]
            assert reference['pid'] == value['process']['pid']
            yield deepcopy(value['process'])

    class Sockets:
        def __call__(self, spec, pid):
            value = state['services'][spec['unit']]['socket']
            assert value['peer_pid'] == pid
            return deepcopy(value)

        @contextmanager
        def pin(self, spec, pid):
            state['socket_pin_hook']()
            try:
                yield 17, self(spec, pid)
            finally:
                state['socket_unpins'] += 1

    def units():
        return {unit:dict(load_state='loaded', unit=deepcopy(value['unit']), files=deepcopy(value['files']))
                for unit,value in state['services'].items()}

    @contextmanager
    def entry(root, path):
        value = state['directories']['/'+path]
        info = SimpleNamespace(st_dev=value['device'], st_ino=value['inode'],
            st_uid=value['uid'], st_gid=value['gid'], st_mode=stat.S_IFDIR|value['mode'])
        yield root, path, info

    monkeypatch.setattr('tools.libvirt_vm_session.entry', entry)
    root = os.open(tmp_path, os.O_RDONLY|os.O_DIRECTORY)
    def verify_source(value):
        assert value == source
        if not state['source_ok']:
            raise Conflict('synthetic context changed')
        return fingerprint(value)

    def construct():
        return NativeVMSession(activation_id='activation', activation_sha256=fingerprint(activation),
            read_activation=lambda operation:deepcopy(state['activation']), root=root, pins=Pins(),
            unit_reader=units, socket_reader=Sockets(), verify_source=verify_source)
    try:
        yield SimpleNamespace(construct=construct, state=state, source=source)
    finally:
        os.close(root)


def test_original_services_and_proof_are_available_without_opening_sdk(vm_session):
    e = vm_session; session = e.construct()
    assert len(e.state['pins']) == 3 and e.state['sdk'] == []
    proof = session.session.proof()
    assert proof['daemon']['pid'] == e.state['services']['dnlab-libvirtd.service']['process']['pid']
    services = session.services()
    services['dnlab-libvirtd.service']['pid'] = 1
    assert session.services()['dnlab-libvirtd.service']['pid'] != 1


@pytest.mark.parametrize('readonly', [True, False])
def test_same_proof_socket_and_event_loop_reach_sdk(vm_session, monkeypatch, readonly):
    e = vm_session; session = e.construct(); sdk = object(); loop = object()
    @contextmanager
    def open_connection(original, *, pin_socket, readonly, sdk, event_loop):
        assert original is session.session and sdk is sdk_object and event_loop is loop
        with pin_socket(original.proof()) as pair:
            e.state['sdk'].append((readonly, pair[0]))
            yield 'original-connection'
    sdk_object = sdk
    monkeypatch.setattr('dnlab_runtime.libvirt_sdk.open_connection', open_connection)
    with session.connect(sdk=sdk, readonly=readonly, event_loop=loop) as connection:
        assert connection == 'original-connection'
    assert e.state['sdk'] == [(readonly, 17)] and e.state['socket_unpins'] == 1


def test_context_conflict_precedes_first_process_pin(vm_session):
    e = vm_session;e.state['source_ok'] = False
    with pytest.raises(Conflict, match='context changed'):e.construct()
    assert e.state['pins'] == []


@pytest.mark.parametrize('fault', ['invocation', 'starttime', 'file', 'socket', 'inactive'])
def test_changed_original_daemon_blocks_before_sdk(vm_session, monkeypatch, fault):
    e = vm_session; session = e.construct()
    value = e.state['services']['dnlab-virtlockd.service']
    if fault == 'invocation':value['unit']['invocation_id'] = 'f'*32
    elif fault == 'starttime':value['process']['start_ticks'] += 1
    elif fault == 'file':next(iter(value['files'].values()))['identity'] = dict(foreign=True)
    elif fault == 'socket':value['socket']['inode'] += 1
    else:value['unit']['active'] = 'inactive'
    monkeypatch.setattr('dnlab_runtime.libvirt_sdk.open_connection',
                        lambda *args, **kwargs:pytest.fail('SDK reached on changed original'))
    with pytest.raises(RuntimeErrorBase):
        with session.connect(sdk=object(), readonly=False):
            pytest.fail('no SDK connection on a changed daemon')
    assert e.state['sdk'] == []


def test_changed_activation_is_not_rebound_to_a_current_generation(vm_session):
    e = vm_session; session = e.construct()
    e.state['activation']['items'][-1]['nonce'] = 'f'*32
    with pytest.raises(RuntimeErrorBase, match='activation changed'):session.services()


def test_changed_directory_is_not_a_new_session_birth(vm_session):
    e = vm_session; session = e.construct()
    path = e.source['profile']['session']['state_root']
    e.state['directories'][path]['inode'] += 1
    with pytest.raises(RuntimeErrorBase, match='directory changed'):session.session.proof()


def test_replacement_during_socket_pin_is_rejected_before_yield(vm_session):
    e = vm_session; session = e.construct()
    proof = session.session.proof()
    def replace():e.state['services']['dnlab-libvirtd.service']['socket']['inode'] += 1
    e.state['socket_pin_hook'] = replace
    with pytest.raises(RuntimeErrorBase, match='SDK socket changed'):
        with session.pin_socket(proof):pytest.fail('foreign socket yielded')
    assert e.state['socket_unpins'] == 1


def test_witness_mutation_cannot_replace_the_original_daemon(vm_session):
    e = vm_session; session = e.construct()
    session.witnesses['libvirtd'][2]['process']['start_ticks'] += 1
    with pytest.raises(RuntimeErrorBase, match='daemon witnesses'):session.services()


def test_socket_postflight_runs_even_when_the_sdk_body_raises(vm_session):
    e = vm_session; session = e.construct(); proof = session.session.proof()
    with pytest.raises(Conflict, match='context changed'):
        with session.pin_socket(proof):
            e.state['source_ok'] = False
            raise OSError('synthetic SDK error')
    assert e.state['socket_unpins'] == 1


@pytest.mark.parametrize('fault', ['requested', 'nonempty', 'missing'])
def test_incomplete_original_activation_is_rejected_before_process_pins(vm_session, fault):
    e = vm_session; value = e.state['activation']
    if fault == 'requested':value['items'][-1]['phase'] = 'requested'
    elif fault == 'nonempty':value['empty_proof']['domains'] = ['foreign']
    else:value['items'].pop()
    with pytest.raises(RuntimeErrorBase):e.construct()
    assert e.state['pins'] == []


@pytest.mark.parametrize('readonly', [None, 0, 1])
def test_connection_mode_must_be_an_explicit_boolean(vm_session, monkeypatch, readonly):
    e = vm_session; session = e.construct()
    monkeypatch.setattr('dnlab_runtime.libvirt_sdk.open_connection',
                        lambda *args, **kwargs:pytest.fail('SDK reached with ambiguous mode'))
    with pytest.raises(RuntimeErrorBase, match='explicit readonly'):
        with session.connect(sdk=object(), readonly=readonly):pytest.fail('ambiguous mode admitted')
