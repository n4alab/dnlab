"""Safety tests for native remote-driver capability canaries."""
from contextlib import nullcontext
from copy import deepcopy
import json
from types import SimpleNamespace

import pytest

from dnlab_runtime.endpoint_name_probe import EndpointNameProbe
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase


@pytest.fixture
def probe(tmp_path, monkeypatch):
    journal = Journal(tmp_path / 'canaries')
    network = {'Id': 'network', 'Name': 'blue', 'Driver': 'dnlab-vrf', 'IPAM': {'Driver': 'dnlab-vrf'}, 'Labels': {'io.dnlab.lab': 'lab', 'io.dnlab.managed': 'mgmt-vrf'}}
    calls, state = [], {'container': None}
    def create(request, spec, creator, **options):
        calls.append(('create', options) if options else 'create')
        state['container'] = {'Id': 'canary', 'State': {'Running': True}, 'Config': {'Labels': {'org.dnlab.runtime.creator': creator}}, 'NetworkSettings': {'Networks': {'blue': {'IPAddress': '192.0.2.2', 'IPPrefixLen': 24, 'Gateway': '192.0.2.1'}}}}
        return state['container']
    def remove(*args):
        calls.append('remove'); state['container'] = None
    docker = SimpleNamespace(request=lambda *args: {'Config': {'Entrypoint': None}}, connect=lambda *args, **kwargs: calls.append('connect'), disconnect=lambda *args: calls.append('disconnect'), network=lambda *args: network)
    docker.exec_checked = lambda *args, **kwargs: calls.append('ready') or 'exec-ready'
    backend = SimpleNamespace(docker=docker, create=create, start=lambda *args: calls.append('start'), inspect=lambda *args: state['container'], stop=lambda *args, **kwargs: calls.append(('stop', kwargs)), remove=remove, namespace=lambda *args: nullcontext('ns'), linux=SimpleNamespace(command=lambda *args: '[]'))
    observed = {'network_id': 'network', 'name': 'dnmu0', 'ifindex': 2, 'peer_ifindex': 3}
    monkeypatch.setattr('dnlab_runtime.endpoint_name_probe.resolve_endpoint', lambda *args: deepcopy(observed))
    helper = EndpointNameProbe(journal, backend, 'lab', 'sha256:' + 'a'*64, 'creator')
    yield helper, network, calls, state, observed
    journal.close()


def test_canary_intent_and_observation_are_durable_and_cleanup_verified(probe):
    helper, network, calls, state, _ = probe
    observed = helper.check(network, 'dnmu0')
    assert observed['cleanup_verified'] and observed['canary_container_id'] == 'canary'
    assert state['container'] is None
    assert calls == ['create', 'start', 'ready', 'disconnect', 'connect', 'ready', ('stop', {}), 'remove']
    row = helper.journal.db.execute('SELECT * FROM endpoint_name_probes').fetchone()
    assert row['phase'] == 'cleaned'
    assert json.loads(row['payload'])['observation']['name'] == 'dnmu0'


def test_driver_ignoring_name_fails_and_removes_only_canary(probe):
    helper, network, calls, state, observed = probe
    observed['name'] = 'eth1'
    with pytest.raises(Conflict, match='did not apply'):
        helper.check(network, 'dnmu0')
    assert state['container'] is None and calls[-1] == 'remove'


def test_cleanup_failure_keeps_recoverable_intent_and_cannot_authorize_handoff(probe):
    helper, network, calls, state, _ = probe
    original = helper.backend.stop
    def fail(*args):
        raise RuntimeErrorBase('exit timeout')
    helper.backend.stop = fail
    with pytest.raises(Conflict, match='cleanup requires recovery'):
        helper.check(network, 'dnmu0')
    assert state['container'] is not None and 'remove' not in calls
    assert helper.journal.db.execute('SELECT phase FROM endpoint_name_probes').fetchone()[0] == 'recovery_required'
    diagnostic = json.loads(helper.journal.db.execute('SELECT payload FROM endpoint_name_probes').fetchone()[0])['cleanup_errors'][-1]
    assert diagnostic['step'] == 'stop' and diagnostic['message'] == 'exit timeout'
    helper.backend.stop = original
    helper.recover()
    assert state['container'] is None
    assert helper.journal.db.execute('SELECT phase FROM endpoint_name_probes').fetchone()[0] == 'cleaned'


def test_foreign_creator_is_not_stopped_during_recovery(probe):
    helper, network, calls, state, _ = probe
    def wrong(request, spec, creator):
        state['container'] = {'Id': 'foreign', 'Config': {'Labels': {'org.dnlab.runtime.creator': 'other'}}}
        raise RuntimeErrorBase('lost create response')
    helper.backend.create = wrong
    with pytest.raises(Conflict, match='cleanup requires recovery'):
        helper.check(network, 'dnmu0')
    with pytest.raises(Conflict, match='creator changed'):
        helper.recover()
    assert ('stop', {}) not in calls and 'remove' not in calls


@pytest.mark.parametrize('bad', ['lab', 'driver', 'entrypoint', 'digest'])
def test_unsupported_canary_inputs_rejected_before_creation(probe, bad):
    helper, network, calls, _, _ = probe
    if bad == 'lab': network['Labels']['io.dnlab.lab'] = 'other'
    if bad == 'driver': network['Driver'] = 'bridge'
    if bad == 'entrypoint': helper.backend.docker.request = lambda *args: {'Config': {'Entrypoint': ['/launch.py']}}
    if bad == 'digest': helper.image = 'python:latest'
    with pytest.raises(RuntimeErrorBase):
        helper.check(network, 'dnmu0')
    assert calls == []


def test_live_probe_lock_prevents_recovery_or_mutation(probe):
    import fcntl
    helper, network, calls, _, _ = probe
    with helper.lock_path.open('w') as lock:
        helper.lock_path.chmod(0o600)
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        with pytest.raises(Conflict, match='still running'):
            helper.check(network, 'dnmu0')
        with pytest.raises(Conflict, match='still running'):
            helper.recover()
        assert calls == []
    helper.check(network, 'dnmu0')
    assert calls[-1] == 'remove'


def test_initial_create_canary_never_disconnects_or_reconnects(probe):
    helper, network, calls, state, _ = probe
    observed = helper.check(network, 'dnmu0', creation_mode='create')
    assert observed['creation_mode'] == 'create' and observed['cleanup_verified']
    assert calls == [('create', {'initial_interface_name': 'dnmu0'}), 'start', 'ready', 'ready', ('stop', {}), 'remove']
    payload = json.loads(helper.journal.db.execute('SELECT payload FROM endpoint_name_probes').fetchone()[0])
    assert payload['creation_mode'] == 'create' and state['container'] is None


def test_initial_create_ignored_name_cannot_authorize_bootstrap(probe):
    helper, network, calls, state, observed = probe
    observed['name'] = 'eth0'
    with pytest.raises(Conflict, match='did not apply'):
        helper.check(network, 'dnmu0', creation_mode='create')
    assert 'disconnect' not in calls and 'connect' not in calls
    assert state['container'] is None and calls[-1] == 'remove'


def test_unknown_creation_mode_rejected_before_resources(probe):
    helper, network, calls, _, _ = probe
    with pytest.raises(Conflict, match='creation mode'):
        helper.check(network, 'dnmu0', creation_mode='none')
    assert calls == []


def test_backend_initial_name_is_in_create_payload_and_default_is_unchanged():
    from dnlab_runtime.backend import Backend
    from fakes import FakeDocker
    request = {'lab_id': 'demo', 'node_id': 'canary'}
    spec = {'kind': 'linux', 'image': 'sha256:' + 'a'*64, 'container_name': 'canary', 'management': {'network': 'mgmt'}}
    for name in (None, 'dnmu0'):
        docker = FakeDocker()
        guards = []
        docker.require_endpoint_name_support = lambda: guards.append(True)
        backend = Backend(docker=docker)
        kwargs = {'initial_interface_name': name} if name else {}
        result = backend.create(request, spec, 'creator', **kwargs)
        config = result['Config']
        assert config['HostConfig']['NetworkMode'] == 'mgmt-id'
        endpoint = config['NetworkingConfig']['EndpointsConfig']['mgmt-id']
        assert endpoint['IPAMConfig'] == {'IPv4Address': '', 'IPv6Address': ''}
        if name:
            assert endpoint['DriverOpts'] == {'com.docker.network.endpoint.ifname': name}
            assert guards == [True]
        else:
            assert 'DriverOpts' not in endpoint and not guards


def test_readiness_failure_prevents_probe_and_stop_but_records_cleanup_cause(probe):
    helper,network,calls,state,_=probe
    def fail(*args,**kwargs):
        assert kwargs['timeout']==12
        raise RuntimeErrorBase('readiness timeout')
    helper.backend.docker.exec_checked=fail
    with pytest.raises(Conflict,match='cleanup requires recovery'):
        helper.check(network,'dnmu0',creation_mode='create')
    payload=json.loads(helper.journal.db.execute('SELECT payload FROM endpoint_name_probes').fetchone()[0])
    assert payload['probe_error']['message']=='readiness timeout'
    assert payload['cleanup_errors'][-1]['step']=='readiness'
    assert payload['cleanup_errors'][-1]['message']=='readiness timeout'
    assert state['container'] is not None
    assert ('stop',{}) not in calls and 'remove' not in calls


@pytest.mark.parametrize('delay',[-1,6,float('nan'),float('inf'),True,'2'])
def test_invalid_startup_delay_cannot_create_resources(probe,delay):
    helper,network,calls,_,_=probe
    with pytest.raises(Conflict,match='startup delay'):
        helper.check(network,'dnmu0',startup_delay=delay)
    assert calls==[]


def test_ready_reader_rejects_stale_boot_or_nonce(tmp_path,monkeypatch):
    import os
    import sys
    from dnlab_runtime.endpoint_name_probe import READY_PROGRAM
    marker=tmp_path/'marker-token'
    marker.write_text('token\nstale-boot');marker.chmod(0o600)
    original=os.fstat
    monkeypatch.setattr(os,'fstat',lambda fd:SimpleNamespace(st_mode=original(fd).st_mode,st_uid=0))
    monkeypatch.setattr(sys,'argv',['check','token'])
    program=READY_PROGRAM.replace('/run/dnlab-canary-ready-',str(tmp_path/'marker-'))
    with pytest.raises(AssertionError):exec(compile(program,'ready-reader.py','exec'),{})
    boot=open('/proc/1/stat').read().rsplit(')',1)[1].split()[19]
    marker.write_text('wrong-token\n'+boot)
    with pytest.raises(AssertionError):exec(compile(program,'ready-reader.py','exec'),{})
    marker.write_text('token\n'+boot)
    exec(compile(program,'ready-reader.py','exec'),{})


def test_ready_reader_missing_marker_has_finite_deadline(tmp_path,monkeypatch):
    import sys,time
    from dnlab_runtime.endpoint_name_probe import READY_PROGRAM
    ticks=iter(range(20))
    monkeypatch.setattr(time,'monotonic',lambda:next(ticks))
    monkeypatch.setattr(time,'sleep',lambda _:None)
    monkeypatch.setattr(sys,'argv',['check','missing'])
    program=READY_PROGRAM.replace('/run/dnlab-canary-ready-',str(tmp_path/'marker-'))
    with pytest.raises(RuntimeError,match='readiness timed out'):
        exec(compile(program,'ready-deadline.py','exec'),{})


def test_ready_reader_rejects_symlink_marker(tmp_path,monkeypatch):
    import sys
    from dnlab_runtime.endpoint_name_probe import READY_PROGRAM
    target=tmp_path/'target';target.write_text('token\nboot')
    (tmp_path/'marker-token').symlink_to(target)
    monkeypatch.setattr(sys,'argv',['check','token'])
    program=READY_PROGRAM.replace('/run/dnlab-canary-ready-',str(tmp_path/'marker-'))
    with pytest.raises(OSError):
        exec(compile(program,'ready-no-follow.py','exec'),{})
