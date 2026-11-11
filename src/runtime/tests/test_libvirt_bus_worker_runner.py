"""Original job handoff over a fake child and temporary journal."""

from copy import deepcopy
import json
import os
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_account_runner import runner, request_profile
from tools.libvirt_bus_worker_runner import BusStartProcessRunner, read_job


def test_job_reader_retains_partial_frame():
    stdout, stdout_write = os.pipe()
    stderr, stderr_write = os.pipe()
    with (os.fdopen(stdout, 'rb') as output, os.fdopen(stderr, 'rb') as errors,
          os.fdopen(stdout_write, 'wb', buffering=0) as reply,
          os.fdopen(stderr_write, 'wb', buffering=0)):
        process = SimpleNamespace(stdout=output, stderr=errors)
        live = dict(stdout=b'', stderr=b'', eof=set())
        reply.write(b'{"jo')
        assert read_job(process, live, timeout=0.05) is None
        assert live['stdout'] == b'{"jo'
        reply.write(b'b":{"path":"original"}}\n')
        assert read_job(process, live, timeout=1) == {'job': {'path': 'original'}}


@pytest.fixture
def start(runner):
    base, _, state, _ = runner
    context = dict(host_id='fixture', boot_id='synthetic', namespaces={'pid': dict(device=1, inode=2)})
    inventory = dict(context=context, status='collected', passes=2, library_present=True,
                     proof=dict(library=dict(object=dict(sha256='b' * 64))))
    command = dict(
        transport=dict(kind='dbus-start-v1', worker_sha256=base.profile['worker']['sha256'], library_sha256='b' * 64),
        request_sha256='a' * 64, destination='org.freedesktop.systemd1', path='/org/freedesktop/systemd1',
        interface='org.freedesktop.systemd1.Manager', member='StartUnit', signature='ss',
        body=['dnlab-virtlogd.service', 'fail'],
    )
    capture = base.observer.capture
    base.observer.capture = lambda process: dict(capture(process), namespace_sha256=fingerprint(context['namespaces']))

    def spawn(*args, **kwargs):
        process = base.spawn(*args, **kwargs)
        process.poll = lambda: None
        return process

    def ready(process):
        bootstrap = json.loads(process.stdin.getvalue().splitlines()[0])
        assert bootstrap['inventory'] == inventory and bootstrap['sources_sha256'] == 'c' * 64
        connection = dict(token=bootstrap['token'], context_sha256=fingerprint(context),
                          manager_owner=':1.42', unique_name=':1.43')
        state['connection'] = connection
        return dict(ready=bootstrap['token'], command_sha256=fingerprint(command),
                    connection_sha256=fingerprint(connection), connection=connection)

    def read_job(process, _):
        if state.get('job_pending'):
            return None
        bootstrap, release = [json.loads(line) for line in process.stdin.getvalue().splitlines()]
        assert not process.stdin.was_closed
        return dict(job=dict(token=bootstrap['token'], command_sha256=release['command_sha256'],
                             connection_sha256=release['connection_sha256'],
                             reply=dict(call_serial=8, reply_serial=8, sender=':1.42', signature='o',
                                        body=['/org/freedesktop/systemd1/job/12'])))

    def make():
        return BusStartProcessRunner(base.journal, profile=base.profile, observer=base.observer,
                                     inventory=inventory, sources_sha256='c' * 64,
                                     verify_connection=lambda reference, connection: (
                                         connection == state['connection'] and not state.get('foreign_connection')),
                                     read_sources=lambda: 'c' * 64, job_reader=read_job,
                                     opener=base.opener, spawn=spawn, read_ready=ready, read_output=base.read_output)

    return make(), command, state, make


def test_runner_commits_original_job_before_ack_and_reopens_completion(start, monkeypatch):
    driver, command, state, make = start
    reference = driver.arm(command)
    driver.release(reference)
    process = state['process']
    assert not process.stdin.was_closed
    write = process.stdin.write

    def check_ack(data):
        ack = json.loads(data)
        assert driver.jobs._read(command)['phase'] == 'committed'
        assert driver._read(reference)['ack_requested'] == ack
        return write(data)

    monkeypatch.setattr(process.stdin, 'write', check_ack)
    result = driver.outcome(reference)
    assert result['exit_code'] == 0
    assert make().completed_outcome(reference) == result
    assert process.stdin.was_closed and len(process.stdin.getvalue().splitlines()) == 3
    with pytest.raises(Conflict, match='no respawn'):
        driver.arm(command)
    assert len(state['spawns']) == 1


def test_pending_job_reuses_original_worker_and_release(start):
    driver, command, state, make = start
    reference = driver.arm(command)
    driver.release(reference)
    state['job_pending'] = True
    with pytest.raises(Conflict, match='response pending'):
        driver.outcome(reference)
    assert not state['process'].stdin.was_closed
    assert len(state['process'].stdin.getvalue().splitlines()) == 2
    with pytest.raises(Conflict, match='not repeated'):
        driver.release(reference)
    with pytest.raises(Conflict, match='connection lost'):
        make().outcome(reference)
    assert len(state['spawns']) == 1
    state['job_pending'] = False
    assert driver.outcome(reference)['exit_code'] == 0


def test_foreign_connection_prevents_release(start):
    driver, command, state, _ = start
    reference = driver.arm(command)
    state['foreign_connection'] = True
    with pytest.raises(Conflict, match='connection required before release'):
        driver.release(reference)
    assert driver._read(reference)['phase'] == 'release_requested'
    assert len(state['process'].stdin.getvalue().splitlines()) == 1
    assert driver.jobs._read(command)['phase'] == 'prepared'
