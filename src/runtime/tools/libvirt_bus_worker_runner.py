"""Supervise the original D-Bus worker and commit its job before acknowledgement."""

from contextlib import contextmanager, suppress
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import select
import subprocess
import time

from dnlab_runtime.libvirt_account_process import AccountWorkerObserver
from dnlab_runtime.libvirt_account_runner import AccountProcessRunner, source_proof
from dnlab_runtime.libvirt_account_worker import ENVIRONMENT, MAX_FRAME, binary_proof, frame
from dnlab_runtime.libvirt_activation_bus import StartJobReceipts, connection_proof, hex_value, validate
from dnlab_runtime.libvirt_activation_worker import validate_command
from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from tools.libvirt_bus_worker_main import source_inventory
from tools.libvirt_systemd_bus import require


def read_job(process, live, *, timeout=10):
    """Retain partial output and collect the job frame while the child awaits ACK."""
    deadline = time.monotonic() + timeout
    for name in ('stdout', 'stderr'):
        os.set_blocking(getattr(process, name).fileno(), False)
    while time.monotonic() < deadline:
        if b'\n' in live['stdout']:
            line, tail = live['stdout'].split(b'\n', 1)
            require(not tail, 'unexpected stdout after original D-Bus job frame')
            return frame(io.StringIO(line.decode('utf-8') + '\n'))
        if 'stdout' in live['eof']:
            return None
        streams = [getattr(process, name) for name in ('stdout', 'stderr') if name not in live['eof']]
        ready, _, _ = select.select(streams, [], [], max(0, deadline - time.monotonic()))
        for stream in ready:
            name = 'stdout' if stream is process.stdout else 'stderr'
            limit = MAX_FRAME if name == 'stdout' else 65536
            try:
                block = os.read(stream.fileno(), min(4096, limit + 1 - len(live[name])))
            except BlockingIOError:
                continue
            if not block:
                live['eof'].add(name)
            else:
                live[name] += block
                require(len(live[name]) <= limit, 'original D-Bus worker output exceeds bound')
    return None


class BusWorkerObserver(AccountWorkerObserver):
    process_table = 'libvirt_activation_bus_processes'

    def _verify_live(self, live, command, phase):
        validate(command)
        require(not self._events(live) and live['process'].poll() is None
                and self._snapshot(live['process']) == live['snapshot']
                and not self._events(live) and live['process'].poll() is None,
                'original D-Bus interpreter process changed')
        return True


class BusStartProcessRunner(AccountProcessRunner):
    worker_table = 'libvirt_activation_bus_workers'
    command_validator = staticmethod(validate)

    def __init__(self, journal, *, profile, observer, inventory, sources_sha256,
                 verify_connection, job_reader=read_job, read_sources=None, **kwargs):
        super().__init__(journal, profile=profile, observer=observer, **kwargs)
        require(callable(verify_connection) and callable(job_reader) and hex_value(sources_sha256, 64)
                and inventory['status'] == 'collected' and inventory['passes'] == 2
                and inventory['library_present'], 'original D-Bus inventory and worker connection verifier required')
        self.inventory = deepcopy(inventory)
        self.sources_sha256 = sources_sha256
        self.verify_connection, self.job_reader = verify_connection, job_reader
        self.read_sources = read_sources or (lambda: source_inventory(Path(self.profile['worker']['path']).parents[1]))
        self.jobs = StartJobReceipts(journal, verify=self._verify_job_worker, read_reply=self._job_reply)

    def _read(self, reference):
        value = super()._read(reference)
        if value.get('ack_requested') or value['phase'] == 'completed':
            receipt = self.jobs._read(value['command'])
            require(receipt is not None and receipt['phase'] == 'committed' and receipt['worker'] == reference
                    and value.get('ack_requested') == dict(
                        committed=reference['token'], job_sha256=fingerprint(receipt['result'])),
                    'original D-Bus acknowledgement or committed job differs')
        return value

    def _check_sources(self, command):
        transport = command['transport']
        require(transport['worker_sha256'] == self.profile['worker']['sha256']
                and transport['library_sha256'] == self.inventory['proof']['library']['object']['sha256']
                and self.read_sources() == self.sources_sha256, 'original D-Bus worker sources or library differ')

    def _request(self, token, command):
        self._check_sources(command)
        return dict(token=token, command=command, inventory=self.inventory, sources_sha256=self.sources_sha256)

    @contextmanager
    def _launch(self, command):
        with (self.opener(self.profile['python']['path']) as python,
              self.opener(self.profile['worker']['path']) as worker):
            binary_proof(python, self.profile['python']['sha256'])
            source_proof(worker, self.profile['worker']['sha256'])
            argv = [self.profile['python']['path'], '-B', '-I', '-S', f'/proc/self/fd/{worker}']
            yield self.spawn(argv, executable=f'/proc/self/fd/{python}', pass_fds=(python, worker),
                             stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                             env=deepcopy(ENVIRONMENT), cwd='/', close_fds=True)

    def _accept_ready(self, token, command, live):
        ready = self.read_ready(live['process'])
        connection = ready.get('connection')
        connection_proof(connection)
        require(connection['token'] == token
                and connection['context_sha256'] == fingerprint(self.inventory['context'])
                and ready == dict(ready=token, command_sha256=fingerprint(command),
                                  connection_sha256=fingerprint(connection), connection=connection),
                'original blocked D-Bus worker readiness differs')
        live['connection'] = connection

    def arm(self, command):
        with self.journal.execution_lock:
            validate(command)
            with self.journal.lock:
                original = any(json.loads(row['payload'])['command']['request_sha256'] == command['request_sha256']
                               for row in self.journal.db.execute('SELECT payload FROM ' + self.worker_table))
            require(not original and self.jobs._read(command) is None,
                    'original D-Bus worker already tracked; no respawn')
            prior = set(self.live)
            try:
                reference = super().arm(command)
                connection = self.live[reference['token']]['connection']
                self.jobs.prepare(command, self.inventory['context'], connection, reference)
                return reference
            except BaseException:
                for token in self.live.keys() - prior:
                    with suppress(OSError):
                        self.live[token]['process'].stdin.close()
                raise

    def _verify_job_worker(self, reference, command, connection):
        self._check_sources(command)
        live = self.live.get(reference['token'])
        return (live is not None and live['connection'] == connection and live['process'].poll() is None
                and self.verify(reference, command) is True
                and self.verify_connection(reference, connection) is True)

    def _send_release(self, value, live):
        reference, command = value['reference'], value['command']
        receipt = self.jobs._read(command)
        require(receipt is not None and receipt['phase'] == 'prepared' and receipt['worker'] == reference
                and self._verify_job_worker(reference, command, receipt['connection']),
                'original job intent and worker connection required before release')
        stdin = live['process'].stdin
        try:
            stdin.write((canonical(dict(release=reference['token'], command_sha256=reference['command_sha256'],
                                        connection_sha256=fingerprint(receipt['connection']))) + '\n').encode())
            stdin.flush()
        except BaseException:
            stdin.close()
            raise

    def _job_reply(self, reference):
        live = self.live[reference['token']]
        if 'job' not in live:
            response = self.job_reader(live['process'], live)
            if response is None:
                return None
            require(isinstance(response, dict) and set(response) == {'job'}, 'original D-Bus job frame required')
            live['job'] = response['job']
        return deepcopy(live['job'])

    def outcome(self, reference):
        with self.journal.execution_lock:
            value = self._read(reference)
            if value['phase'] in ('release_requested', 'released') and not value.get('ack_requested'):
                ack = self.jobs.collect(value['command'])
                live = self.live[reference['token']]
                stdin = live['process'].stdin
                try:
                    value['ack_requested'] = ack
                    self._save(value)
                    require(self._verify_job_worker(reference, value['command'], live['connection']),
                            'original D-Bus worker changed before acknowledgement')
                    stdin.write((canonical(ack) + '\n').encode())
                    stdin.flush()
                finally:
                    stdin.close()
            return super().outcome(reference)


class NativeActivationRunner:
    """Dispatch the fixed reload and D-Bus starts to their original journals."""

    def __init__(self, reload_runner, start_runner):
        require(reload_runner.journal is start_runner.journal, 'shared activation journal required')
        self.journal = start_runner.journal
        self.reload, self.start = reload_runner, start_runner

    def arm(self, command):
        if 'transport' in command:
            return self.start.arm(validate(command))
        require(validate_command(command)['argv'] == ['/usr/bin/systemctl', 'daemon-reload'],
                'native activation requires D-Bus for dedicated starts')
        return self.reload.arm(command)

    def _original(self, reference):
        with self.journal.lock:
            matching = [runner for runner in (self.reload, self.start)
                        if self.journal.db.execute('SELECT 1 FROM ' + runner.worker_table + ' WHERE token=?',
                                                   (reference['token'],)).fetchone() is not None]
        require(len(matching) == 1, 'one original activation worker journal required')
        return matching[0]

    def verify(self, reference, command):
        return self._original(reference).verify(reference, command)

    def release(self, reference):
        return self._original(reference).release(reference)

    def outcome(self, reference):
        return self._original(reference).outcome(reference)

    def completed_outcome(self, reference):
        return self._original(reference).completed_outcome(reference)
