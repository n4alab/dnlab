"""Fresh remote-driver naming qualification using journalled native canaries.

This experimental gate has a separate journal from the handoff. It never
reuses a VD as a probe, never caches a capability across operations, and never
implicitly forces process shutdown. The caller supplies a pinned native image.
"""
from __future__ import annotations

from contextlib import contextmanager
import fcntl
import json
import os
from pathlib import Path
import threading
import uuid
from urllib.parse import quote

from .endpoint_uplink import resolve_endpoint
from .manifest import Conflict, RuntimeErrorBase, canonical, validate_spec

CANARY_PROGRAM = '''import os, signal, sys, time
time.sleep(float(sys.argv[2]))
signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
with open('/proc/1/stat') as stream:
    boot = stream.read().rsplit(')', 1)[1].split()[19]
ready = '/run/dnlab-canary-ready-' + sys.argv[1]
fd = os.open(ready + '.pending', os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, 'w') as stream:
    stream.write(sys.argv[1] + '\\n' + boot)
    stream.flush()
    os.fsync(stream.fileno())
os.replace(ready + '.pending', ready)
time.sleep(86400)
'''

READY_PROGRAM = '''import os, stat, sys, time
deadline = time.monotonic() + 10
while True:
    try:
        fd = os.open('/run/dnlab-canary-ready-' + sys.argv[1], os.O_RDONLY | os.O_NOFOLLOW)
        with os.fdopen(fd) as stream:
            info = os.fstat(stream.fileno())
            assert stat.S_ISREG(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
            marker = stream.read(256)
        with open('/proc/1/stat') as stream:
            boot = stream.read().rsplit(')', 1)[1].split()[19]
        assert marker == sys.argv[1] + '\\n' + boot
        break
    except FileNotFoundError:
        if time.monotonic() >= deadline:
            raise RuntimeError('canary signal-handler readiness timed out')
        time.sleep(0.05)
'''


class EndpointNameProbe:
    def __init__(self, journal, backend, lab_id, image, creator):
        self.journal, self.backend = journal, backend
        self.lab_id, self.image, self.creator = lab_id, image, creator
        with journal.lock:
            if not hasattr(journal, 'endpoint_probe_execution_lock'):
                journal.endpoint_probe_execution_lock = threading.RLock()
            self.execution_lock = journal.endpoint_probe_execution_lock
            directory = Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
            self.lock_path = directory / 'endpoint-name-probes.lock'

        with journal.transaction():
            journal.db.execute('''CREATE TABLE IF NOT EXISTS endpoint_name_probes (
                id TEXT PRIMARY KEY, payload TEXT NOT NULL, phase TEXT NOT NULL)''')

    def save(self, identity, payload, phase):
        with self.journal.transaction():
            self.journal.db.execute('UPDATE endpoint_name_probes SET payload=?,phase=? WHERE id=?', (canonical(payload), phase, identity))

    def wait_ready(self, payload, container):
        if not container or container['Id'] != payload.get('container_id'):
            raise Conflict('canary readiness container identity changed')
        helper = self.backend.docker.exec_checked(container['Id'],
            ['python3', '-c', READY_PROGRAM, payload['readiness_token']], timeout=12)
        observed = self.backend.inspect(payload['request'], payload['spec'])
        if not observed or observed['Id'] != container['Id'] or not observed['State']['Running']:
            raise Conflict('canary changed or exited while checking signal-handler readiness')
        payload['readiness'] = {'container_id': container['Id'], 'exec_id': helper, 'verified': True}

    def cleanup(self, identity, payload):
        try:
            self._cleanup(identity, payload)
        except Exception as error:
            diagnostic = {'step': payload.get('cleanup_step'), 'type': type(error).__name__, 'message': str(error)}
            try:
                observed = self.backend.inspect(payload['request'], payload['spec'])
                diagnostic['container_state'] = observed.get('State') if observed else None
            except Exception as inspect_error:
                diagnostic['inspection_error'] = str(inspect_error)
            payload.setdefault('cleanup_errors', []).append(diagnostic)
            self.save(identity, payload, 'recovery_required')
            raise

    def _cleanup(self, identity, payload):
        request, spec = payload['request'], payload['spec']
        payload['cleanup_step'] = 'inspect'
        container = self.backend.inspect(request, spec)
        if container:
            if container['Config']['Labels'].get('org.dnlab.runtime.creator') != payload['creator']:
                raise Conflict('endpoint naming canary creator changed; refusing cleanup')
            if payload.get('container_id') and payload['container_id'] != container['Id']:
                raise Conflict('endpoint naming canary identity changed; refusing cleanup')
            if payload.get('readiness_token') and container['State']['Running']:
                payload['cleanup_step'] = 'readiness'
                self.wait_ready(payload, container)
            payload['cleanup_step'] = 'stop'
            self.backend.stop(request, spec)  # Verified native exit, no implicit kill.
            payload['cleanup_step'] = 'remove'
            self.backend.remove(request, spec)
        payload['cleanup_step'] = 'verify_absent'
        if self.backend.inspect(request, spec) is not None:
            raise Conflict('endpoint naming canary cleanup incomplete')
        self.save(identity, payload, 'cleaned')

    @contextmanager
    def execution(self):
        # Never recover another live checker as if it had crashed. Independent
        # processes also serialize on the persistent journal's lock inode.
        with self.execution_lock:
            fd = os.open(self.lock_path, os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
            try:
                info = os.fstat(fd)
                if info.st_uid != os.geteuid() or info.st_mode & 0o077:
                    raise Conflict('endpoint probe execution lock ownership/mode mismatch')
                try:
                    fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
                except BlockingIOError:
                    raise Conflict('another endpoint naming probe is still running') from None
                yield
            finally:
                os.close(fd)

    def recover(self):
        with self.execution():
            self._recover()

    def _recover(self):
        with self.journal.lock:
            pending = self.journal.db.execute("SELECT id,payload FROM endpoint_name_probes WHERE phase != 'cleaned'").fetchall()
        for row in pending:
            payload = json.loads(row['payload'])
            if payload['request']['lab_id'] != self.lab_id:
                raise Conflict('endpoint probe journal belongs to another lab')
            self.cleanup(row['id'], payload)

    def check(self, network, interface_name, *, creation_mode='connect', startup_delay=0):
        with self.execution():
            return self._check(network, interface_name, creation_mode=creation_mode, startup_delay=startup_delay)

    def _check(self, network, interface_name, *, creation_mode='connect', startup_delay=0):
        # Do not probe a foreign network or launch an image with an implicit NOS
        # entrypoint. Validation and lost-response recovery precede creation.
        if network.get('Driver') != 'dnlab-vrf' or network.get('IPAM', {}).get('Driver') != 'dnlab-vrf' or network.get('Labels', {}).get('io.dnlab.lab') != self.lab_id or network.get('Labels', {}).get('io.dnlab.managed') != 'mgmt-vrf':
            raise Conflict('endpoint naming probe requires an owned dnlab-vrf network')
        if creation_mode not in {'create', 'connect'}:
            raise Conflict('unsupported endpoint naming probe creation mode')
        if type(startup_delay) not in (int, float) or not 0 <= startup_delay <= 5:
            raise Conflict('canary startup delay must be between zero and five seconds')
        identity = uuid.uuid4().hex
        request = {'lab_id': self.lab_id, 'node_id': 'endpoint-probe-' + identity}
        spec = {'kind': 'linux', 'image': self.image, 'container_name': 'dnlab-endpoint-probe-' + identity,
                'management': {'network': network['Name']},
                'command': ['python3', '-c', CANARY_PROGRAM, identity, str(startup_delay)], 'stop_timeout': 5}
        validate_spec(spec)
        image = self.backend.docker.request('GET', '/images/' + quote(self.image, safe='') + '/json')
        if image.get('Config', {}).get('Entrypoint'):
            raise RuntimeErrorBase('endpoint naming probe requires a native image without an entrypoint')
        self._recover()
        payload = {'request': request, 'spec': spec, 'creator': self.creator, 'network_id': network['Id'], 'interface_name': interface_name, 'creation_mode': creation_mode, 'readiness_token': identity}
        with self.journal.transaction():
            self.journal.db.execute('INSERT INTO endpoint_name_probes VALUES(?,?,?)', (identity, canonical(payload), 'creating'))
        result = None
        try:
            options = {'initial_interface_name': interface_name} if creation_mode == 'create' else {}
            container = self.backend.create(request, spec, self.creator, **options)
            payload['container_id'] = container['Id']
            self.save(identity, payload, 'starting')
            self.backend.start(request, spec)
            self.save(identity, payload, 'waiting_ready')
            self.wait_ready(payload, self.backend.inspect(request, spec))
            self.save(identity, payload, 'ready')
            if creation_mode == 'connect':
                self.save(identity, payload, 'disconnecting')
                self.backend.docker.disconnect(network['Id'], container['Id'])
                self.save(identity, payload, 'connecting')
                self.backend.docker.connect(network['Id'], container['Id'], '', interface_name=interface_name)
            container = self.backend.inspect(request, spec)
            endpoints = container['NetworkSettings']['Networks']
            if set(endpoints) != {network['Name']}:
                raise Conflict('endpoint naming probe received unexpected attachments')
            endpoint = endpoints[network['Name']]
            connection = {'network_id': network['Id'], 'network_name': network['Name'], 'cidr': f"{endpoint['IPAddress']}/{endpoint['IPPrefixLen']}", 'gateway': endpoint['Gateway']}
            with self.backend.namespace(request, spec, container) as ns:
                host = json.loads(self.backend.linux.command(['-j', '-d', 'link', 'show']))
                links = json.loads(self.backend.linux.command(['-j', '-d', 'link', 'show'], ns))
                result = resolve_endpoint(self.backend.docker.network(network['Id']), container, connection, host, links)
            if result['name'] != interface_name:
                raise Conflict('remote driver did not apply the requested management uplink name')
            result['canary_container_id'] = container['Id']
            payload['observation'] = result
            self.save(identity, payload, 'verified')
        except Exception as error:
            payload['probe_error'] = {'type': type(error).__name__, 'message': str(error)}
            self.save(identity, payload, 'failed')
            raise
        finally:
            try:
                self.cleanup(identity, payload)
            except Exception:
                self.save(identity, payload, 'recovery_required')
                raise Conflict('endpoint naming canary cleanup requires recovery; handoff forbidden') from None
        return {**result, 'cleanup_verified': True, 'probe_id': identity, 'creation_mode': creation_mode, 'process_readiness_verified': True}
