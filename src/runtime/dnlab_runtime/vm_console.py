"""Bounded serial I/O to the original running QEMU, without guest commands.

The caller supplies the existing qualified VM directory pin (for example the
overlay adapter's root capability). Socket ownership alone is insufficient:
SO_PEERCRED must identify the recorded QEMU incarnation. Connections are never
retried and partial/uncertain writes are returned to the caller, not replayed.
"""
from contextlib import contextmanager, ExitStack
from copy import deepcopy
import os
from pathlib import PurePosixPath
import socket
import stat
import struct
from xml.etree import ElementTree as ET

from .manifest import Conflict
from .vm_console_endpoint import read as endpoint_receipt, remember
from .vm_overlay_files import directory_identity
from .vm_template import require


def socket_identity(parent, name):
    info = os.stat(name, dir_fd=parent, follow_symlinks=False)
    require(stat.S_ISSOCK(info.st_mode) and info.st_nlink == 1, 'original unaliased QEMU console socket required')
    return dict(device=info.st_dev, inode=info.st_ino, uid=info.st_uid,
                gid=info.st_gid, mode=info.st_mode)


class ConsoleStream:
    def __init__(self, stream, verify):
        self._stream, self._verify, self._active = stream, verify, True

    def _check(self):
        require(self._active, 'original VM console session closed')
        self._verify()

    def recv(self, size=65536):
        require(type(size) is int and 0 < size <= 65536, 'bounded console read required')
        self._check()
        try:
            result = self._stream.recv(size)
            self._check()
            return result
        except BaseException:
            self._active = False
            raise

    def send(self, data):
        require(type(data) is bytes and 0 < len(data) <= 65536, 'bounded console bytes required')
        self._check()
        # A short send is explicit. On any failure the caller must not replay
        # an unknown prefix; this adapter issues no automatic guest commands.
        try:
            result = self._stream.send(data)
            self._check()
            return result
        except BaseException:
            self._active = False
            raise


class VMConsole:
    def __init__(self, boot, directories, operation, *, pin_directory, socket_factory=socket.socket):
        require(boot.definitions is directories.definitions and boot.journal is directories.journal
                and callable(pin_directory) and callable(socket_factory),
                'original VM boot, directory and socket providers required')
        self.boot, self.directories, self.operation = boot, directories, operation
        self.pin_directory, self.socket_factory = pin_directory, socket_factory
        with boot.journal.transaction():
            boot.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_console_endpoints '
                '(id TEXT PRIMARY KEY,definition_id TEXT NOT NULL,source_id TEXT NOT NULL,'
                'payload TEXT NOT NULL,fingerprint TEXT NOT NULL,UNIQUE(definition_id,source_id))')

    @contextmanager
    def connect(self, *, timeout=1):
        require(type(timeout) in (int, float) and 0 < timeout <= 30, 'bounded console timeout required')
        definitions = self.boot.definitions
        with self.boot.journal.execution_lock:
            original = definitions.read(self.operation)
            require(self.boot._boot(original)['phase'] == 'running', 'original running VM boot required for console')
            self.boot._instance(original, 1)
            directory = self.directories.observe(self.operation)
            require(directory['phase'] == 'ready' and directory['birth'] == original['birth']
                    and directory['definition_sha256'] == original['request_fingerprint'],
                    'original ready console directory required')
            serial = ET.fromstring(original['xml']).findall('devices/serial')
            require(len(serial) == 1 and serial[0].get('type') == 'unix', 'original Unix serial console required')
            sources = serial[0].findall('source')
            require(len(sources) == 1 and sources[0].get('mode') == 'bind'
                    and set(sources[0].attrib) == {'mode', 'path'}, 'original bound console source required')
            path = PurePosixPath(sources[0].get('path'))
            require(str(path.parent) == directory['spec']['path'] and path.name not in ('', '.', '..'),
                    'console outside original VM directory')
            parent = {key:value for key,value in directory['proof']['identity'].items() if key != 'kind'}
            record = deepcopy(original['boot']['process_record'])
            peer = (record['process']['pid'], record['uid'], record['gid'])

        with ExitStack() as stack:
            fd = stack.enter_context(self.pin_directory())
            require(directory_identity(fd) == parent, 'original console parent changed')
            endpoint = socket_identity(fd, path.name)
            require((endpoint['uid'], endpoint['gid']) == peer[1:], 'original console socket owner differs')
            prior = endpoint_receipt(self.boot.journal,original,directory)
            require(prior is None or prior['endpoint'] == endpoint, 'original console endpoint cannot be replaced')
            # Hold a pidfd for the original incarnation throughout serial I/O.
            process = self.boot._observer(original).process
            stack.enter_context(process.capture(deepcopy(original['birth'])))
            stream = self.socket_factory(socket.AF_UNIX, socket.SOCK_STREAM)
            stack.callback(stream.close)
            stream.settimeout(timeout)

            def verify(*, connected=True, events=True):
                with self.boot.journal.execution_lock:
                    if definitions.read(self.operation) != original or self.directories.observe(self.operation) != directory:
                        raise Conflict('original console generation or directory changed')
                    require(directory_identity(fd) == parent and socket_identity(fd, path.name) == endpoint,
                            'original console endpoint replaced')
                    if events:self.boot._instance(original, 1)
                    else:
                        # Event-source verification may pump its own journal.
                        # Inside this transaction use readonly resource, process
                        # and CPU checks; run the full event check outside it.
                        self.boot._check(original)
                        self.boot._observer(original)(original['birth'])
                        require(self.boot._domain(original).state(0)[0] == 1, 'original console VM stopped during publication')
                    if connected:
                        credentials = stream.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize('3i'))
                        require(struct.unpack('3i', credentials) == peer, 'console peer is not original QEMU')
            verify(connected=False)
            stream.connect(f'/proc/self/fd/{fd}/{path.name}')
            verify()
            with self.boot.journal.execution_lock:
                with self.boot.journal.transaction():
                    verify(events=False)
                    remember(self.boot.journal,original,directory,endpoint)
                    verify(events=False)
            verify()
            lease = ConsoleStream(stream, verify)
            try:
                yield lease
            finally:
                lease._active = False
