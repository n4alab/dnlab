"""Retire one original VM directory; never recursively delete its contents.

The explicit preflight qualifies completed storage/TAP removal and writer
absence. A residual console additionally needs the immutable original peer
receipt. Root writers must honor the qualified administration window.
"""
from contextlib import contextmanager
from copy import deepcopy
import json
import os
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET

from .backend_reservations import available, verify_tap_reservations
from .libvirt_configuration_swap import NOREPLACE, rename_siblings
from .libvirt_install_files import InstallationFiles, MARKER
from .libvirt_provisioning import ProvisioningWindow
from .manifest import Conflict, canonical, fingerprint, identifier
from .vm_console import socket_identity
from .vm_console_endpoint import read as endpoint_receipt
from .vm_definition_retirement import UnstartedDefinitionRetirement
from .vm_directories import VMDirectories
from .vm_overlay_files import directory_identity, local_filesystem
from .vm_template import digest, fields, require


class VMDirectoryRetirement:
    def __init__(self, directories, retirement, *, window, preflight):
        require(isinstance(directories,VMDirectories) and isinstance(directories.files,InstallationFiles)
                and not directories.files.readonly and directories.files.root == '/'
                and isinstance(retirement,UnstartedDefinitionRetirement)
                and directories.definitions is retirement.definitions
                and isinstance(window,ProvisioningWindow) and callable(preflight),
                'original directory, retirement, exclusive window and remaining-resource proof required')
        self.directories,self.retirement,self.window,self.preflight = directories,retirement,window,preflight
        self.definitions,self.journal,self.files = directories.definitions,directories.journal,directories.files
        with self.journal.transaction():
            self.journal.db.execute('CREATE TABLE IF NOT EXISTS vm_directory_retirements '
                '(id TEXT PRIMARY KEY,definition_id TEXT UNIQUE NOT NULL,payload TEXT NOT NULL,fingerprint TEXT NOT NULL)')

    @staticmethod
    def _quarantine(value):return '.dnlab-retired-directory-'+fingerprint(dict(
        id=value['id'],birth=value['birth'],directory=value['directory'],retirement=value['retirement']))

    @staticmethod
    def _proof(value):
        return dict(directory_sha256=fingerprint(value['directory']),retirement_sha256=fingerprint(value['retirement']),
            storage_retirement_sha256=value['storage_retirement_sha256'],tap_retirement_sha256=value['tap_retirement_sha256'],
            original_path_absent=True,quarantine_absent=True,parent_synced=True)

    def read(self, operation):
        row = self.journal.db.execute('SELECT * FROM vm_directory_retirements WHERE id=?',(operation,)).fetchone()
        if row is None:raise Conflict('original VM directory retirement missing')
        value = json.loads(row['payload'])
        fields(value,('id','birth','definition','directory','file_birth','retirement','console','storage_retirement_sha256',
            'tap_retirement_sha256','window_sha256','quarantine','phase','proof'),'VM directory retirement')
        require(fingerprint(value) == row['fingerprint'] and value['id'] == row['id'] == operation
                and row['definition_id'] == value['directory']['id'] == value['birth']['creator_operation_id']
                and value['birth'] == value['directory']['birth'] == value['definition']['birth'] == value['retirement']['birth']
                and digest(value['storage_retirement_sha256']) and digest(value['tap_retirement_sha256'])
                and value['window_sha256'] == self.window.sha256 and value['quarantine'] == self._quarantine(value)
                and value['phase'] in ('prepared','rename_requested','quarantined','console_unlink_requested','empty','rmdir_requested','removed'),
                'original VM directory retirement lineage differs')
        expected = self._proof(value) if value['phase'] == 'removed' else None
        require(fingerprint(value['proof']) == fingerprint(expected), 'original VM directory absence receipt differs')
        return value

    def _write(self, value):
        self.journal.db.execute('UPDATE vm_directory_retirements SET payload=?,fingerprint=? WHERE id=?',
                                (canonical(value),fingerprint(value),value['id']))

    def _source(self, value, *, held=True):
        if held:require(self.read(value['id']) == value, 'original directory retirement changed')
        require(self.directories.definitions is self.definitions and self.directories.files is self.files
                and self.retirement.definitions is self.definitions and self.files.journal is self.journal,
                'original directory retirement controllers changed')
        directory = value['directory'];operation = directory['id'];original = value['retirement']
        require(self.directories.read(operation) == directory and directory['phase'] == 'ready'
                and self.retirement.read(original['id']) == original and original['phase'] == 'retired',
                'original directory and completed domain retirement required')
        expected = deepcopy(original['definition'])
        expected.update(phase='retired',retirement=dict(id=original['id'],definition_sha256=original['definition_sha256']))
        require(self.definitions.read(operation) == value['definition'] == expected,
                'original retired directory owner changed')
        require(isinstance(value['file_birth'],dict)
                and self.files._birth(self.directories._item(directory),operation) == value['file_birth']
                and value['file_birth']['phase'] == 'durability_confirmed'
                and value['file_birth']['proof'] == directory['proof'], 'original durable directory birth changed')
        context = self.directories.window.receipt['context']
        require(self.directories.read_context() == self.window.receipt['context'] == context
                and context['host_id'] == value['birth']['host_id']
                and context['boot_id'] == self.definitions.session.proof()['daemon']['boot_id'],
                'original directory retirement context differs')
        self.definitions._fence(expected);self.definitions._session(expected)
        available(self.journal,value['birth']['lab_id'],value['birth']['node_id'],'libvirt',vm_birth=value['birth'])
        verify_tap_reservations(self.journal,value['birth'],expected['xml'])
        ack = original['definition']['creation_ack']
        self.definitions._absent(self.definitions.connection.lookupByUUIDString,ack['uuid'])
        self.definitions._absent(self.definitions.connection.lookupByName,ack['name'])
        console = endpoint_receipt(self.journal,original['definition'],directory) if 'boot' in original['definition'] else None
        require(console == value['console'], 'original console cleanup proof changed')
        receipt = dict(definition_sha256=expected['request_fingerprint'],retirement_sha256=fingerprint(original),
            storage_retirement_sha256=value['storage_retirement_sha256'],tap_retirement_sha256=value['tap_retirement_sha256'],
            storage_removed_verified=True,taps_absent_verified=True,writers_absent=True)
        require(fingerprint(self.preflight(deepcopy(value))) == fingerprint(receipt),
                'complete disk/TAP retirement and writer absence preflight required')
        self.window.verify(self.directories._item(directory),operation,value['window_sha256'])
        self.definitions._fence(expected)
        require(self.definitions.read(operation) == expected and self.directories.read_context() == context,
                'directory owner/context changed during retirement preflight')

    @contextmanager
    def _parent(self, value):
        with self.files._parent(value['directory']['spec']['path']) as (parent,leaf):
            require(directory_identity(parent) == value['directory']['parent'], 'original VM administrative parent changed')
            local_filesystem(parent)
            yield parent,leaf
            require(directory_identity(parent) == value['directory']['parent'], 'VM administrative parent changed during cleanup')
            with self.files._parent(value['directory']['spec']['path']) as (visible,_):
                require(directory_identity(visible) == value['directory']['parent'], 'VM administrative parent path replaced')

    @staticmethod
    def _exists(parent, name):
        try:os.stat(name,dir_fd=parent,follow_symlinks=False)
        except FileNotFoundError:return False
        return True

    @contextmanager
    def _directory(self, parent, name, value):
        original = value['directory'];item = self.directories._item(original)
        require(self.files._qualified(item,original['id'],parent,name,value['file_birth']) == original['proof'],
                'original VM directory inode or marker changed')
        fd = os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
        try:
            require(self.files._identity(fd,original['spec']) == original['proof']['identity']
                    and os.getxattr(fd,MARKER) == self.files._marker(item,original['id']), 'original VM directory changed before cleanup')
            yield fd
            require(self.files._identity(fd,original['spec']) == original['proof']['identity']
                    and os.getxattr(fd,MARKER) == self.files._marker(item,original['id']), 'original VM directory changed during cleanup')
            if self._exists(parent,name):
                linked = os.stat(name,dir_fd=parent,follow_symlinks=False)
                require((linked.st_dev,linked.st_ino) == (os.fstat(fd).st_dev,os.fstat(fd).st_ino), 'VM directory path replaced')
            else:require(value['phase'] == 'rmdir_requested' and os.fstat(fd).st_nlink == 0,
                         'original VM directory disappeared outside rmdir')
        finally:os.close(fd)

    def _contents(self, fd, value):
        names = os.listdir(fd)
        console = value['console']
        name = PurePosixPath(ET.fromstring(value['definition']['xml']).find('devices/serial/source').get('path')).name
        require(not names or names == [name], 'unexpected files in original VM directory; no recursive cleanup')
        if names:
            require(console is not None and socket_identity(fd,name) == console['endpoint'],
                    'residual console lacks original qualified endpoint proof')
        return names

    def _advance(self, value, phase):
        with self.journal.transaction():
            self._source(value);value['phase'] = phase;self._write(value);self._source(value)

    def prepare(self, operation, definition_id, retirement_id, *, storage_retirement_sha256, tap_retirement_sha256):
        identifier(operation,'directory retirement operation_id')
        require(digest(storage_retirement_sha256) and digest(tap_retirement_sha256), 'original disk and TAP retirement digests required')
        with self.journal.execution_lock:
            row = self.journal.db.execute('SELECT id FROM vm_directory_retirements WHERE id=? OR definition_id=?',
                                          (operation,definition_id)).fetchone()
            if row is not None:
                value = self.read(row['id'])
                require(value['id'] == operation and value['directory']['id'] == definition_id
                        and value['retirement']['id'] == retirement_id
                        and value['storage_retirement_sha256'] == storage_retirement_sha256
                        and value['tap_retirement_sha256'] == tap_retirement_sha256, 'original directory retirement request differs')
                self._source(value);return value
            directory = self.directories.read(definition_id);retirement = self.retirement.read(retirement_id)
            value = dict(id=operation,birth=deepcopy(directory['birth']),definition=self.definitions.read(definition_id),
                directory=directory,file_birth=self.files._birth(self.directories._item(directory),definition_id),retirement=retirement,
                console=endpoint_receipt(self.journal,retirement['definition'],directory) if 'boot' in retirement['definition'] else None,
                storage_retirement_sha256=storage_retirement_sha256,tap_retirement_sha256=tap_retirement_sha256,
                window_sha256=self.window.sha256,quarantine='',phase='prepared',proof=None)
            value['quarantine'] = self._quarantine(value);self._source(value,held=False)
            with self._parent(value) as (parent,leaf):
                require(not self._exists(parent,value['quarantine']), 'VM directory quarantine occupied')
                with self._directory(parent,leaf,value) as fd:self._contents(fd,value)
                with self.journal.transaction():
                    self._source(value,held=False)
                    self.journal.db.execute('INSERT INTO vm_directory_retirements VALUES(?,?,?,?)',
                        (operation,definition_id,canonical(value),fingerprint(value)))
            return self.read(operation)

    def apply(self, operation):
        with self.journal.execution_lock:
            value = self.read(operation);self._source(value)
            with self._parent(value) as (parent,leaf):
                quarantine = value['quarantine']
                if value['phase'] == 'prepared':
                    require(not self._exists(parent,quarantine), 'VM directory quarantine occupied')
                    with self._directory(parent,leaf,value) as fd:self._contents(fd,value)
                    self._advance(value,'rename_requested')
                    with self._directory(parent,leaf,value) as fd:
                        self._contents(fd,value);self._source(value)
                    rename_siblings(parent,leaf,quarantine,NOREPLACE)
                if value['phase'] == 'rename_requested':
                    require(not self._exists(parent,leaf), 'VM directory rename uncertain; no resend')
                    with self._directory(parent,quarantine,value) as fd:self._contents(fd,value)
                    os.fsync(parent);self._advance(value,'quarantined')
                if value['phase'] == 'quarantined':
                    with self._directory(parent,quarantine,value) as fd:
                        names = self._contents(fd,value)
                        if names:
                            self._advance(value,'console_unlink_requested');self._source(value)
                            require(self._contents(fd,value) == names, 'original console changed before unlink')
                            os.unlink(names[0],dir_fd=fd)
                            os.fsync(fd)
                    if value['phase'] == 'quarantined':self._advance(value,'empty')
                if value['phase'] == 'console_unlink_requested':
                    with self._directory(parent,quarantine,value) as fd:
                        require(not self._contents(fd,value), 'console unlink uncertain; no resend')
                        os.fsync(fd)
                    self._advance(value,'empty')
                if value['phase'] == 'empty':
                    # Absence predating this request cannot become evidence
                    # of our rmdir on a later retry.
                    with self._directory(parent,quarantine,value) as fd:
                        require(not self._contents(fd,value), 'VM directory not empty before rmdir intent')
                        self._source(value)
                    self._advance(value,'rmdir_requested')
                    with self._directory(parent,quarantine,value) as fd:
                        require(not self._contents(fd,value), 'VM directory not empty before rmdir')
                        self._source(value)
                        require(not self._exists(parent,leaf), 'original VM directory path reoccupied')
                        os.rmdir(quarantine,dir_fd=parent)
                require(not self._exists(parent,leaf) and not self._exists(parent,quarantine),
                        'VM directory removal uncertain or path occupied; no resend')
                self._source(value);os.fsync(parent);self._source(value)
                if value['phase'] != 'removed':
                    with self.journal.transaction():
                        value.update(phase='removed',proof=self._proof(value));self._write(value);self._source(value)
                        require(not self._exists(parent,leaf) and not self._exists(parent,quarantine),
                                'VM directory reappeared during absence publication')
                        with self._parent(value) as (visible,visible_leaf):
                            require(not self._exists(visible,visible_leaf) and not self._exists(visible,quarantine),
                                    'visible VM directory path reappeared during absence publication')
                return self.read(operation)
