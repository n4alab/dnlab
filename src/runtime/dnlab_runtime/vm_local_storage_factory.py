"""Bind original runtime/TAP actor and tracked formatter to local VM storage.

Construction launches no worker or VM. The initial-start coordinator creates the
directory and reserves the TAP set first. This factory keeps original storage
instances and formatter runners alive for their explicit same-attempt recovery.
"""
from copy import deepcopy
from pathlib import PurePosixPath

from .libvirt_xml import absolute
from .manifest import fingerprint
from .vm_directories import VMDirectories
from .vm_directory_storage import DirectoryVMStorage
from .vm_overlay_runner import OverlayProcessRunner, OverlayWorkerObserver
from .vm_tap_local import LocalTapEndpoints, worker_command
from .vm_taps import VMTaps
from .vm_template import digest, fields, require


class VMLocalStorageFactory:
    def __init__(self, directories, taps, runtime, *, assets, writers, formatter, binary, verify_formatter):
        require(isinstance(directories,VMDirectories) and isinstance(taps,VMTaps)
                and isinstance(taps.endpoints,LocalTapEndpoints)
                and directories.definitions is taps.definitions and runtime.journal is directories.journal
                and all(callable(getattr(runtime,name,None)) for name in ('check','reference','verify'))
                and callable(assets) and callable(getattr(assets,'verify',None)) and callable(writers)
                and taps.writers is writers and callable(verify_formatter),
                'original runtime, directory/TAP actor, published assets and shared writer census required')
        fields(formatter,('python','worker'),'qualified overlay formatter profile')
        for value in (*formatter.values(),binary):
            fields(value,('path','sha256'),'qualified formatter asset');absolute(value['path'])
            require(digest(value['sha256']), 'qualified formatter asset digest required')
        require(binary['path'] == '/usr/bin/qemu-img'
                and PurePosixPath(formatter['worker']['path']).parts[-2:] == ('tools','vm_overlay_worker_main.py'),
                'fixed original qemu-img and overlay worker required')
        self.directories,self.taps,self.runtime = directories,taps,runtime
        self.endpoints = taps.endpoints
        self.definitions,self.journal = directories.definitions,directories.journal
        self.assets,self.writers,self.verify_formatter = assets,writers,verify_formatter
        self.formatter,self.binary = deepcopy(formatter),deepcopy(binary)
        self.profile_sha256 = fingerprint(dict(formatter=formatter,binary=binary))
        self.epoch = fingerprint(runtime.check());self._storage = {}
        self._guard()

    def _guard(self):
        require(self.directories.definitions is self.taps.definitions is self.definitions
                and self.taps.endpoints is self.endpoints and self.endpoints.sets is self.taps
                and self.directories.journal is self.taps.journal is self.runtime.journal is self.journal
                and self.taps.writers is self.writers and fingerprint(self.runtime.check()) == self.epoch
                and fingerprint(dict(formatter=self.formatter,binary=self.binary)) == self.profile_sha256
                and self.verify_formatter(deepcopy(self.formatter),deepcopy(self.binary)) == self.profile_sha256,
                'original local VM formatter/runtime prerequisites changed')

    def _assets(self, value):
        self._guard()
        return self.assets(deepcopy(value))

    def _writers(self, value):
        self._guard()
        return self.writers(deepcopy(value))

    def _runner(self):
        self._guard()
        return OverlayProcessRunner(self.journal,profile=deepcopy(self.formatter),
                                    observer=OverlayWorkerObserver(self.journal))

    def __call__(self, operation):
        with self.journal.execution_lock:
            self._guard()
            definition = self.definitions.read(operation)
            self.definitions._fence(definition);self.definitions._session(definition)
            directory = self.directories.observe(operation)
            require(directory['phase'] == 'ready', 'original ready directory required before storage factory')
            taps = self.taps.read(operation)
            reference = self.runtime.reference(worker_command(taps))
            # bind() checks the original actor on retry. It never replaces a
            # lost actor, even when names and retained kernel resources match.
            self.taps.endpoints.bind(operation,reference)
            if operation not in self._storage:
                self._storage[operation] = DirectoryVMStorage(self.directories,operation,
                    assets=self._assets,writers=self._writers,binary=deepcopy(self.binary),runner_factory=self._runner)
            storage = self._storage[operation]
            require(storage.directories is self.directories and storage.operation == operation
                    and storage.directory == directory, 'original VM storage factory capability changed')
            self._guard()
            return storage
