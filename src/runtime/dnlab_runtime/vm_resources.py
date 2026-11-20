"""Compose the original directory, storage and TAP observers for VM boot.

Only already-persisted resources are observed. This capability allocates no
resources and cannot replace a missing directory, overlay, endpoint or writer.
"""
from .vm_directory_storage import DirectoryVMStorage
from .vm_taps import VMTaps
from .vm_template import require, template_digest


class VMResourcePreflight:
    def __init__(self, storage, taps):
        require(isinstance(storage,DirectoryVMStorage) and isinstance(taps,VMTaps)
                and storage.definitions is taps.definitions and storage.journal is taps.journal,
                'original VM directory/storage and TAP controllers required')
        self.storage, self.taps = storage, taps
        self.definitions, self.journal = storage.definitions, storage.journal
        self.operation = storage.operation

    def __call__(self, value):
        with self.journal.execution_lock:
            require(value['birth']['creator_operation_id'] == self.operation
                    and self.definitions.read(self.operation) == value,
                    'original persisted VM resource owner required')
            self.definitions._fence(value)
            self.definitions._session(value)
            directory = self.storage.directories.observe(self.operation)
            storage = self.storage.observe(self.operation)
            taps = self.taps.observe(self.operation)
            require(directory['phase'] == storage['phase'] == 'ready' and taps['phase'] == 'retained'
                    and all(proof['birth'] == value['birth']
                            and proof['definition_sha256'] == value['request_fingerprint']
                            for proof in (directory,storage,taps))
                    and template_digest(storage['template']) == value['birth']['template_sha256'],
                    'complete original VM resources must be ready')
            require(self.storage.assets(storage) == dict(template_sha256=value['birth']['template_sha256'],
                                                        assets_verified=True),
                    'original published template verification required')
            require(self.definitions.read(self.operation) == value,
                    'VM definition changed during complete resource preflight')
            self.definitions._fence(value)
            self.definitions._session(value)
            return dict(request_fingerprint=value['request_fingerprint'], session_sha256=value['session_sha256'],
                        assets_verified=True, overlays_verified=True, endpoints_verified=True)
