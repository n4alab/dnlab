"""Readonly remaining-resource capability for original VM directory removal."""
from copy import deepcopy

from .manifest import fingerprint
from .vm_storage_retirement import VMStorageRetirement
from .vm_tap_retirement import VMTapRetirement
from .vm_template import require, template_digest


class VMRetiredResources:
    def __init__(self, storage, taps, *, storage_operation, tap_operation):
        require(isinstance(storage,VMStorageRetirement) and isinstance(taps,VMTapRetirement)
                and storage.definitions is taps.definitions and storage.journal is taps.journal,
                'original storage and TAP retirement controllers required')
        self.storage,self.taps,self.definitions,self.journal = storage,taps,storage.definitions,storage.journal
        self.storage_receipt,self.tap_receipt = storage.read(storage_operation),taps.read(tap_operation)
        require(self.storage_receipt['phase'] == self.tap_receipt['phase'] == 'removed',
                'completed original storage and TAP cleanup required')
        self.storage_sha256,self.tap_sha256 = fingerprint(self.storage_receipt),fingerprint(self.tap_receipt)

    def __call__(self, value):
        with self.journal.execution_lock:
            storage,taps = self.storage_receipt,self.tap_receipt
            require(self.storage.definitions is self.taps.definitions is self.definitions
                    and self.storage.journal is self.taps.journal is self.journal
                    and self.storage.files.files is self.storage.storage.files
                    and self.taps.taps.endpoints is self.taps.endpoints,
                    'original retired-resource controllers changed')
            require(fingerprint(storage) == self.storage_sha256 and fingerprint(taps) == self.tap_sha256
                    and self.storage.read(storage['id']) == storage and self.taps.read(taps['id']) == taps
                    and value['storage_retirement_sha256'] == self.storage_sha256
                    and value['tap_retirement_sha256'] == self.tap_sha256
                    and value['birth'] == storage['birth'] == taps['birth']
                    and value['retirement'] == storage['retirement'] == taps['retirement']
                    and value['definition'] == storage['definition'] == taps['definition'],
                    'original retired resource lineage changed')
            definition = self.definitions.read(value['birth']['creator_operation_id'])
            require(definition == value['definition'], 'original retired VM owner changed')
            self.definitions._fence(definition);self.definitions._session(definition)
            require(self.storage.storage.read(storage['storage']['id']) == storage['storage']
                    and self.taps.taps.read(taps['tap_set']['id']) == taps['tap_set'],
                    'original storage or TAP birth changed')
            self.taps._layout(taps)
            require(self.storage.storage._writer_state(storage['storage']) == []
                    and self.taps.taps._writers(taps['tap_set'],definition) == [],
                    'qualified writer absence required before directory cleanup')
            require(self.storage.storage.assets(deepcopy(storage['storage'])) == dict(
                template_sha256=template_digest(storage['storage']['template']),assets_verified=True),
                'original immutable template changed during final cleanup')
            for item in storage['storage']['items']:
                child = self.storage.files.read(item,storage['storage']['id'])
                require(child['phase'] == 'removed' and child['definition_retirement_sha256'] == fingerprint(value['retirement'])
                        and self.storage.storage.files._load(item,storage['storage']['id']) == child['original'],
                        'original disk removal proof changed')
            require(self.definitions.read(value['birth']['creator_operation_id']) == definition,
                    'VM owner changed during retired-resource observation')
            self.definitions._fence(definition)
            return dict(definition_sha256=definition['request_fingerprint'],retirement_sha256=fingerprint(value['retirement']),
                storage_retirement_sha256=self.storage_sha256,tap_retirement_sha256=self.tap_sha256,
                storage_removed_verified=True,taps_absent_verified=True,writers_absent=True)
