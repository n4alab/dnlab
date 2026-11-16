"""Local overlays bound to the original ready per-VM directory.

This composes the existing directory, storage and formatter controllers. It
creates no directories and does not define/start a domain. Native callers must
supply qualified assets, writer census and formatter providers.
"""
from copy import deepcopy
from pathlib import PurePosixPath
from xml.etree import ElementTree as ET

from .manifest import Conflict, fingerprint
from .vm_directories import VMDirectories
from .vm_overlay_files import OverlayFiles
from .vm_storage import VMStorage
from .vm_template import require, template_digest


class DirectoryVMStorage(VMStorage):
    def __init__(self, directories, operation, *, assets, writers, binary, runner_factory):
        require(isinstance(directories,VMDirectories), 'original VM directory controller required')
        directory = directories.observe(operation)
        require(directory['phase']=='ready', 'original ready VM resource directory required')
        self.directories,self.operation = directories,operation
        self.directory = deepcopy(directory)
        self.directory_sha256 = fingerprint(directory)
        parent = {key:value for key,value in directory['proof']['identity'].items() if key!='kind'}
        files = OverlayFiles(directories.journal,root=directory['spec']['path'],parent_identity=parent,
                             binary=binary,runner_factory=runner_factory,preflight=self._overlay_preflight)
        super().__init__(directories.definitions,assets=assets,files=files,writers=writers)

    def _directory(self):
        require(self.directories.definitions is self.definitions
                and self.directories.journal is self.journal
                and fingerprint(self.directory)==self.directory_sha256,
                'original VM directory capability changed')
        observed = self.directories.observe(self.operation)
        require(observed==self.directory and fingerprint(observed)==self.directory_sha256,
                'original VM directory receipt changed')
        require(self.files.journal is self.journal and self.files.root==observed['spec']['path']
                and self.files.parent_identity=={key:value for key,value in observed['proof']['identity'].items() if key!='kind'},
                'overlay adapter parent differs from original VM directory')

    def _owner(self, value, *, mutating):
        require(value['id']==self.operation and value['birth']==self.directory['birth']
                and value['definition_sha256']==self.directory['definition_sha256'],
                'original directory/storage VM owner differs')
        self._directory()
        definition = self.definitions.read(self.operation)
        require(all(str(PurePosixPath(item['spec']['path']).parent)==self.directory['spec']['path']
                    for item in value['items']), 'overlay outside original VM resource directory')
        if mutating:self._before_definition(definition)
        require(self.assets(deepcopy(value))==dict(template_sha256=template_digest(value['template']),assets_verified=True),
                'original directory/storage immutable assets differ')
        writers = self._writer_state(value)
        if mutating and writers:raise Conflict('VM overlays cannot be created while a writer exists')
        self._directory()
        require(self.definitions.read(self.operation)==definition, 'VM definition changed during overlay preflight')
        if mutating:self._before_definition(definition)
        return writers

    def _before_definition(self, definition):
        self.definitions._fence(definition)
        require(definition['phase']=='prepared' and definition.get('creation_ack') is None
                and definition.get('boot') is None, 'overlay allocation must precede domain definition/start')
        self.definitions._absent(self.definitions.connection.lookupByUUIDString,definition['birth']['uuid'])
        self.definitions._absent(self.definitions.connection.lookupByName,ET.fromstring(definition['xml']).findtext('name'))

    def _overlay_preflight(self, item, operation, *, mutating):
        require(operation==self.operation, 'original overlay operation required')
        value = self.read(operation)
        require(sum(original==item for original in value['items'])==1,
                'original persisted overlay item required')
        return self._owner(value,mutating=mutating)

    def _check(self, value, *, mutate):
        self._owner(value,mutating=mutate)
        super()._check(value,mutate=mutate)
        self._owner(value,mutating=mutate)
