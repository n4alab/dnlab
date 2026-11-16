"""Bind VM storage admission to one original published local template.

The catalog is an already opened readonly bundle controller. Opening/binding
its original journal and store is a caller responsibility. No path discovery,
catalog initialization, import, copying or hypervisor operation happens here.
"""
from copy import deepcopy
from pathlib import PurePosixPath

from .libvirt_xml import absolute
from .manifest import Conflict, fingerprint, identifier
from .vm_events import validate_birth
from .vm_template import fields, template_digest, validate_template
from .vm_template_install import TemplateBundleInstall


class PublishedTemplateAssets:
    def __init__(self, catalog, *, host_id, publication):
        identifier(host_id, 'template host')
        if not isinstance(catalog, TemplateBundleInstall) or not catalog.readonly:
            raise Conflict('original readonly template catalog required')
        fields(publication, ('operation_id','directory','template_sha256','bundle'), 'original template publication')
        absolute(publication['directory']);identifier(publication['operation_id'],'template import')
        template = validate_template(publication['bundle']['template'])
        digest = template_digest(template)
        if (publication['template_sha256'] != digest or publication['bundle']['template_sha256'] != digest
                or publication['directory'] != str(PurePosixPath(catalog.root)/digest)
                or catalog.window.receipt['context'].get('host_id') != host_id):
            raise Conflict('original local template publication binding differs')
        self.catalog, self.host_id = catalog, host_id
        self.journal = catalog.journal
        self.publication = deepcopy(publication)
        self.sha256 = fingerprint(publication)
        self.catalog_sha256 = self._catalog_binding()
        self._observe()

    def _catalog_binding(self):
        journal_id = self.catalog.journal.identity
        if (not isinstance(journal_id,str) or len(journal_id) != 32
                or any(c not in '0123456789abcdef' for c in journal_id)):
            raise Conflict('original logical template journal identity required')
        return fingerprint(dict(journal_identity=journal_id,root=self.catalog.root,
                                parent=self.catalog.parent,window_sha256=self.catalog.window.sha256,
                                host_id=self.catalog.window.receipt['context'].get('host_id'),
                                pinned_host_id=self.host_id))

    def _bound(self):
        if (not self.catalog.readonly or self.catalog.journal is not self.journal
                or getattr(self.catalog.journal,'closed',False)
                or self._catalog_binding() != self.catalog_sha256
                or fingerprint(self.publication) != self.sha256):
            raise Conflict('original template catalog capability changed or closed')

    def _observe(self):
        self._bound()
        actual = self.catalog.observe(self.publication['operation_id'])
        if actual != self.publication or fingerprint(actual) != self.sha256:
            raise Conflict('original published template changed; no fallback')
        self._bound()
        return actual

    def verify(self, *, birth, template, bundle_root):
        validate_birth(birth);template = validate_template(template);absolute(bundle_root)
        expected = self.publication
        if (birth['host_id'] != self.host_id or birth['template_sha256'] != expected['template_sha256']
                or template_digest(template) != expected['template_sha256']
                or template != expected['bundle']['template'] or bundle_root != expected['directory']):
            raise Conflict('VM template, placement or bundle path differs from original publication')
        self._observe()
        return dict(template_sha256=expected['template_sha256'],assets_verified=True)

    def __call__(self, value):
        if (not isinstance(value,dict) or not {'id','birth','template','bundle_root'} <= set(value)
                or not isinstance(value['birth'],dict)
                or value['id'] != value['birth'].get('creator_operation_id')):
            raise Conflict('original VM storage owner required before template admission')
        return self.verify(birth=value['birth'],template=value['template'],bundle_root=value['bundle_root'])
