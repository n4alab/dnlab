"""Assemble revision from one completed original provisioning session.

Construction reads only its original journal binding. Snapshot/NSS/filesystem
observation starts at explicit prepare/apply/recovery. No account command or
service operation is part of this interface. Host authorization belongs to a
separate operational recipe; tests use only private fixture files and fake NSS.
"""
from copy import deepcopy

from .libvirt_configuration import ConfigurationRevision,UNIT,compile_revision
from .libvirt_configuration_adapter import ConfigurationFileAdapter
from .libvirt_configuration_preflight import CompletedAccountObserver,ConfigurationPreflight
from .manifest import Conflict


class ConfigurationSession:
    def __init__(self,provisioning,reference,*,window,journal_identity):
        journal=provisioning.installer.journal
        if journal.identity!=journal_identity:raise Conflict('original configuration journal identity differs')
        original=provisioning.installer.read(reference['id'])
        if original!=reference:raise Conflict('original completed installation reference differs')
        compile_revision(original)
        if (original['request']!=provisioning.request
                or original['dependencies']!=provisioning.dependencies
                or original['context']!=provisioning.original['context']
                or original['prerequisites']!=dict(provisioning.original['prerequisites'],
                    provisioning_window_sha256=provisioning.window.sha256)
                or window.receipt['operation_id']==original['id']
                or window.receipt['context']!=original['context']
                or window.receipt['targets']!=['file:'+UNIT]):
            raise Conflict('original provisioning and separate revision window required')
        self.provisioning,self.window,self.journal=provisioning,window,journal
        self.original,self.journal_identity=deepcopy(original),journal_identity
        self.operation=window.receipt['operation_id']
        adapter=provisioning.adapter
        if adapter.accounts.journal is not journal or adapter.files.journal is not journal:
            raise Conflict('one original account/filesystem journal required')

        def snapshot():
            self._source()
            current=adapter.snapshot()
            if (not isinstance(current,dict) or set(current)!={'context','prerequisites'}
                    or current['context']!=self.original['context']
                    or current['prerequisites']!=self.original['prerequisites']):
                raise Conflict('original session prerequisites differ during revision')
            result=deepcopy(current)
            result['prerequisites'].pop('provisioning_window_sha256')
            self._source()
            return result

        self.preflight=ConfigurationPreflight(original,snapshot=snapshot,
            accounts=CompletedAccountObserver(adapter.accounts),files=adapter.files,
            directory_dependency=adapter.directory_dependency)
        self.adapter=ConfigurationFileAdapter(adapter.files,window=window,preflight=self.preflight)
        self.driver=ConfigurationRevision(journal,self.adapter,window=window)

    def _source(self):
        if (self.journal.identity!=self.journal_identity
                or self.provisioning.installer.read(self.original['id'])!=self.original):
            raise Conflict('original installation changed since revision assembly')

    def prepare(self):
        self._source()
        return self.driver.prepare(self.operation,self.original)

    def _binding(self,reference):
        self._source()
        if (not isinstance(reference,dict) or reference.get('phase')!='prepared'
                or reference.get('id')!=self.operation):
            raise Conflict('original prepared revision reference required')
        current=self.driver.read(self.operation)
        keys=('id','installation','source_sha256','plan','nonce','staging','backup','window_sha256')
        if any(current[key]!=reference.get(key) for key in keys):
            raise Conflict('original prepared revision binding differs')
        if current.get('predecessor')!=reference.get('predecessor'):
            raise Conflict('original prepared revision predecessor differs')
        return current

    def apply_original(self,reference):
        with self.journal.execution_lock:
            self._binding(reference)
            return self.driver.apply(self.operation)

    def recover_original(self,reference):
        with self.journal.execution_lock:
            self._binding(reference)
            return self.driver.recover(self.operation)

    def effective(self):
        self._source()
        return self.driver.effective(self.operation)
