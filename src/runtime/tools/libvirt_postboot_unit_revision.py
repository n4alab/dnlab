"""Apply/recover one original unit revision with a separate file capability.

The directory mutator stays directory-only. Existing preflight/staging/exchange
engines qualify unchanged resources, inactive services and both file births.
Only the original candidate may be created/recovered; no new prepare, account
command, cleanup, reload/start or libvirt connection is exposed.
"""
from copy import deepcopy

from dnlab_runtime.libvirt_configuration import UNIT
from dnlab_runtime.libvirt_configuration_adapter import ConfigurationFileAdapter
from dnlab_runtime.libvirt_configuration_staging import ConfigurationStaging
from dnlab_runtime.libvirt_current_session import CurrentConfigurationSession,CurrentSessionView
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.manifest import Conflict


class PreparedUnitFiles(InstallationFiles):
    def __init__(self,root,*,journal,reference):
        if reference.get('phase')!='prepared' or reference.get('proof') is not None:
            raise Conflict('original prepared unit revision reference required')
        self.request=ConfigurationFileAdapter.request(reference)
        self.candidate=ConfigurationStaging.item(self.request)
        super().__init__(root,journal=journal)

    def _candidate(self,item,operation):
        if operation!=self.request['id'] or item!=self.candidate:
            raise Conflict('original prepared unit candidate mutation binding differs')

    def create(self,item,operation_id,**kwargs):
        self._candidate(item,operation_id)
        return super().create(item,operation_id,**kwargs)

    def recover(self,item,operation_id,**kwargs):
        self._candidate(item,operation_id)
        return super().recover(item,operation_id,**kwargs)

    def observe(self,item,operation_id):
        source=self.request['plan']['source_item']
        if not (item==source and operation_id==self.request['installation']['id']):
            self._candidate(item,operation_id)
        return super().observe(item,operation_id)

    def observe_relocated(self,item,operation_id,destination):
        source=self.request['plan']['source_item']
        if item==source and operation_id==self.request['installation']['id']:
            allowed=(UNIT,self.request['staging'],self.request['backup'])
        else:
            self._candidate(item,operation_id);allowed=(UNIT,self.request['staging'])
        if destination not in allowed:raise Conflict('original prepared unit relocation differs')
        return super().observe_relocated(item,operation_id,destination)


class PostBootUnitRevision:
    def __init__(self,directories,*,effective_source,window,unit_reference):
        self.directories,self.reference=directories,deepcopy(unit_reference)
        self.view=CurrentSessionView(directories.session.recovery,directories.reference['recovery']['id'])
        if self.view.read()!=effective_source:raise Conflict('original effective unit revision source differs')
        readonly=directories.readonly
        def dependency(spec):
            if readonly.dependencies is None:raise Conflict('no original unit revision dependency selected')
            return readonly.dependencies(spec)
        arguments=dict(snapshot=readonly.snapshot,identity=readonly.identity,directory_dependency=dependency,
            window=window,journal_identity=directories.reference['journal_identity'])
        original=CurrentConfigurationSession(self.view,**arguments)
        original._binding(self.reference)
        self.files=PreparedUnitFiles(self.view.files.root,journal=self.view.journal,reference=self.reference)
        self.revision=CurrentConfigurationSession(self.view,**arguments,revision_files=self.files)
        self.revision._binding(self.reference)

    def apply_original(self):return self.revision.apply_original(self.reference)
    def recover_original(self):return self.revision.recover_original(self.reference)
    def effective(self):return self.revision.effective()
