"""Prepare a unit-policy revision from the completed current directory lineage.

Only revision metadata may be prepared. The installed unit, staging/backup
files, accounts and services remain unchanged. The original directory window
need not be reopened: revision has its own explicit current-context window.
"""
from copy import deepcopy

from dnlab_runtime.libvirt_current_session import CurrentConfigurationSession,CurrentSessionView
from dnlab_runtime.manifest import Conflict


class MetadataConfigurationSession(CurrentConfigurationSession):
    def apply_original(self,reference):raise Conflict('metadata-only unit session cannot apply revision')
    def recover_original(self,reference):raise Conflict('metadata-only unit session cannot recover revision')


class PostBootUnitPrepare:
    def __init__(self,directories,*,effective_source,window):
        self.directories=directories
        recovery=directories.session.recovery
        self.view=CurrentSessionView(recovery,directories.reference['recovery']['id'])
        self.source=deepcopy(effective_source)
        if self.view.read()!=self.source:raise Conflict('original effective directory source differs')
        readonly=directories.readonly
        def dependency(spec):
            if readonly.dependencies is None:raise Conflict('no original unit revision dependency selected')
            return readonly.dependencies(spec)
        self.revision=MetadataConfigurationSession(self.view,snapshot=readonly.snapshot,
            identity=readonly.identity,directory_dependency=dependency,window=window,
            journal_identity=directories.reference['journal_identity'])

    def prepare(self):
        with self.view.journal.execution_lock:
            if self.view.read()!=self.source:raise Conflict('effective directory source changed before unit prepare')
            reference=self.revision.prepare()
            if reference['phase']!='prepared':raise Conflict('unit revision already started; original reference required')
            if self.view.read()!=self.source:raise Conflict('effective directory source changed during unit prepare')
            return deepcopy(reference)
