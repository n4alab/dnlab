"""Metadata-only retirement from an exact completed current directory lineage."""
from copy import deepcopy

from dnlab_runtime.libvirt_current_session import CurrentConfigurationSession,CurrentSessionView
from dnlab_runtime.manifest import Conflict


class PostBootUnitRetirement:
    def __init__(self,directories,*,effective_source,window,unit_reference):
        self.directories,self.reference=directories,deepcopy(unit_reference)
        self.view=CurrentSessionView(directories.session.recovery,directories.reference['recovery']['id'])
        self.source=deepcopy(effective_source)
        if self.view.read()!=self.source:raise Conflict('original effective retirement source differs')
        readonly=directories.readonly
        def dependency(spec):
            if readonly.dependencies is None:raise Conflict('no original retirement dependency selected')
            return readonly.dependencies(spec)
        self.window=window
        self.session=CurrentConfigurationSession(self.view,snapshot=readonly.snapshot,identity=readonly.identity,
            directory_dependency=dependency,window=window,journal_identity=directories.reference['journal_identity'])
        if self.session.driver.read(self.reference['id'])!=self.reference:
            raise Conflict('original historical unit retirement reference differs')

    def retire_original(self):
        with self.view.journal.execution_lock:
            if self.view.read()!=self.source:raise Conflict('current retirement lineage changed')
            return self.session.retire_original(self.reference,window=self.window)
