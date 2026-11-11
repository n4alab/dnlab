"""Readonly current activation lineage and file observation capabilities.

All fresh resource/service preflight remains injected and mandatory. Lineage
projection alone never proves readiness or permits reload/start. The revised
unit is observed through its original exchange/backup, not adopted by path.
"""
from copy import deepcopy

from .libvirt_configuration import UNIT,project_revision
from .libvirt_configuration_adapter import ConfigurationFileAdapter
from .libvirt_current_session import CurrentSessionView
from .manifest import Conflict,fingerprint


class ActivationLineage:
    def __init__(self,view,revision,*,reference,effective_source):
        if view.journal is not revision.journal:raise Conflict('one original activation lineage journal required')
        self.view,self.revision=view,revision
        self.reference,self.source=deepcopy(reference),deepcopy(effective_source)
        self.read()

    def read(self):
        with self.view.journal.execution_lock:
            current=self.revision.read(self.reference['id'])
            self.revision._active(current)
            if current!=self.reference:
                raise Conflict('original activation revision or directory lineage differs')
            view=self.view.read()
            if view==current['installation']:
                source=project_revision(current)
            elif isinstance(self.view,CurrentSessionView) and 'configuration_revision' in view:
                qualification=self.view.recovery.qualification.read(view['postboot']['qualification_id'])
                if qualification.get('completed_revision')!=dict(id=current['id'],sha256=fingerprint(current)):
                    raise Conflict('original post-boot activation revision binding differs')
                source=view
            else:
                raise Conflict('original activation revision or directory lineage differs')
            if source!=self.source:raise Conflict('original effective activation source differs')
            return deepcopy(source)


class ActivationFiles:
    def __init__(self,lineage,files,*,revision_window,preflight=None,completed_exchange=None):
        if (files.journal is not lineage.view.journal
                or getattr(files,'root',None)!=lineage.view.files.root):
            raise Conflict('original activation files required')
        self.lineage,self.files=lineage,files
        reference=lineage.reference
        if revision_window.sha256!=reference['window_sha256']:
            raise Conflict('original revision window binding required for file observation')
        if completed_exchange is not None:
            from .libvirt_activation_exchange import CompletedExchangeFiles
            if (not isinstance(completed_exchange,CompletedExchangeFiles)
                    or completed_exchange.reference!=reference or completed_exchange.swap.files is not files):
                raise Conflict('original completed activation exchange observer required')
        self.completed_exchange=completed_exchange
        self.adapter=(ConfigurationFileAdapter(files,window=revision_window,preflight=preflight)
                      if completed_exchange is None else None)

    def observe(self,item,creator):
        source=self.lineage.read()
        if item not in source['items'] or item['spec']['kind']!='file':
            raise Conflict('original activation file descriptor required')
        if item['spec']['path']==UNIT:
            if creator!=self.lineage.reference['id']:
                raise Conflict('original revised activation file creator required')
            if self.completed_exchange is None:
                proof=self.adapter.observe_revised_file(item,creator,self.lineage.reference)
            else:
                if item['spec']!=self.lineage.reference['plan']['target_spec'] or item['nonce']!=self.lineage.reference['nonce']:
                    raise Conflict('original revised activation descriptor differs')
                proof=self.completed_exchange.observe()['replacement']
        else:
            if creator!=source['id']:raise Conflict('original persistent activation file creator required')
            proof=self.lineage.view.files.observe(deepcopy(item),creator)
        if proof!=item['proof']:raise Conflict('original activation file birth differs')
        if self.lineage.read()!=source:raise Conflict('activation file lineage changed during observation')
        return deepcopy(proof)
