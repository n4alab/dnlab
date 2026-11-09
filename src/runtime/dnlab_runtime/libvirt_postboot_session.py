"""Compose qualified post-boot metadata and directory recovery.

All host observers/filesystem adapters are injected. Construction reads the
original source binding and initializes journal schema, without observing live
resources. Prepare writes only journal metadata; apply/recovery require the
original prepared reference and cannot create accounts, change units or start
a daemon.
"""
from copy import deepcopy

from .libvirt_current_session import CurrentSessionView
from .libvirt_package_policy import INSTALLED_PACKAGES
from .libvirt_postboot import PostBootQualification,context,plan
from .libvirt_run_parent import validate_run_parent
from .libvirt_volatile_recovery import VolatileDirectories
from .manifest import Conflict,fingerprint,identifier


class PostBootRecoverySession:
    def __init__(self,journal,installation,current,*,qualification_id,recovery_id,run_parent,
                 source_reader,observer,account_history,files,window,journal_identity,prepare_only=False):
        identifier(qualification_id,'post-boot qualification_id');identifier(recovery_id,'post-boot recovery_id')
        self.journal,self.original,self.context=journal,deepcopy(installation),context(current)
        self.qualification_id,self.recovery_id=qualification_id,recovery_id
        self.source_reader,self.window,self.journal_identity=source_reader,window,journal_identity
        if not all(callable(fn) for fn in (source_reader,observer,account_history)):
            raise Conflict('explicit post-boot session observers required')
        if (type(prepare_only) is not bool or files.journal is not journal
                or getattr(files,'readonly',False) is not prepare_only
                or len({installation['id'],qualification_id,recovery_id})!=3):
            raise Conflict('original journal, explicit filesystem capability and separate post-boot operations required')
        self.prepare_only=prepare_only
        self.layout=plan(self.original,self.context)
        self.parent=validate_run_parent(run_parent,self.original,self.context)
        self.window_sha256=window.sha256
        self._source()

        def observe(value):
            self._source();result=observer(deepcopy(value));self._source()
            return result

        def history(item):
            self._source();result=account_history(deepcopy(item));self._source()
            return result

        self.qualification=PostBootQualification(journal,source_reader=source_reader,
            observer=observe,account_history=history)
        self.recovery=VolatileDirectories(self.qualification,files,window=window)

    def _source(self):
        if (self.journal.identity!=self.journal_identity
                or self.source_reader(self.original['id'])!=self.original):
            raise Conflict('original post-boot session journal/source changed')
        if (self.window.sha256!=self.window_sha256
                or self.window.receipt['operation_id']!=self.recovery_id
                or self.window.receipt['context']!=self.context
                or set(self.window.receipt['targets'])!=set(self.layout['volatile'])):
            raise Conflict('separate current-boot directory window required')

    def prepare(self):
        with self.journal.execution_lock:
            self._source()
            value=self.qualification.prepare(self.qualification_id,self.original,self.context,
                package_policy=INSTALLED_PACKAGES,run_parent=self.parent)
            if value['phase']=='prepared':self.qualification.qualify_persistent(value['id'])
            else:self.qualification.observe_persistent(value['id'])
            qualified=self.qualification.read(value['id'])
            prepared=self.recovery.prepare(self.recovery_id,value['id'])
            if prepared['phase']!='prepared':
                raise Conflict('post-boot recovery already started; original prepared reference required')
            self._source()
            return dict(kind='postboot-recovery-reference-v1',journal_identity=self.journal_identity,
                source_sha256=fingerprint(self.original),context=deepcopy(self.context),
                qualification_id=self.qualification_id,qualification_sha256=fingerprint(qualified),
                recovery=deepcopy(prepared))

    def _binding(self,reference):
        self._source()
        fields={'kind','journal_identity','source_sha256','context','qualification_id','qualification_sha256','recovery'}
        if (not isinstance(reference,dict) or set(reference)!=fields
                or reference['kind']!='postboot-recovery-reference-v1'
                or reference['journal_identity']!=self.journal_identity
                or reference['source_sha256']!=fingerprint(self.original) or reference['context']!=self.context
                or reference['qualification_id']!=self.qualification_id):
            raise Conflict('original prepared post-boot reference required')
        qualified=self.qualification.read(self.qualification_id)
        if (qualified['phase']!='persistent_qualified' or fingerprint(qualified)!=reference['qualification_sha256']
                or qualified.get('package_policy')!=INSTALLED_PACKAGES or qualified.get('run_parent')!=self.parent):
            raise Conflict('original post-boot qualification binding differs')
        prepared=reference['recovery'];current=self.recovery.read(self.recovery_id)
        keys={'id','qualification_id','qualification_sha256','context','window_sha256','items','phase'}
        if (not isinstance(prepared,dict) or set(prepared)!=keys or prepared['phase']!='prepared'
                or any(current[key]!=prepared[key] for key in keys-{'items','phase'})
                or not isinstance(prepared['items'],list) or len(prepared['items'])!=len(current['items'])):
            raise Conflict('original prepared directory recovery binding differs')
        for original,item in zip(prepared['items'],current['items']):
            if (not isinstance(original,dict) or set(original)!={'spec','nonce','phase','proof'}
                    or original['phase']!='prepared' or original['proof'] is not None
                    or original['spec']!=item['spec'] or original['nonce']!=item['nonce']):
                raise Conflict('original prepared directory birth binding differs')
        return current

    def apply_original(self,reference):
        if self.prepare_only:raise Conflict('metadata-only post-boot session cannot apply directories')
        with self.journal.execution_lock:
            self._binding(reference)
            return self.recovery.apply(self.recovery_id)

    def recover_original(self,reference):
        if self.prepare_only:raise Conflict('metadata-only post-boot session cannot recover directories')
        with self.journal.execution_lock:
            self._binding(reference)
            return self.recovery.recover(self.recovery_id)

    def effective(self,reference):
        with self.journal.execution_lock:
            self._binding(reference)
            observed=self.recovery.observe(self.recovery_id)
            self._source()
            return dict(scope='session-directories-only',daemon_ready=False,
                observation=observed,source=CurrentSessionView(self.recovery,self.recovery_id).read())
