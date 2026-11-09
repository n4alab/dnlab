"""Directory-only post-boot assembly using an original prepared reference.

Observers remain readonly. The separate mutator permits only the exact two
prepared directory specs/nonces and recovery ID validated by the session.
Construction never prepares a replacement operation or creates a directory.
No account commands, unit changes, service actions or libvirt connection exist.
"""
from copy import deepcopy

from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_postboot_session import PostBootRecoverySession
from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_assembly import PostBootPrepareAssembly


class PreparedDirectoryFiles(InstallationFiles):
    def __init__(self,root,*,journal,reference):
        self.reference=deepcopy(reference)
        items=self.reference['recovery']['items']
        if (len(items)!=2 or any(item['spec']['kind']!='directory'
                or not item['spec']['path'].startswith('/run/') for item in items)):
            raise Conflict('two original runtime directory intents required')
        super().__init__(root,journal=journal)

    def _allowed(self,item,operation):
        if (operation!=self.reference['recovery']['id'] or not isinstance(item,dict)
                or set(item)!={'spec','nonce','phase','proof'} or item['phase']!='create_requested'
                or item['proof'] is not None or not any(original['spec']==item['spec']
                    and original['nonce']==item['nonce'] for original in self.reference['recovery']['items'])):
            raise Conflict('original prepared directory mutation binding differs')

    def create(self,item,operation_id,*,window=None,run_parent=None):
        self._allowed(item,operation_id)
        return super().create(item,operation_id,window=window,run_parent=run_parent)

    def recover(self,item,operation_id,*,window=None):
        self._allowed(item,operation_id)
        return super().recover(item,operation_id,window=window)


class PostBootDirectoryAssembly:
    def __init__(self,journal,installation,current,*,prepared_reference,qualification_id,recovery_id,
                 run_parent,window,expected_packages,approved_account_inputs,worker_profile,query,nss_query,root='/'):
        self.readonly=PostBootPrepareAssembly(journal,installation,current,
            qualification_id=qualification_id,recovery_id=recovery_id,run_parent=run_parent,window=window,
            expected_packages=expected_packages,approved_account_inputs=approved_account_inputs,
            worker_profile=worker_profile,query=query,nss_query=nss_query,root=root)
        self.reference=deepcopy(prepared_reference)
        self.readonly.session._binding(self.reference)
        self.files=PreparedDirectoryFiles(root,journal=journal,reference=self.reference)
        self.session=PostBootRecoverySession(journal,installation,current,
            qualification_id=qualification_id,recovery_id=recovery_id,run_parent=run_parent,
            source_reader=self.readonly.source.read,observer=self.readonly.observer,
            account_history=self.readonly.history,files=self.files,window=window,journal_identity=journal.identity)
        self.session._binding(self.reference)

    def apply_original(self):return self.session.apply_original(self.reference)
    def recover_original(self):return self.session.recover_original(self.reference)
    def effective(self):return self.session.effective(self.reference)

    @property
    def diagnostics(self):return self.readonly.diagnostics
