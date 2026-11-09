"""Wire existing readonly observers to a metadata-only post-boot session.

Construction does not query NSS, systemd or resources. The original journal must
already have been qualified/opened by the caller. Query/NSS transports, current
context and administrative window are explicit. No account-command adapter,
directory creator, service mutation or libvirt connection is supplied.
"""
from copy import deepcopy

from dnlab_runtime.libvirt_account_history import HistoricalAccountCreation
from dnlab_runtime.libvirt_account_identity import LocalAccountIdentity
from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.libvirt_install_dependencies import InstallationDirectoryDependencies
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_postboot_session import PostBootRecoverySession
from dnlab_runtime.manifest import Conflict
from tools.libvirt_install_activity import InstallationActivity
from tools.libvirt_install_snapshot import InstallationSnapshot
from tools.libvirt_postboot_observer import PostBootObserver


class PostBootPrepareAssembly:
    def __init__(self,journal,installation,current,*,qualification_id,recovery_id,run_parent,
                 window,expected_packages,approved_account_inputs,worker_profile,query,nss_query,root='/'):
        self.source=SessionInstaller(journal,None,readonly=True)
        if self.source.read(installation['id'])!=installation:
            raise Conflict('original prepare assembly installation differs')
        self.files=InstallationFiles(root,journal=journal,readonly=True)
        self.identity=LocalAccountIdentity(root,nss_query=nss_query)
        dependencies=[deepcopy(item['spec']) for item in installation['items'] if item['phase']=='dependency']
        self.dependencies=InstallationDirectoryDependencies(root,dependencies) if dependencies else None
        def directory(spec):
            if self.dependencies is None:raise Conflict('no original directory dependency selected')
            return self.dependencies(spec)
        binaries={role:dict(path='/usr/sbin/'+role,
            sha256=installation['prerequisites']['account_inputs']['usr/sbin/'+role]['sha256'])
            for role in ('groupadd','useradd')}
        self.history=HistoricalAccountCreation(journal,installation=installation,worker_profile=worker_profile,
            binaries=binaries,source_reader=self.source.read)
        self.activity=InstallationActivity(installation['profile'],query=query)
        self.snapshot=InstallationSnapshot(root,installation['request'],expected_packages,approved_account_inputs,
            namespaces=self.activity.namespaces,services=self.activity)
        self.observer=PostBootObserver(root,installation,current,source_reader=self.source.read,
            snapshot=self.snapshot,identity=self.identity,files=self.files,directory_dependency=directory)
        self.session=PostBootRecoverySession(journal,installation,current,
            qualification_id=qualification_id,recovery_id=recovery_id,run_parent=run_parent,
            source_reader=self.source.read,observer=self.observer,account_history=self.history,
            files=self.files,window=window,journal_identity=journal.identity,prepare_only=True)

    @property
    def diagnostics(self):
        return dict(observer=deepcopy(self.observer.diagnostics),activity=deepcopy(self.activity.diagnostics))
