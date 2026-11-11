"""Reopen the exact completed revision and exchange through readonly adapters."""

from dnlab_runtime.libvirt_configuration import ConfigurationRevision, project_revision
from dnlab_runtime.libvirt_configuration_staging import ConfigurationStaging
from dnlab_runtime.libvirt_configuration_swap import ConfigurationSwap
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_postboot_revision import PostBootRevision
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict


def completed_revision_input(journal, binding, installation, context, *, root='/'):
    if not isinstance(binding, dict) or set(binding) != {'source', 'window'}:
        raise Conflict('explicit completed revision recipe input required')
    window = ProvisioningWindow(binding['window'], lambda: None)
    revision = ConfigurationRevision(journal, None, window=window, readonly=True)
    reference = revision.read(window.receipt['operation_id'])
    if project_revision(reference) != binding['source']:
        raise Conflict('original completed revision recipe source differs')
    files = InstallationFiles(root, journal=journal, readonly=True)
    stage = ConfigurationStaging(journal, files, window=window, readonly=True)
    swap = ConfigurationSwap(stage, readonly=True)
    completed = PostBootRevision(revision, swap, reference)
    completed.source(installation, context)
    return completed
