"""Bind native activation providers to the completed current-boot lineage."""

from contextlib import contextmanager
import os

from dnlab_runtime.libvirt_activation_controller import resource_digest
from dnlab_runtime.libvirt_activation_exchange import CompletedExchangeFiles
from dnlab_runtime.libvirt_activation_lineage import ActivationFiles
from dnlab_runtime.libvirt_activation_resources import observe_activation_targets
from dnlab_runtime.libvirt_account_identity import LocalAccountIdentity
from dnlab_runtime.libvirt_current_session import CurrentAccountObserver
from dnlab_runtime.libvirt_install_dependencies import InstallationDirectoryDependencies
from dnlab_runtime.libvirt_package_policy import prerequisites_for_policy
from dnlab_runtime.manifest import Conflict, fingerprint
from tools.libvirt_install_activity import InstallationActivity
from tools.libvirt_install_snapshot import InstallationSnapshot
from tools.libvirt_native_activation import open_native_activation


class ActivationHostInputs:
    def __init__(self, lineage, *, swap, expected_packages, approved_account_inputs, query, nss_query):
        self.lineage = lineage
        self.source = lineage.read()
        self.root = lineage.view.files.root
        if swap.journal is not lineage.view.journal:
            raise Conflict('one original activation and exchange journal required')
        self.exchange = CompletedExchangeFiles(swap, lineage.reference)
        self.files = ActivationFiles(lineage, swap.files, revision_window=swap.window,
                                     completed_exchange=self.exchange)
        self.inventory = InstallationActivity(self.source['profile'], query=query)
        self.snapshot = InstallationSnapshot(
            self.root, self.source['request'], expected_packages, approved_account_inputs,
            namespaces=self.inventory.namespaces, services=self.inventory)
        self.accounts = CurrentAccountObserver(lineage.view, LocalAccountIdentity(self.root, nss_query=nss_query))
        specs = [item['spec'] for item in self.source['items'] if item['phase'] == 'dependency']
        self.dependencies = InstallationDirectoryDependencies(self.root, specs) if specs else None
        self.policy = self.source['postboot'].get('package_policy')
        self.expected = prerequisites_for_policy(self.source['prerequisites'], self.policy)
        self.expected.pop('services', None)

    def directory_dependency(self, spec):
        if self.dependencies is None:
            raise Conflict('no original activation directory dependency selected')
        return self.dependencies(spec)

    def resources(self, value, receipts):
        """Verify static resources inside the controller's live service census."""
        source = self.source
        if value['installation'] != source or self.lineage.read() != source:
            raise Conflict('original activation host lineage differs')

        def static():
            snapshot = self.snapshot.observe_static()
            return (snapshot['context'], prerequisites_for_policy(snapshot['prerequisites'], self.policy))

        expected = (source['context'], self.expected)
        if static() != expected:
            raise Conflict('original activation host prerequisites differ')
        targets = observe_activation_targets(self.lineage, self.accounts, self.directory_dependency)
        exchange = self.exchange.observe()
        if (observe_activation_targets(self.lineage, self.accounts, self.directory_dependency) != targets
                or static() != expected or self.exchange.observe() != exchange or self.lineage.read() != source):
            raise Conflict('activation host resources changed during observation')
        return dict(qualified=True, installation_sha256=fingerprint(source),
                    context_sha256=fingerprint(source['context']), resources_sha256=resource_digest(source))


@contextmanager
def open_lineage_activation(inputs, *, unit_query, **activation):
    """Use the original journal and readonly providers with one native supervisor."""
    root = os.open(inputs.root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        with open_native_activation(
                inputs.lineage.view.journal, inputs.source, root=root, source_reader=inputs.lineage.read,
                resources=inputs.resources, inventory=inputs.inventory, files=inputs.files,
                unit_query=unit_query, **activation) as session:
            yield session
    finally:
        os.close(root)
