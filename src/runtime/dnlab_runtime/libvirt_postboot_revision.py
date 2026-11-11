"""Observe the completed configuration revision across a boot boundary."""

from copy import deepcopy

from .libvirt_activation_exchange import CompletedExchangeFiles
from .libvirt_configuration import project_revision
from .manifest import Conflict, fingerprint


class PostBootRevision:
    def __init__(self, revision, swap, reference):
        if revision.journal is not swap.journal:
            raise Conflict('one original post-boot revision journal required')
        self.revision = revision
        self.exchange = CompletedExchangeFiles(swap, reference)
        self.reference = deepcopy(reference)
        # Only the immutable projection is reusable. Journal state, retirement
        # and observations of installed resources must still be checked live.
        self._projected = project_revision(self.reference)
        self._binding = dict(id=self.reference['id'], sha256=fingerprint(self.reference))

    def source_and_binding(self, installation, current):
        reference = self.revision.read(self.reference['id'])
        self.revision._active(reference)
        if reference != self.reference or fingerprint(reference) != self._binding['sha256']:
            raise Conflict('original completed unit revision changed')
        source = deepcopy(self._projected)
        if (source['context']['host_id'] != current['host_id']
                or source['context']['boot_id'] == current['boot_id']
                or source.get('postboot', {}).get('source_sha256') != fingerprint(installation)):
            raise Conflict('original completed revision and a later boot required')
        return source, deepcopy(self._binding)

    def source(self, installation, current):
        return self.source_and_binding(installation, current)[0]

    def binding(self, installation, current):
        return self.source_and_binding(installation, current)[1]

    def observe(self, installation, current):
        source = self.source(installation, current)
        receipt = self.exchange.observe()
        if self.source(installation, current) != source:
            raise Conflict('completed revision changed during post-boot observation')
        return receipt
