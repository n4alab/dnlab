"""Read-only ordinary-shutdown proof for an already held original pidfd.

No shutdown request, timeout, signal, restart or cleanup is performed. The
lifecycle operation must persist its original intent/witness before the guest
action and retain this receipt before changing disk or endpoint ownership.
"""
from copy import deepcopy

from .manifest import fingerprint
from .vm_template import require


class VMShutdownObservation:
    def __init__(self, boot):
        self.boot, self.definitions = boot, boot.definitions

    @staticmethod
    def _ordinary_state(domain):
        state = domain.state(0)
        return (type(state) in (tuple,list) and len(state) == 2
                and all(type(item) is int for item in state) and tuple(state) == (5,1))

    def __call__(self, original, witness):
        operation = original['birth']['creator_operation_id']
        with self.definitions.journal.execution_lock:
            require(self.definitions.read(operation) == original
                    and self.boot._boot(original)['phase'] == 'running',
                    'original persisted running generation required for shutdown observation')
            self.definitions._session(original)
            reference = witness.reference()
            require(reference['birth'] == original['birth']
                    and reference['process_record_sha256'] == fingerprint(original['boot']['process_record']),
                    'shutdown witness differs from original QEMU')
            exited = witness.exited()
            if exited is None:
                self.boot._observer(original)(original['birth'])
                return None
            require(exited == dict(reference=reference, process=original['boot']['process_record']['process'], exited=True),
                    'original QEMU exit proof differs')
            domain = self.definitions.connection.lookupByUUIDString(original['birth']['uuid'])
            # VIR_DOMAIN_SHUTOFF / VIR_DOMAIN_SHUTOFF_SHUTDOWN. Destroy,
            # crash, failed boot and unknown reasons are not ordinary exit.
            require(self._ordinary_state(domain) and self.definitions._ack(original,domain) == original['ack'],
                    'original domain did not complete ordinary guest shutdown')
            self.definitions._session(original)
            require(witness.exited() == exited and self.definitions.read(operation) == original
                    and self._ordinary_state(domain) and self.definitions._ack(original,domain) == original['ack'],
                    'original shutdown changed during observation')
            return dict(kind='ordinary-qemu-shutdown-v1', birth=deepcopy(original['birth']),
                        definition_sha256=original['request_fingerprint'], exit=exited,
                        inactive_ack=deepcopy(original['ack']), reason='guest-shutdown')
