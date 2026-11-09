"""Typed resource references; ownership still requires the original birth proof.

Names are never resource identities. This representation does not discover or
adopt resources, and does not enable the VM backend in the request validator.
"""
from dataclasses import dataclass
from uuid import UUID

from .manifest import RuntimeErrorBase


@dataclass(frozen=True)
class WorkloadReference:
    backend: str
    kind: str
    resource_id: str

    def __post_init__(self):
        if (self.backend, self.kind) not in {('docker', 'container'), ('libvirt', 'vm')}:
            raise RuntimeErrorBase('unsupported workload backend and kind')
        if (not isinstance(self.resource_id, str) or not self.resource_id
                or len(self.resource_id) > 128 or any(c.isspace() or ord(c) < 32 for c in self.resource_id)):
            raise RuntimeErrorBase('nonempty immutable workload resource ID required')
        if self.backend == 'libvirt':
            try:
                valid = str(UUID(self.resource_id)) == self.resource_id
            except ValueError:
                valid = False
            if not valid:
                raise RuntimeErrorBase('canonical libvirt domain UUID required')

    def public(self):
        return {'backend': self.backend, 'kind': self.kind, 'id': self.resource_id}


def container_reference(container):
    """Project an already-qualified container; never look it up by name."""
    if container is None:
        return None
    return WorkloadReference('docker', 'container', container['Id']).public()
