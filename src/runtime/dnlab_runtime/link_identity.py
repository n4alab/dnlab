"""VXLAN identity: short kernel name, full endpoint altname and ownership token.

This is an isolated primitive contract, not a distributed topology registry.
An altname lookup alone does not authorize adoption or deletion.
"""
from dataclasses import dataclass
import hashlib

from .manifest import Conflict, identifier


@dataclass(frozen=True)
class VxlanIdentity:
    lab_id: str
    link_id: str
    host_endpoint: str
    vni: int

    def __post_init__(self):
        for field in ('lab_id', 'link_id', 'host_endpoint'):
            identifier(getattr(self, field), field)
        if type(self.vni) is not int or not 1 <= self.vni <= 16777215:
            raise Conflict('invalid VXLAN VNI')

    @property
    def digest(self):
        # Field boundaries are explicit; topology names cannot contain NUL.
        value = '\0'.join(('vxlan-v1', self.lab_id, self.link_id, self.host_endpoint))
        return hashlib.sha256(value.encode()).hexdigest()

    @property
    def kernel_name(self):
        return 'drvx-' + self.digest[:10]

    @property
    def altname(self):
        return 'vx-' + self.host_endpoint

    @property
    def ownership(self):
        return 'dnr-o-' + self.digest[:32]

    def resolve(self, links: list[dict], *, expected_index: int | None = None):
        candidates = [link for link in links if link.get('ifname') == self.kernel_name
                      or self.altname in link.get('altnames', [])
                      or self.ownership in link.get('altnames', [])]
        if not candidates:
            return None
        if len(candidates) != 1:
            raise Conflict('ambiguous VXLAN resource identity')
        link = candidates[0]
        info = link.get('linkinfo', {})
        names = link.get('altnames', [])
        if (link.get('ifname') != self.kernel_name or self.altname not in names
                or self.ownership not in names or info.get('info_kind') != 'vxlan'
                or info.get('info_data', {}).get('id') != self.vni
                or type(link.get('ifindex')) is not int
                or (expected_index is not None and link['ifindex'] != expected_index)):
            raise Conflict('VXLAN ownership or kernel identity mismatch')
        return link
