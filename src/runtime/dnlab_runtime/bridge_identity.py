"""Local bridge identity shared with multinode's complete-lab naming contract."""
from dataclasses import dataclass
import hashlib
import json

from .manifest import Conflict, identifier


@dataclass(frozen=True)
class BridgeIdentity:
    lab_id: str
    link_id: str

    def __post_init__(self):
        identifier(self.lab_id,'lab_id')
        identifier(self.link_id,'link_id')

    @property
    def digest(self):
        payload=json.dumps(['local-bridge',self.lab_id,self.link_id],ensure_ascii=True,separators=(',',':'))
        return hashlib.sha256(payload.encode()).hexdigest()

    @property
    def kernel_name(self):
        return 'br-rt-'+self.digest[:9]

    @property
    def alias(self):
        return 'dnlab-runtime:bridge:'+self.digest

    @property
    def mac(self):
        data=bytearray(bytes.fromhex(self.digest[:12]))
        data[0]=(data[0]&0xfc)|2
        return ':'.join(f'{byte:02x}' for byte in data)

    def resolve(self,links,*,expected_index=None):
        candidates=[value for value in links if value.get('ifname')==self.kernel_name or value.get('ifalias')==self.alias]
        if not candidates:return None
        if len(candidates)!=1:raise Conflict('ambiguous local bridge ownership')
        value=candidates[0]
        if (value.get('ifname')!=self.kernel_name or value.get('ifalias')!=self.alias
                or value.get('address')!=self.mac
                or value.get('linkinfo',{}).get('info_kind')!='bridge'
                or type(value.get('ifindex')) is not int
                or expected_index is not None and value['ifindex']!=expected_index):
            raise Conflict('local bridge ownership or identity mismatch')
        return value
