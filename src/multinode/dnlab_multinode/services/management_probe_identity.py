"""Pure infrastructure reservations for pre-VD management qualification.

The IPv4 anchor reservation changes role only in the opt-in custom model. Probe
identities never appear as topology nodes and are not borrowed from a VD.
"""
from copy import deepcopy
import hashlib
import ipaddress

from .config import ConfigError
from .mgmt_ips import ipv4_reservations


def owner(segment):
    return '@management-probe:'+segment


def identity(lab,segment,config):
    def seed(purpose):return hashlib.sha256(('management-readiness-v1\0'+lab+'\0'+segment+'\0'+purpose).encode()).digest()
    mac=bytes([2])+seed('mac')[:5]
    ipv6=''
    if config['ipv6_subnet']:
        network=ipaddress.IPv6Network(config['ipv6_subnet']);gateway=ipaddress.IPv6Address(config['ipv6_gw'])
        selected=network.broadcast_address
        if selected==gateway:selected-=1
        if selected<=network.network_address:raise ConfigError('management IPv6 has no space for infrastructure probe')
        ipv6=str(selected)
    return {'owner':owner(segment),'ipv4':ipv4_reservations(config['ipv4_subnet']).anchor,'ipv6':ipv6,
        'mac':':'.join(f'{v:02x}' for v in mac),'duid':'00:04:'+':'.join(f'{v:02x}' for v in seed('duid')[:16]),
        'iaid':seed('iaid')[:4].hex()}


def duid_key(value):
    try:return bytes.fromhex(value.replace(':','')).hex()
    except (ValueError,AttributeError):return value


def reserve(lab,networks,ledgers,previous):
    """Return a staged ledger and probes; reject collisions without moving VDs."""
    probes={segment:identity(lab,segment,config) for segment,config in sorted(networks.items())}
    if not isinstance(previous,dict) or any(probes.get(key)!=row for key,row in previous.items()):
        raise ConfigError('original infrastructure probe identity changed')
    staged=deepcopy(ledgers)
    for segment,row in probes.items():
        key=row['owner']
        claims=[('mac',staged['mac'],row['mac']),('duid',staged['duid'],row['duid']),('iaid',staged['iaid'],row['iaid'])]
        if row['ipv6']:claims.append(('ipv6',staged['ipv6'].setdefault(segment,{}),row['ipv6']))
        for family,values,value in claims:
            normalize=duid_key if family=='duid' else lambda v:v
            if key in values and segment not in previous:
                raise ConfigError('probe reservation exists without original identity intent')
            if key in values and values[key]!=value:raise ConfigError('original probe reservation differs')
            # A probe DUID is dedicated even if another client has a different
            # IAID; dnsmasq reservations currently select clients by DUID.
            if family!='iaid' and any(other!=key and normalize(old)==normalize(value) for other,old in values.items()):
                raise ConfigError('infrastructure probe '+family+' reserved by another owner')
            values[key]=value
    return staged,probes


def validate(model):
    staged,probes=reserve(model['lab'],model['networks'],model['ledgers'],model['probes'])
    if probes!=model['probes'] or staged!=model['ledgers']:
        raise ConfigError('complete original infrastructure probe reservations required')
