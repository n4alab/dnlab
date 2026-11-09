"""Pure service provisioning intent bound before the offline fence is acquired.

Addresses, published ports, credentials and resolved helper images are supplied
by the existing coordinator. This compiler allocates nothing and does not infer
DNS data by reading Containerlab-generated files.
"""
from copy import deepcopy
import ipaddress
import re

from .management_segments import resolve,SegmentError
from .management_services import compile_services
from .management_dhcp import compile_dhcp
from .jumphost_host import validate as validate_jumphost,JumphostError
from .dns_host import validate as validate_dns
from .mgmt_network import _expected_network
from .hostsfile import HostEntry,render_hosts_file
from .runtime_operations import digest
from ..utils.naming import micro_vd_container_name


def compile_service_intent(topo,model,configs,*,extra_dns_entries=()):
    """Validate exact materialization inputs against the original resolved lab."""
    try:
        topo,checked=resolve(topo,model)
        if checked!=model or set(configs)!={'jumphost','dns'}:
            raise SegmentError('complete original management service inputs required')
        configs=deepcopy(configs)
        jump=validate_jumphost(configs['jumphost']);dns=validate_dns(configs['dns'])
        external={('network' if key=='name' else key):value for key,value in jump['network'].items()}
        services=compile_services(model,external)
        if (jump['lab']!=topo.name or dns['lab']!=topo.name
                or jump['name']!=services['jumphost']['container_name']
                or dns['name']!=services['dns']['container_name']
                or dns['network']!=jump['network']
                or jump['attachment']!=services['jumphost']['attachments']['default']['config']
                or jump.get('management_intent')!=_expected_network(topo,'master')
                or jump['env'].get('JUMPHOST_LAB_NAME')!=topo.name
                or not jump['env'].get('JUMPHOST_PASSWORD')
                or jump['dns']!=[dns['ip']]):
            raise SegmentError('service configuration differs from resolved management')
        for config in (jump,dns):
            if not re.fullmatch('sha256:[0-9a-f]{64}',config['image']):
                raise SegmentError('resolved immutable management helper image required')
        subnet=ipaddress.IPv4Network(external['subnet'])
        addresses=[ipaddress.IPv4Address(jump['ip']),ipaddress.IPv4Address(dns['ip'])]
        if (addresses[0]==addresses[1]
                or any(value not in subnet or value in (subnet.network_address,subnet.broadcast_address,
                    ipaddress.IPv4Address(external['gateway'])) for value in addresses)
                or any(str(value) in dns['upstream'] for value in addresses)):
            raise SegmentError('management service external addresses conflict')
        dhcp=compile_dhcp(topo,model,services,dns['ip'])
        if jump['dhcp']!=dhcp:
            raise SegmentError('DHCP config differs from original management intent')
        # Publish both the VD's logical name and its existing native container
        # name; reject contradictory aliases before touching any service.
        entries=[];aliases={}
        def add(entry):
            if (not isinstance(entry,HostEntry) or not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,252}',entry.name)
                    or entry.family not in ('A','AAAA')
                    or ipaddress.ip_address(entry.ip).version != (4 if entry.family=='A' else 6)):
                raise SegmentError('invalid management DNS entry')
            key=(entry.name.lower(),entry.family)
            if key in aliases and aliases[key]!=entry.ip:
                raise SegmentError('management DNS alias conflicts with resolved VD')
            if key not in aliases:aliases[key]=entry.ip;entries.append(entry)
        for name,node in sorted(topo.nodes.items()):
            for alias in dict.fromkeys((name,micro_vd_container_name(topo.name,name))):
                add(HostEntry(alias,node.mgmt_ipv4,'A'))
                if node.mgmt_ipv6:add(HostEntry(alias,node.mgmt_ipv6,'AAAA'))
        for entry in extra_dns_entries:add(entry)
        # A service-owned record permits a real query before any VD exists.
        # It is part of the original hosts asset, never injected at probe time.
        health='dnlab-health-'+digest(topo.name)[:20]+'.invalid'
        add(HostEntry(health,dns['ip'],'A'))
        probe=[{'name':health,'address':dns['ip']}]
        ipv6=next((entry for entry in entries if entry.family=='AAAA'),None)
        if ipv6:probe.append({'name':ipv6.name,'address':ipv6.ip})
        attachments={}
        for segment,row in services['jumphost']['attachments'].items():
            selected=deepcopy(topo);selected.mgmt=selected.management_networks[segment]
            attachments[segment]={'attachment':deepcopy(row['config']),
                'management_intent':_expected_network(selected,'master')}
        result={'schema_version':1,'lab':topo.name,'host':'master','management_plan':deepcopy(model),
            'services':services,'jumphost':jump,'dns':{'config':dns,'content':render_hosts_file(entries)},
            'attachments':attachments,'dns_probe':{'server':dns['ip'],'records':probe}}
        if 'probes' in model:result['packet_probe_identities']=deepcopy(model['probes'])
        result['fingerprint']=digest(result)
        return result
    except SegmentError:
        raise
    except (KeyError,TypeError,ValueError,AttributeError,JumphostError):
        raise SegmentError('invalid management service provisioning input') from None
