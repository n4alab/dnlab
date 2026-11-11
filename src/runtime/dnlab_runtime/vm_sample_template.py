"""Explicit candidate hardware for the first two direct-VM samples.

This translates reviewed V2 source facts, without running launcher code or
claiming guest qualification. Machine, root PCI placement, resources and NIC
count are mandatory inputs: the launcher's automatic root placement is not
guessed. A candidate must pass host and guest gates before runtime admission.
"""
from copy import deepcopy
import math

from .vm_template import fields, require, validate_template


def sample_template(kind, *, source, base, machine, resources, nic_count, placement, firmware=None):
    require(kind in ('n9kv-9500-v2', 'vios-l2-v2'), 'unsupported initial VM sample')
    fields(source, ('repository', 'branch', 'commit'), 'sample source revision')
    fields(resources, ('memory_mib', 'vcpus', 'cpu'), 'sample resources')
    fields(placement, ('bridges', 'first_nic', 'disk'), 'explicit sample root PCI placement')
    n9kv = kind == 'n9kv-9500-v2'
    capacity = 129 if n9kv else 15
    require(type(nic_count) is int and 2 <= nic_count <= capacity + 1,
            'explicit sample NIC count outside source capacity')
    bridges = placement['bridges']
    require(type(bridges) is list and len(bridges) == math.ceil(capacity / 26),
            'complete source PCI bridge inventory required')
    require(all(type(address) is dict and address.get('bus') == 0
                for address in [*bridges, placement['first_nic'], placement['disk']]),
            'sample root PCI addresses must be explicit on bus zero')
    require(type(base) is dict and base.get('format') == 'qcow2', 'explicit qcow2 sample base required')
    assets = {'base': deepcopy(base)}
    controllers = [dict(type='pci', index=0, model='pci-root')]
    controllers.extend(dict(type='pci', index=index, model='pci-bridge', address=deepcopy(address))
                       for index, address in enumerate(bridges, 1))
    if n9kv:
        require(type(firmware) is dict and firmware.get('format') == 'raw',
                'explicit n9kv V2 firmware asset required')
        assets['firmware'] = deepcopy(firmware)
        loader = dict(mode='rom', asset='firmware')
        controllers.append(dict(type='sata', index=0, address=deepcopy(placement['disk'])))
        disk = dict(id='boot', asset='base', bus='sata', target='sda',
                    address=dict(controller=0, bus=0, target=0, unit=0))
    else:
        require(firmware is None, 'vIOS sample has no source firmware override')
        loader = dict(mode='bios')
        disk = dict(id='boot', asset='base', bus='virtio', target='vda', address=deepcopy(placement['disk']))
    nics = []
    for index in range(nic_count):
        address = (deepcopy(placement['first_nic']) if index == 0 else
                   dict(bus=index // 26 + 1, slot=index % 26 + 1, function=0))
        guest = ('mgmt0' if index == 0 else f'Ethernet1/{index}') if n9kv else f'GigabitEthernet0/{index}'
        nics.append(dict(id=f'p{index:02d}', model='e1000', guest_name=guest,
                         role='oob' if n9kv and index == 0 else 'data', address=address))
    hardware = dict(arch='x86_64', machine=machine, **deepcopy(resources), firmware=loader,
                    controllers=controllers, disks=[disk], nics=nics)
    launcher = 'cisco/n9kv_V2/docker/launch.py' if n9kv else 'cisco/vios_V2/docker/launch.py'
    candidate = dict(schema_version=1, id='cisco-' + kind,
                     source=dict(deepcopy(source), launcher=launcher), assets=assets, hardware=hardware,
                     management=dict(mode='oob' if n9kv else 'selected-data',
                                     eligible_ports=['p00'] if n9kv else [nic['id'] for nic in nics]),
                     profiles=dict(bootstrap='manual', readiness='manual', shutdown='unqualified'))
    return validate_template(candidate)
