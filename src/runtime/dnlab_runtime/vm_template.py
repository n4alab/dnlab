"""Offline single-VM template contract, with no launcher or asset execution.

Validation is structural, not a qualification of the disk, firmware, NOS or
installed hypervisor. The filesystem bundle reader must verify asset hashes.
"""
import json
from pathlib import PurePosixPath
import re

from .manifest import RuntimeErrorBase, canonical, fingerprint, identifier


class TemplateError(RuntimeErrorBase):
    pass


def require(condition, message):
    if not condition:
        raise TemplateError(message)


def fields(value, names, label):
    require(type(value) is dict and set(value) == set(names), 'invalid ' + label + ' fields')


def token(value):
    return isinstance(value, str) and re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', value) is not None


def digest(value):
    return isinstance(value, str) and re.fullmatch(r'[0-9a-f]{64}', value) is not None


def relative(value):
    return (isinstance(value, str) and bool(value) and not PurePosixPath(value).is_absolute()
            and '..' not in PurePosixPath(value).parts and str(PurePosixPath(value)) == value
            and value != '.' and not any(ord(c) < 32 for c in value))


def pci(value):
    fields(value, ('bus', 'slot', 'function'), 'PCI address')
    require(all(type(v) is int for v in value.values()) and 0 <= value['bus'] <= 255
            and 0 <= value['slot'] <= 31 and 0 <= value['function'] <= 7, 'invalid PCI address')
    return tuple(value[k] for k in ('bus', 'slot', 'function'))


def validate_template(raw):
    fields(raw, ('schema_version', 'id', 'source', 'assets', 'hardware', 'management', 'profiles'), 'VM template')
    require(type(raw['schema_version']) is int and raw['schema_version'] == 1, 'unsupported VM template version')
    identifier(raw['id'], 'template.id')
    source = raw['source']
    fields(source, ('repository', 'branch', 'commit', 'launcher'), 'template source')
    require(all(isinstance(source[k], str) and source[k] and not any(ord(c) < 32 for c in source[k])
                for k in ('repository', 'branch'))
            and isinstance(source['commit'], str) and re.fullmatch(r'[0-9a-f]{40}', source['commit'])
            and relative(source['launcher']), 'pinned template source required')
    assets = raw['assets']
    require(type(assets) is dict and 1 <= len(assets) <= 64, 'bounded template assets required')
    paths = set()
    for key, asset in assets.items():
        require(token(key), 'invalid template asset ID')
        fields(asset, ('path', 'sha256', 'size', 'format'), 'asset')
        require(relative(asset['path']) and asset['path'] not in paths and digest(asset['sha256'])
                and type(asset['size']) is int and asset['size'] > 0
                and asset['format'] in ('qcow2', 'raw'), 'invalid immutable template asset')
        paths.add(asset['path'])
    hardware = raw['hardware']
    fields(hardware, ('arch', 'machine', 'memory_mib', 'vcpus', 'cpu', 'firmware', 'controllers', 'disks', 'nics'), 'hardware')
    require(hardware['arch'] == 'x86_64' and isinstance(hardware['machine'], str)
            and re.fullmatch(r'pc-i440fx-[0-9]+\.[0-9]+(?:\.[0-9]+)?', hardware['machine']) and token(hardware['cpu'])
            and type(hardware['memory_mib']) is int and hardware['memory_mib'] > 0
            and type(hardware['vcpus']) is int and hardware['vcpus'] > 0,
            'pinned i440fx machine and valid VM resources required')
    firmware = hardware['firmware']
    require(type(firmware) is dict and firmware.get('mode') in ('bios', 'rom', 'pflash'), 'invalid firmware mode')
    expected = ('mode',) if firmware['mode'] == 'bios' else ('mode', 'asset') if firmware['mode'] == 'rom' else ('mode', 'asset', 'nvram_template')
    fields(firmware, expected, 'firmware')
    for key in expected:
        if key != 'mode':
            require(isinstance(firmware[key], str) and firmware[key] in assets
                    and assets[firmware[key]]['format'] == 'raw', 'firmware asset missing or not raw')
    controllers = hardware['controllers']
    require(type(controllers) is list and 1 <= len(controllers) <= 256, 'explicit controllers required')
    buses, disk_controllers, occupied = set(), set(), set()
    for controller in controllers:
        require(type(controller) is dict, 'invalid controller')
        kind, index = controller.get('type'), controller.get('index')
        require(type(index) is int and 0 <= index <= 255, 'invalid controller index')
        if kind == 'pci' and index == 0:
            fields(controller, ('type', 'index', 'model'), 'root PCI controller')
            require(not buses and controller['model'] == 'pci-root', 'single PCI root required')
            buses.add(0)
        else:
            names = ('type', 'index', 'model', 'address') if kind == 'pci' else ('type', 'index', 'address')
            fields(controller, names, 'controller')
            require(kind in ('pci', 'sata') and buses, 'unsupported controller')
            address = pci(controller['address'])
            require(address[0] in buses and address not in occupied, 'controller PCI address conflict')
            occupied.add(address)
            if kind == 'pci':
                require(controller['model'] == 'pci-bridge' and index == len(buses), 'contiguous PCI bridges required')
                buses.add(index)
            else:
                require(index not in disk_controllers, 'duplicate SATA controller')
                disk_controllers.add(index)
    disks = hardware['disks']
    require(type(disks) is list and 1 <= len(disks) <= 32, 'explicit VM disks required')
    disk_ids, targets, drive_addresses = set(), set(), set()
    for disk in disks:
        fields(disk, ('id', 'asset', 'bus', 'target', 'address'), 'disk')
        require(token(disk['id']) and disk['id'] not in disk_ids and isinstance(disk['asset'], str) and disk['asset'] in assets
                and disk['bus'] in ('virtio', 'sata', 'ide') and token(disk['target'])
                and disk['target'] not in targets, 'invalid or duplicate disk')
        disk_ids.add(disk['id']); targets.add(disk['target'])
        if disk['bus'] == 'virtio':
            address = pci(disk['address'])
            require(address[0] in buses and address not in occupied, 'disk PCI address conflict')
            occupied.add(address)
        else:
            fields(disk['address'], ('controller', 'bus', 'target', 'unit'), 'drive address')
            address = tuple(disk['address'][k] for k in ('controller', 'bus', 'target', 'unit'))
            require(all(type(v) is int and v >= 0 for v in address)
                    and (disk['bus'], address) not in drive_addresses, 'invalid or duplicate drive address')
            require(disk['bus'] != 'sata' or address[0] in disk_controllers, 'missing SATA controller')
            drive_addresses.add((disk['bus'], address))
    nics = hardware['nics']
    require(type(nics) is list and 1 <= len(nics) <= 256, 'explicit guest NICs required')
    nic_ids, guest_names, oob = set(), set(), set()
    for nic in nics:
        fields(nic, ('id', 'model', 'guest_name', 'role', 'address'), 'NIC')
        require(token(nic['id']) and nic['id'] not in nic_ids and token(nic['model'])
                and isinstance(nic['guest_name'], str) and nic['guest_name'] and nic['guest_name'] not in guest_names
                and nic['role'] in ('oob', 'data'), 'invalid or duplicate NIC')
        address = pci(nic['address'])
        require(address[0] in buses and address not in occupied, 'NIC PCI address conflict')
        occupied.add(address); nic_ids.add(nic['id']); guest_names.add(nic['guest_name'])
        if nic['role'] == 'oob':oob.add(nic['id'])
    management = raw['management']
    fields(management, ('mode', 'eligible_ports'), 'management')
    ports = management['eligible_ports']
    require(type(ports) is list and ports and all(isinstance(p, str) and p in nic_ids for p in ports)
            and len(ports) == len(set(ports)), 'qualified management ports required')
    require((management['mode'] == 'oob' and len(oob) == 1 and set(ports) == oob)
            or (management['mode'] == 'selected-data' and not oob), 'management policy conflicts with NIC roles')
    fields(raw['profiles'], ('bootstrap', 'readiness', 'shutdown'), 'guest profiles')
    require(raw['profiles'] == {'bootstrap': 'manual', 'readiness': 'manual', 'shutdown': 'unqualified'},
            'guest automation profiles are not implemented or qualified')
    return json.loads(canonical(raw))


def template_digest(raw):
    return fingerprint(validate_template(raw))
