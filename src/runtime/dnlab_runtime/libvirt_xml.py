"""Deterministic offline XML for a single VM, not a libvirt execution adapter.

Host preflight must qualify assets, overlay chains, TAP ownership, capabilities
and original operation before using this output. No IO is performed here.
"""
from pathlib import PurePosixPath
import re
from xml.etree import ElementTree as ET

from .manifest import identifier
from .vm_template import fields, require, template_digest, validate_template
from .workload_identity import WorkloadReference

OWNER_NS = 'urn:dnlab:runtime:vm:1'


def absolute(value):
    require(isinstance(value, str) and value.startswith('/') and value != '/'
            and '..' not in PurePosixPath(value).parts and str(PurePosixPath(value)) == value
            and not any(ord(c) < 32 for c in value), 'canonical absolute VM asset path required')
    return value


def pci_element(parent, value):
    ET.SubElement(parent, 'address', type='pci', domain='0x0000',
        bus=f"0x{value['bus']:02x}", slot=f"0x{value['slot']:02x}", function=f"0x{value['function']:x}")


def render_domain(template, *, bundle_root, domain, overlays, interfaces, console_path, emulator, nvram_path=None):
    template = validate_template(template)
    hardware = template['hardware']; bundle_root = absolute(bundle_root)
    fields(domain, ('name', 'uuid', 'lab_id', 'node_id', 'host_id', 'generation', 'creator_operation_id', 'nonce', 'management_port'), 'VM instance')
    for key in ('name', 'lab_id', 'node_id', 'host_id'):identifier(domain[key], key)
    WorkloadReference('libvirt', 'vm', domain['uuid'])
    require(type(domain['generation']) is int and domain['generation'] > 0
            and all(isinstance(domain[k], str) and re.fullmatch(r'[0-9a-f]{32}', domain[k])
                    for k in ('creator_operation_id', 'nonce'))
            and domain['management_port'] in template['management']['eligible_ports'], 'invalid original VM generation or management port')
    disks, nics = hardware['disks'], hardware['nics']
    require(type(overlays) is dict and set(overlays) == {disk['id'] for disk in disks}, 'exact overlay inventory required')
    paths = set()
    for value in overlays.values():
        absolute(value)
        require(value not in paths and not PurePosixPath(value).is_relative_to(bundle_root),
                'overlay must be distinct and outside immutable template bundle')
        paths.add(value)
    absolute(console_path); absolute(emulator)
    require(console_path not in paths and not PurePosixPath(console_path).is_relative_to(bundle_root),
            'console socket must be outside immutable bundle and disks')
    firmware = hardware['firmware']
    if firmware['mode'] == 'pflash':
        absolute(nvram_path)
        require(nvram_path not in paths and nvram_path != console_path
                and not PurePosixPath(nvram_path).is_relative_to(bundle_root), 'distinct writable NVRAM path required')
    else:
        require(nvram_path is None, 'unexpected writable NVRAM')
    require(type(interfaces) is dict and set(interfaces) == {nic['id'] for nic in nics}, 'exact TAP inventory required')
    taps, macs = set(), set()
    for value in interfaces.values():
        fields(value, ('tap', 'mac', 'mtu', 'link_state'), 'TAP binding')
        require(isinstance(value['tap'], str) and re.fullmatch(r'[A-Za-z][A-Za-z0-9_-]{0,14}', value['tap'])
                and not value['tap'].startswith(('vnet', 'vif', 'macvtap', 'macvlan'))
                and value['tap'] not in taps, 'distinct non-reserved TAP names required')
        require(isinstance(value['mac'], str) and re.fullmatch(r'[0-9a-f]{2}(?::[0-9a-f]{2}){5}', value['mac'])
                and not (int(value['mac'][:2], 16) & 1) and value['mac'] != '00:00:00:00:00:00'
                and value['mac'] not in macs, 'distinct unicast guest MACs required')
        require(type(value['mtu']) is int and 576 <= value['mtu'] <= 9216
                and value['link_state'] in ('up', 'down'), 'invalid NIC MTU or carrier')
        taps.add(value['tap']); macs.add(value['mac'])
    root = ET.Element('domain', type='kvm')
    ET.SubElement(root, 'name').text = domain['name']
    ET.SubElement(root, 'uuid').text = domain['uuid']
    metadata = ET.SubElement(root, 'metadata')
    owner = {key: str(value) for key, value in domain.items() if key not in ('name', 'uuid')}
    owner['template_sha256'] = template_digest(template)
    ET.SubElement(metadata, '{' + OWNER_NS + '}owner', owner)
    ET.SubElement(root, 'memory', unit='MiB').text = str(hardware['memory_mib'])
    ET.SubElement(root, 'currentMemory', unit='MiB').text = str(hardware['memory_mib'])
    ET.SubElement(root, 'vcpu', placement='static').text = str(hardware['vcpus'])
    if hardware['cpu'] == 'host':
        ET.SubElement(root, 'cpu', mode='host-passthrough', check='none')
    else:
        cpu = ET.SubElement(root, 'cpu', mode='custom', match='exact')
        ET.SubElement(cpu, 'model', fallback='forbid').text = hardware['cpu']
    os = ET.SubElement(root, 'os')
    ET.SubElement(os, 'type', arch=hardware['arch'], machine=hardware['machine']).text = 'hvm'
    def asset_path(key):return str(PurePosixPath(bundle_root) / template['assets'][key]['path'])
    if firmware['mode'] != 'bios':
        ET.SubElement(os, 'loader', readonly='yes', type=firmware['mode']).text = asset_path(firmware['asset'])
    if firmware['mode'] == 'pflash':
        ET.SubElement(os, 'nvram', template=asset_path(firmware['nvram_template'])).text = nvram_path
    ET.SubElement(os, 'boot', dev='hd')
    features = ET.SubElement(root, 'features')
    ET.SubElement(features, 'acpi'); ET.SubElement(features, 'apic')
    # Guest-initiated reboot is permitted; crash never requests a restart.
    # The execution adapter must journal events and requalify the incarnation.
    for key, value in (('on_poweroff', 'destroy'), ('on_reboot', 'restart'), ('on_crash', 'destroy')):
        ET.SubElement(root, key).text = value
    devices = ET.SubElement(root, 'devices')
    ET.SubElement(devices, 'emulator').text = emulator
    for value in hardware['controllers']:
        attrs = {k: str(value[k]) for k in ('type', 'index', 'model') if k in value}
        controller = ET.SubElement(devices, 'controller', attrs)
        if 'address' in value:pci_element(controller, value['address'])
    for disk in disks:
        element = ET.SubElement(devices, 'disk', type='file', device='disk')
        ET.SubElement(element, 'driver', name='qemu', type='qcow2')
        ET.SubElement(element, 'source', file=overlays[disk['id']])
        ET.SubElement(element, 'target', dev=disk['target'], bus=disk['bus'])
        if disk['bus'] == 'virtio':pci_element(element, disk['address'])
        else:ET.SubElement(element, 'address', type='drive', **{k: str(v) for k, v in disk['address'].items()})
    for nic in nics:
        value = interfaces[nic['id']]
        element = ET.SubElement(devices, 'interface', type='ethernet')
        ET.SubElement(element, 'mac', address=value['mac'])
        ET.SubElement(element, 'target', dev=value['tap'], managed='no')
        ET.SubElement(element, 'model', type=nic['model'])
        ET.SubElement(element, 'mtu', size=str(value['mtu']))
        ET.SubElement(element, 'link', state=value['link_state'])
        pci_element(element, nic['address'])
    serial = ET.SubElement(devices, 'serial', type='unix')
    ET.SubElement(serial, 'source', mode='bind', path=console_path)
    ET.SubElement(serial, 'target', type='isa-serial', port='0')
    ET.indent(root)
    return ET.tostring(root, encoding='unicode')
