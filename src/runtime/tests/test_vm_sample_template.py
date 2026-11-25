"""V2 translation from explicit inputs; no vendor assets or hypervisor IO."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.vm_sample_template import sample_template
from dnlab_runtime.vm_template import TemplateError, template_digest, validate_template
from dnlab_runtime.libvirt_xml import render_domain
from dnlab_runtime.vm_storage import disk_plan


@pytest.fixture
def inputs():
    return dict(source=dict(repository='https://github.com/n4alab/vrnetlab.git', branch='dnlab', commit='a' * 40),
                base=dict(path='disks/base.qcow2', sha256='b' * 64, size=1234, format='qcow2'),
                machine='pc-i440fx-10.0', resources=dict(memory_mib=2048, vcpus=1, cpu='host'), nic_count=9,
                placement=dict(bridges=[dict(bus=0, slot=4, function=0)],
                               first_nic=dict(bus=0, slot=5, function=0), disk=dict(bus=0, slot=6, function=0)))


def test_vios_retains_resolved_resources_and_all_ports_are_data(inputs):
    before = deepcopy(inputs)
    value = sample_template('vios-l2-v2', **inputs)
    assert inputs == before
    assert value['hardware']['memory_mib'] == 2048
    assert value['hardware']['disks'][0]['bus'] == 'virtio'
    assert value['hardware']['firmware'] == dict(mode='bios')
    assert [nic['guest_name'] for nic in value['hardware']['nics']] == [f'GigabitEthernet0/{i}' for i in range(9)]
    assert all(nic['role'] == 'data' for nic in value['hardware']['nics'])
    assert value['management'] == dict(mode='selected-data', eligible_ports=[f'p{i:02d}' for i in range(9)])
    assert value['profiles']['shutdown'] == 'unqualified'


def test_n9kv_retains_source_bridges_sata_rom_and_oob_at_boundary(inputs):
    inputs.update(resources=dict(memory_mib=10240, vcpus=4, cpu='host'), nic_count=27,
                  firmware=dict(path='firmware/OVMF.fd', sha256='c' * 64, size=4096, format='raw'))
    inputs['placement'] = dict(bridges=[dict(bus=0, slot=slot, function=0) for slot in range(4, 9)],
                               first_nic=dict(bus=0, slot=9, function=0), disk=dict(bus=0, slot=10, function=0))
    value = sample_template('n9kv-9500-v2', **inputs)
    hardware = value['hardware']
    assert len([c for c in hardware['controllers'] if c['type'] == 'pci']) == 6
    assert hardware['disks'][0]['bus'] == 'sata'
    assert hardware['firmware'] == dict(mode='rom', asset='firmware')
    assert value['management'] == dict(mode='oob', eligible_ports=['p00'])
    assert hardware['nics'][0]['role'] == 'oob'
    assert hardware['nics'][25]['address'] == dict(bus=1, slot=26, function=0)
    assert hardware['nics'][26]['address'] == dict(bus=2, slot=1, function=0)


@pytest.mark.parametrize('fault', ['machine-alias', 'too-many-nics', 'missing-bridge', 'pci-conflict', 'firmware', 'resources'])
def test_no_implicit_hardware_or_resource_fallback(inputs, fault):
    if fault == 'machine-alias':inputs['machine'] = 'pc'
    elif fault == 'too-many-nics':inputs['nic_count'] = 17
    elif fault == 'missing-bridge':inputs['placement']['bridges'] = []
    elif fault == 'pci-conflict':inputs['placement']['disk'] = deepcopy(inputs['placement']['first_nic'])
    elif fault == 'firmware':inputs['firmware'] = dict(path='firmware.fd', sha256='c' * 64, size=4096, format='raw')
    else:inputs['resources']['vcpus'] = True
    with pytest.raises(TemplateError):sample_template('vios-l2-v2', **inputs)


@pytest.fixture
def openwrt_inputs(inputs):
    value = deepcopy(inputs)
    value.update(base=dict(path='disks/base.img', sha256='b' * 64, size=1234, format='raw'),
                 resources=dict(memory_mib=128, vcpus=1, cpu='host'))
    value['placement'] = dict(bridges=[dict(bus=0, slot=4, function=0)],
        first_nic=dict(bus=0, slot=5, function=0),
        ide_controller=dict(bus=0, slot=1, function=1),
        disk=dict(controller=0, bus=0, target=0, unit=0))
    return value


def test_openwrt_preserves_raw_base_ide_boot_and_separate_management(openwrt_inputs):
    before = deepcopy(openwrt_inputs)
    value = sample_template('openwrt-v2', **openwrt_inputs)
    assert openwrt_inputs == before
    assert value['source']['launcher'] == 'openwrt_V2/docker/launch.py'
    assert value['hardware']['memory_mib'] == 128
    assert value['assets']['base']['format'] == 'raw'
    assert value['hardware']['disks'][0]['bus'] == 'ide'
    assert value['hardware']['nics'][0]['guest_name'] == 'eth0'
    assert value['management'] == dict(mode='oob', eligible_ports=['p00'])
    assert [nic['guest_name'] for nic in value['hardware']['nics']] == [f'eth{i}' for i in range(9)]
    assert all(nic['model'] == 'virtio' for nic in value['hardware']['nics'])
    assert all(nic['role'] == 'data' for nic in value['hardware']['nics'][1:])
    assert value['profiles'] == dict(bootstrap='manual', readiness='manual', shutdown='unqualified')


def test_openwrt_xml_and_overlay_plan_keep_raw_backing_and_ide_mapping(openwrt_inputs):
    value = sample_template('openwrt-v2', **openwrt_inputs)
    domain = dict(name='openwrt-test', uuid='12345678-1234-4234-8234-123456789abc',
        lab_id='lab', node_id='openwrt', host_id='worker', generation=1,
        creator_operation_id='c' * 32, nonce='d' * 32, management_port='p00')
    interfaces = {nic['id']:dict(tap=f'dt-openwrt{i}', mac=f'02:00:00:00:00:{i:02x}',
                                mtu=1500, link_state='down')
                  for i,nic in enumerate(value['hardware']['nics'])}
    xml = render_domain(value, bundle_root='/templates/openwrt', domain=domain,
        overlays=dict(boot='/persist/openwrt/boot.qcow2'), interfaces=interfaces,
        console_path='/persist/openwrt/console.sock', emulator='/usr/bin/qemu-system-x86_64')
    root = ET.fromstring(xml)
    assert root.find('devices/controller[@type="ide"]').get('index') == '0'
    assert root.find('devices/disk/target').attrib == dict(dev='hda', bus='ide')
    assert root.find('devices/disk/driver').get('type') == 'qcow2'
    assert root.find('devices/disk/address').attrib == dict(type='drive', controller='0', bus='0', target='0', unit='0')
    birth = {key:item for key,item in domain.items() if key not in ('name','management_port')}
    birth['template_sha256'] = template_digest(value)
    plan = disk_plan(dict(xml=xml, birth=birth), value, '/templates/openwrt', dict(uid=1001, gid=1002))
    assert plan[0]['base_format'] == 'raw'
    assert plan[0]['base_path'] == '/templates/openwrt/disks/base.img'


@pytest.mark.parametrize('fault', ['qcow2-base','missing-ide','missing-bridge','pci-conflict',
                                  'drive-controller','machine-alias','firmware','too-many-nics'])
def test_openwrt_refuses_unqualified_layout_without_fallback(openwrt_inputs, fault):
    if fault == 'qcow2-base':openwrt_inputs['base']['format'] = 'qcow2'
    elif fault == 'missing-ide':del openwrt_inputs['placement']['ide_controller']
    elif fault == 'missing-bridge':openwrt_inputs['placement']['bridges'] = []
    elif fault == 'pci-conflict':openwrt_inputs['placement']['ide_controller'] = deepcopy(openwrt_inputs['placement']['first_nic'])
    elif fault == 'drive-controller':openwrt_inputs['placement']['disk']['controller'] = 1
    elif fault == 'machine-alias':openwrt_inputs['machine'] = 'pc'
    elif fault == 'firmware':openwrt_inputs['firmware'] = dict(path='firmware.fd', sha256='c' * 64, size=4096, format='raw')
    else:openwrt_inputs['nic_count'] = 66
    with pytest.raises(TemplateError):sample_template('openwrt-v2', **openwrt_inputs)


@pytest.mark.parametrize('fault', ['missing','wrong-type','duplicate'])
def test_ide_disk_requires_its_own_unique_controller(openwrt_inputs, fault):
    value = sample_template('openwrt-v2', **openwrt_inputs)
    controllers = value['hardware']['controllers']
    if fault == 'missing':controllers.pop()
    elif fault == 'wrong-type':controllers[-1]['type'] = 'sata'
    else:
        duplicate = deepcopy(controllers[-1]);duplicate['address']['slot'] = 7
        controllers.append(duplicate)
    with pytest.raises(TemplateError):validate_template(value)
