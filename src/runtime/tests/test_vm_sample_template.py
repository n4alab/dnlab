"""V2 translation from explicit inputs; no vendor assets or hypervisor IO."""
from copy import deepcopy

import pytest

from dnlab_runtime.vm_sample_template import sample_template
from dnlab_runtime.vm_template import TemplateError


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
