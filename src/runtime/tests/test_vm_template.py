"""Single-VM template and XML planning with synthetic data, no filesystem IO."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.libvirt_xml import OWNER_NS, render_domain
from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.vm_template import TemplateError, template_digest, validate_template


@pytest.fixture
def template():
    return {'schema_version':1,'id':'synthetic-vm','source':{
        'repository':'https://example.invalid/vrnetlab.git','branch':'dnlab','commit':'a'*40,
        'launcher':'cisco/example_V2/docker/launch.py'},
        'assets':{'base':{'path':'disks/base.qcow2','sha256':'b'*64,'size':1234,'format':'qcow2'}},
        'hardware':{'arch':'x86_64','machine':'pc-i440fx-9.0','memory_mib':512,'vcpus':1,'cpu':'host',
            'firmware':{'mode':'bios'},'controllers':[{'type':'pci','index':0,'model':'pci-root'}],
            'disks':[{'id':'boot','asset':'base','bus':'virtio','target':'vda','address':{'bus':0,'slot':4,'function':0}}],
            'nics':[{'id':'p0','model':'e1000','guest_name':'GigabitEthernet0/0','role':'data','address':{'bus':0,'slot':5,'function':0}},
                    {'id':'p1','model':'e1000','guest_name':'GigabitEthernet0/1','role':'data','address':{'bus':0,'slot':6,'function':0}}]},
        'management':{'mode':'selected-data','eligible_ports':['p0','p1']},
        'profiles':{'bootstrap':'manual','readiness':'manual','shutdown':'unqualified'}}


@pytest.fixture
def instance():
    return dict(bundle_root='/templates/synthetic',
        domain={'name':'dnlab-test-vd','uuid':'12345678-1234-4234-8234-123456789abc',
            'lab_id':'lab','node_id':'vd','host_id':'worker','generation':1,
            'creator_operation_id':'c'*32,'nonce':'d'*32,'management_port':'p1'},
        overlays={'boot':'/persist/lab/vd/overlay.qcow2'},
        interfaces={'p0':{'tap':'dt-data0','mac':'02:00:00:00:00:01','mtu':1500,'link_state':'down'},
                    'p1':{'tap':'dt-mgmt0','mac':'02:00:00:00:00:02','mtu':1500,'link_state':'up'}},
        console_path='/run/dnlab/vd/console.sock',emulator='/usr/bin/qemu-system-x86_64')


def test_template_digest_is_stable_and_validation_does_not_mutate(template):
    original=deepcopy(template)
    value=validate_template(template)
    assert value==original and value is not template
    assert template_digest(template)==template_digest(dict(reversed(list(template.items()))))
    value['hardware']['memory_mib']=1024
    assert template==original and template_digest(value)!=template_digest(template)


def test_xml_binds_identity_hardware_overlays_and_precreated_taps(template,instance):
    before=deepcopy(instance)
    xml=render_domain(template,**instance);root=ET.fromstring(xml)
    assert xml==render_domain(template,**instance) and instance==before
    assert root.attrib=={'type':'kvm'}
    assert root.findtext('uuid')==instance['domain']['uuid']
    owner=root.find('metadata/{'+OWNER_NS+'}owner')
    assert owner.get('nonce')==instance['domain']['nonce']
    assert owner.get('template_sha256')==template_digest(template)
    assert root.find('devices/disk/source').get('file')==instance['overlays']['boot']
    assert root.find('devices/disk/driver').get('type')=='qcow2'
    assert root.findtext('memory')=='512' and root.findtext('vcpu')=='1'
    assert root.find('cpu').get('mode')=='host-passthrough'
    interfaces=root.findall('devices/interface')
    assert [v.find('target').attrib for v in interfaces]==[
        {'dev':'dt-data0','managed':'no'},{'dev':'dt-mgmt0','managed':'no'}]
    assert [v.find('address').get('slot') for v in interfaces]==['0x05','0x06']
    assert [v.find('link').get('state') for v in interfaces]==['down','up']
    assert all(v.get('type')=='ethernet' and v.find('source') is None for v in interfaces)
    assert root.find('devices/serial').get('type')=='unix'
    assert root.find('devices/serial/source').attrib=={'mode':'bind','path':instance['console_path']}
    assert not root.findall('.//script') and not root.findall('.//downscript') and not root.findall('.//network')
    assert root.findtext('on_reboot')=='restart' and root.findtext('on_crash')=='destroy'


@pytest.mark.parametrize('fault',['asset-path','hash','resources','machine-alias','pci-conflict','missing-controller','wrong-management','automation'])
def test_invalid_templates_fail_before_xml(template,instance,fault):
    if fault=='asset-path':template['assets']['base']['path']='../outside.qcow2'
    elif fault=='hash':template['assets']['base']['sha256']='unversioned'
    elif fault=='resources':template['hardware']['vcpus']=True
    elif fault=='machine-alias':template['hardware']['machine']='pc'
    elif fault=='pci-conflict':template['hardware']['nics'][0]['address']=deepcopy(template['hardware']['disks'][0]['address'])
    elif fault=='missing-controller':template['hardware']['nics'][0]['address']['bus']=9
    elif fault=='wrong-management':template['management']['mode']='oob'
    else:template['profiles']['shutdown']='verified'
    with pytest.raises(TemplateError):render_domain(template,**instance)


@pytest.mark.parametrize('fault',['wrong-management','base-as-overlay','duplicate-tap','duplicate-mac','reserved-tap','uuid'])
def test_instance_conflicts_are_not_silently_normalized(template,instance,fault):
    if fault=='wrong-management':instance['domain']['management_port']='foreign'
    elif fault=='base-as-overlay':instance['overlays']['boot']='/templates/synthetic/disks/base.qcow2'
    elif fault=='duplicate-tap':instance['interfaces']['p1']['tap']=instance['interfaces']['p0']['tap']
    elif fault=='duplicate-mac':instance['interfaces']['p1']['mac']=instance['interfaces']['p0']['mac']
    elif fault=='reserved-tap':instance['interfaces']['p1']['tap']='vnet0'
    else:instance['domain']['uuid']='a'*64
    with pytest.raises(RuntimeErrorBase):render_domain(template,**instance)


def test_rom_firmware_and_sata_are_explicit(template,instance):
    template['assets']['firmware']={'path':'firmware/OVMF.fd','sha256':'e'*64,'size':456,'format':'raw'}
    template['hardware']['firmware']={'mode':'rom','asset':'firmware'}
    template['hardware']['controllers'].append({'type':'sata','index':0,'address':{'bus':0,'slot':4,'function':0}})
    template['hardware']['disks'][0].update(bus='sata',target='sda',address={'controller':0,'bus':0,'target':0,'unit':0})
    root=ET.fromstring(render_domain(template,**instance))
    assert root.find('os/loader').attrib=={'readonly':'yes','type':'rom'}
    assert root.findtext('os/loader')=='/templates/synthetic/firmware/OVMF.fd'
    assert root.find('devices/disk/target').attrib=={'dev':'sda','bus':'sata'}
    assert root.find('devices/disk/address').get('type')=='drive'


def test_pflash_has_separate_writable_nvram_and_xml_paths_are_escaped(template,instance):
    template['assets']['code']={'path':'firmware/code.fd','sha256':'e'*64,'size':456,'format':'raw'}
    template['assets']['vars']={'path':'firmware/vars.fd','sha256':'f'*64,'size':789,'format':'raw'}
    template['hardware']['firmware']={'mode':'pflash','asset':'code','nvram_template':'vars'}
    instance['nvram_path']='/persist/lab/vd/vars.fd'
    instance['console_path']='/run/dnlab/a&b/console.sock'
    root=ET.fromstring(render_domain(template,**instance))
    assert root.findtext('os/nvram')==instance['nvram_path']
    assert root.find('os/nvram').get('template')=='/templates/synthetic/firmware/vars.fd'
    assert root.find('devices/serial/source').get('path')==instance['console_path']
    instance['nvram_path']=instance['overlays']['boot']
    with pytest.raises(TemplateError):render_domain(template,**instance)
