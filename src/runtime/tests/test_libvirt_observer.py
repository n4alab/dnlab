"""SDK-shaped fake connection; all domain/process observations are synthetic."""
from contextlib import contextmanager
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_observer import LibvirtDomainObserver, creation_reference, xml_fingerprint
from dnlab_runtime.libvirt_xml import render_domain, OWNER_NS
from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.vm_events import VMEventTracker
from test_vm_template import template, instance


@pytest.fixture
def observer(template,instance):
    xml=render_domain(template,**instance)
    domain=instance['domain']
    from dnlab_runtime.vm_template import template_digest
    birth={key:domain[key] for key in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256']=template_digest(template)
    state={'xml':{0:xml,2:xml},'uuid':domain['uuid'],'active':1,'uri':'qemu:///system',
           'process':{'boot_id':'synthetic-boot','pid':123,'start_ticks':456,'executable_sha256':'a'*64}}
    calls=[]
    class Domain:
        def UUIDString(self):return state['uuid']
        def isActive(self):return state['active']
        def XMLDesc(self,flag):calls.append(('XMLDesc',flag));return state['xml'][flag]
    class Connection:
        def getURI(self):return state['uri']
        def lookupByUUIDString(self,uuid):
            assert uuid==birth['uuid'];calls.append(('lookupByUUIDString',uuid));return Domain()
    class Process:
        @contextmanager
        def capture(self,expected):
            assert expected==birth;calls.append(('pidfd-enter',))
            try:yield deepcopy(state['process'])
            finally:calls.append(('pidfd-exit',))
    reference=creation_reference(birth,uri=state['uri'],persistent_xml=xml,live_xml=xml,process=state['process'])
    value=LibvirtDomainObserver(Connection(),reference,xml_inactive_flag=2,process=Process())
    return value,birth,state,calls


def test_observer_reads_only_original_uuid_both_configs_and_pinned_process(observer):
    value,birth,state,calls=observer
    before=deepcopy(state)
    result=value(birth)
    assert result['birth']==birth and result['process']==state['process'] and state==before
    assert calls.count(('lookupByUUIDString',birth['uuid']))==2
    assert calls.count(('XMLDesc',0))==calls.count(('XMLDesc',2))==2
    assert calls[-1]==('pidfd-exit',)


@pytest.mark.parametrize('fault',['uri','uuid','nonce','persistent-disk','live-nic','inactive','pid','starttime','executable'])
def test_observer_refuses_replacements_instead_of_learning_them(observer,fault):
    value,birth,state,_=observer
    if fault=='uri':state['uri']='qemu:///session'
    elif fault=='uuid':state['uuid']='22345678-1234-4234-8234-123456789abc'
    elif fault=='nonce':
        root=ET.fromstring(state['xml'][0]);root.find('metadata/{'+OWNER_NS+'}owner').set('nonce','f'*32)
        state['xml'][0]=ET.tostring(root,encoding='unicode')
    elif fault=='persistent-disk':state['xml'][2]=state['xml'][2].replace('overlay.qcow2','foreign.qcow2')
    elif fault=='live-nic':state['xml'][0]=state['xml'][0].replace('dt-mgmt0','foreign0')
    elif fault=='inactive':state['active']=0
    elif fault=='pid':state['process']['pid']=999
    elif fault=='starttime':state['process']['start_ticks']+=1
    else:state['process']['executable_sha256']='f'*64
    reference=deepcopy(value.reference);before=deepcopy(state)
    with pytest.raises(RuntimeErrorBase):value(birth)
    assert value.reference==reference and state==before


def test_formatting_changes_do_not_hide_or_invent_config_changes(observer):
    value,birth,state,_=observer
    root=ET.fromstring(state['xml'][0])
    for element in root.iter():element.attrib=dict(reversed(list(element.attrib.items())))
    ET.indent(root,space='    ')
    formatted=ET.tostring(root,encoding='unicode')
    assert xml_fingerprint(formatted,birth)==xml_fingerprint(state['xml'][0],birth)
    state['xml'][0]=formatted
    assert value(birth)['process']==state['process']


def test_observer_composes_with_durable_tracker_without_hypervisor_commands(observer,tmp_path):
    value,birth,state,_=observer
    journal=Journal(tmp_path/'journal')
    try:
        tracker=VMEventTracker(journal,value)
        tracker.begin('b'*32,birth)
        assert tracker.record('b'*32,1,'reboot')['state']['phase']=='active'
        state['process']['start_ticks']+=1
        result=tracker.record('b'*32,2,'reboot')
        assert result['state']['phase']=='recovery_required' and result['state']['reboot_count']==1
    finally:journal.close()


def test_live_config_change_during_pinned_process_observation_is_rejected(observer,monkeypatch):
    value,birth,state,calls=observer
    original=value.process.capture;reference=deepcopy(value.reference)
    @contextmanager
    def capture(expected):
        with original(expected) as proof:
            state['xml'][0]=state['xml'][0].replace('dt-mgmt0','foreign0')
            yield proof
    monkeypatch.setattr(value.process,'capture',capture)
    with pytest.raises(RuntimeErrorBase):value(birth)
    assert calls[-1]==('pidfd-exit',) and value.reference==reference


def test_domain_xml_dtd_is_refused_before_process_observation(observer):
    value,birth,state,calls=observer
    state['xml'][0]='<!DOCTYPE domain [<!ENTITY injected "value">]>'+state['xml'][0]
    with pytest.raises(RuntimeErrorBase,match='without DTD'):value(birth)
    assert ('pidfd-enter',) not in calls
