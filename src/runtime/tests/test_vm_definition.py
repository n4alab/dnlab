"""One-shot definition and dedicated session proofs with an inert SDK fake."""
from contextlib import contextmanager
from copy import deepcopy
import stat
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_session import DedicatedSession
from dnlab_runtime.libvirt_xml import render_domain
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from dnlab_runtime.vm_template import template_digest
from test_vm_template import template, instance


@pytest.fixture
def definition(template,instance,tmp_path):
    profile={'host_id':'worker','uid':1001,'gid':1001,'uri':'qemu:///session',
        'socket':'/run/user/1001/libvirt/libvirt-sock','runtime_root':'/run/user/1001',
        'state_root':'/var/lib/dnlab-libvirt'}
    def resource(kind,inode):return dict(uid=1001,gid=1001,device=4,inode=inode,mode=kind|0o700)
    proof={'profile_sha256':fingerprint(profile),'config_sha256':'a'*64,
        'daemon':dict(uid=1001,gid=1001,boot_id='fake-boot',pid=123,start_ticks=456,executable_sha256='b'*64),
        'socket':resource(stat.S_IFSOCK,1),
        'directories':{'state':resource(stat.S_IFDIR,2),'runtime':resource(stat.S_IFDIR,3)}}
    session=DedicatedSession(profile,lambda:deepcopy(proof))
    state={'domains':{},'calls':[],'uri':'qemu:///session','lost':False,'normalize':False,'lookup_error':None}
    class Error(Exception):
        def __init__(self,code):self.code=code
        def get_error_code(self):return self.code
    class Domain:
        def __init__(self,xml):self.xml=xml;self.active=0
        def UUIDString(self):return ET.fromstring(self.xml).findtext('uuid')
        def name(self):return ET.fromstring(self.xml).findtext('name')
        def isPersistent(self):return 1
        def isActive(self):return self.active
        def XMLDesc(self,flag):assert flag==2;return self.xml
    class Connection:
        def getURI(self):return state['uri']
        def lookupByUUIDString(self,uuid):
            state['calls'].append(('lookup-uuid',uuid))
            if state['lookup_error']:raise Error(state['lookup_error'])
            if uuid not in state['domains']:raise Error(42)
            return state['domains'][uuid]
        def lookupByName(self,name):
            state['calls'].append(('lookup-name',name))
            for domain in state['domains'].values():
                if domain.name()==name:return domain
            raise Error(42)
        def defineXMLFlags(self,xml,flags):
            assert flags==1;state['calls'].append(('define',))
            value=Domain(xml)
            state['domains'][value.UUIDString()]=value
            if state['normalize']:value.xml=value.xml.replace('</domain>','<description>unexpected default</description></domain>')
            if state['lost']:raise OSError('simulated lost SDK response')
            return value
    xml=render_domain(template,**instance)
    birth={key:instance['domain'][key] for key in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256']=template_digest(template)
    def preflight(value):return {'request_fingerprint':value['request_fingerprint'],
        'session_sha256':value['session_sha256'],'assets_verified':True,'overlays_verified':True,'endpoints_verified':True}
    journal=Journal(tmp_path/'journal')
    driver=VMDefinitionDriver(journal,Connection(),session,preflight,no_domain_code=42)
    driver.prepare('first-define',birth,xml)
    yield driver,birth,xml,state,proof,Domain
    journal.close()


def test_definition_records_original_ack_once_and_does_not_boot(definition):
    driver,birth,xml,state,_,_=definition
    value=driver.apply(birth['creator_operation_id'])
    assert value['phase']=='defined' and value['ack']['uuid']==birth['uuid']
    assert driver.apply(birth['creator_operation_id'])==value
    assert state['calls'].count(('define',))==1 and state['domains'][birth['uuid']].active==0
    assert driver.prepare('first-define',birth,xml)==value


def test_lost_define_response_never_causes_second_define_or_cleanup(definition):
    driver,birth,_,state,_,_=definition
    state['lost']=True
    with pytest.raises(OSError):driver.apply(birth['creator_operation_id'])
    assert driver.read(birth['creator_operation_id'])['phase']=='recovery_required'
    with pytest.raises(Conflict,match='not repeated'):driver.apply(birth['creator_operation_id'])
    assert state['calls'].count(('define',))==1 and len(state['domains'])==1


def test_committed_ack_with_lost_commit_response_is_reused(definition,monkeypatch):
    driver,birth,_,state,_,_=definition
    original=driver.journal.transaction;lost=[]
    @contextmanager
    def transaction():
        with original():yield
        if driver.read(birth['creator_operation_id'])['phase']=='defined' and not lost:
            lost.append(True);raise OSError('simulated lost commit response')
    monkeypatch.setattr(driver.journal,'transaction',transaction)
    with pytest.raises(OSError):driver.apply(birth['creator_operation_id'])
    assert driver.apply(birth['creator_operation_id'])['phase']=='defined'
    assert state['calls'].count(('define',))==1


def test_existing_domain_is_preserved_before_any_define(definition):
    driver,birth,xml,state,_,Domain=definition
    foreign=Domain(xml);state['domains'][birth['uuid']]=foreign
    with pytest.raises(Conflict,match='already present'):driver.apply(birth['creator_operation_id'])
    assert ('define',) not in state['calls'] and state['domains'][birth['uuid']] is foreign


@pytest.mark.parametrize('fault',['lookup-denied','session-daemon','session-socket','socket-public','daemon-root','uri','preflight'])
def test_failed_preflight_performs_no_definition(definition,fault):
    driver,birth,_,state,proof,_=definition
    if fault=='lookup-denied':state['lookup_error']=13
    elif fault=='session-daemon':proof['daemon']['pid']=999
    elif fault=='session-socket':proof['socket']['inode']=999
    elif fault=='socket-public':proof['socket']['mode']|=0o060
    elif fault=='daemon-root':proof['daemon']['uid']=0
    elif fault=='uri':state['uri']='qemu:///system'
    else:driver.preflight=lambda value:{}
    with pytest.raises(RuntimeErrorBase):driver.apply(birth['creator_operation_id'])
    assert ('define',) not in state['calls'] and state['domains']=={}


def test_definition_appearing_after_checkpoint_is_not_replaced(definition,monkeypatch):
    driver,birth,xml,state,_,Domain=definition
    original=driver._save;foreign=Domain(xml)
    def save(operation,value):
        original(operation,value)
        if value['phase']=='define_requested':state['domains'][birth['uuid']]=foreign
    monkeypatch.setattr(driver,'_save',save)
    with pytest.raises(Conflict,match='already present'):driver.apply(birth['creator_operation_id'])
    assert ('define',) not in state['calls'] and state['domains'][birth['uuid']] is foreign


def test_unqualified_normalization_keeps_original_domain_and_recovery(definition):
    driver,birth,_,state,_,_=definition
    state['normalize']=True
    with pytest.raises(Conflict,match='normalization'):driver.apply(birth['creator_operation_id'])
    assert driver.read(birth['creator_operation_id'])['phase']=='recovery_required'
    assert len(state['domains'])==1 and state['domains'][birth['uuid']].active==0


def test_definition_intent_alone_protects_lab_cleanup(definition):
    driver,_,_,state,_,_=definition
    before=driver.journal.db.total_changes
    assert cleanup_inventory(driver.journal,'lab')=={'nodes':['vd'],'blocked':['resources','vm_definition_intents']}
    assert cleanup_inventory(driver.journal,'other')=={'nodes':[],'blocked':[]}
    assert driver.journal.db.total_changes==before and ('define',) not in state['calls']


def test_request_content_cannot_be_changed_on_retry(definition):
    driver,birth,xml,_,_,_=definition
    changed=deepcopy(birth);changed['nonce']='9'*32
    changed_xml=xml.replace(birth['nonce'],changed['nonce'])
    with pytest.raises(Conflict,match='content differs'):driver.prepare('first-define',changed,changed_xml)
    assert driver.read(birth['creator_operation_id'])['birth']==birth
