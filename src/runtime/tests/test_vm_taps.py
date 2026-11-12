"""Complete-set VM TAP admission and original-provider response recovery."""
from copy import deepcopy
from xml.etree import ElementTree as ET

import pytest

from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_tap_device import IFF_TAP, IFF_NO_PI, IFF_VNET_HDR
from dnlab_runtime.vm_tap_retention import PERSIST, request_part
from dnlab_runtime.vm_taps import VMTaps
from test_vm_definition import definition, template, instance


@pytest.fixture
def taps(definition):
    definitions,birth,xml,domains,session_proof,_=definition
    context=dict(boot_id='12345678-1234-4234-8234-123456789abc',device=4,inode=100)
    requests=[dict(name=target.get('dev'),ifindex=400+index,nonce=str(index+1)*32,vnet_header=True)
        for index,target in enumerate(ET.fromstring(xml).findall('devices/interface/target'))]
    state=dict(proofs={},creates=[],recovers=[],context=deepcopy(context),writer=False)
    class Endpoints:
        def observe(self,item,operation):return deepcopy(state['proofs'].get(item['spec']['tap']['name']))
        def create(self,item,operation):
            spec=item['spec'];tap=spec['tap'];state['creates'].append(tap['name'])
            saved=driver.read(operation)
            assert saved['items'][len(state['creates'])-1]['phase']=='create_requested'
            flags=IFF_TAP|IFF_NO_PI|(IFF_VNET_HDR if tap['vnet_header'] else 0)
            born=dict(context=deepcopy(context),request_sha256=fingerprint(tap),flags=flags,
                device=dict(device=6,inode=194,mode=8630,uid=0,gid=0,rdev=2760),
                link=dict(ifname=tap['name'],ifindex=tap['ifindex'],address='02:00:00:00:00:fe',mtu=1500,
                    flags=['BROADCAST','MULTICAST'],linkinfo=dict(info_kind='tun',info_data=dict(type='tap',persist=False))))
            current=deepcopy(born);current['flags']|=PERSIST
            current['link']['linkinfo']['info_data'].update(user=spec['uid'],group=spec['gid'],persist=True)
            retained=dict(id=tap['nonce'],spec=deepcopy(tap),context=deepcopy(context),lease_token='a'*32,
                birth=born,uid=spec['uid'],gid=spec['gid'],phase='retained',step=3,proof=None,retained_proof=current)
            retained['request_sha256']=fingerprint(request_part(retained))
            proof=dict(operation_id=operation,spec_sha256=fingerprint(spec),worker_reference_sha256='b'*64,retention=retained)
            state['proofs'][tap['name']]=proof
            if state.get('lost'):raise OSError('lost original TAP worker response')
            return deepcopy(proof)
        def recover(self,item,operation):
            state['recovers'].append(item['spec']['tap']['name'])
            if state.get('lease_lost'):raise Conflict('original creator lease lost; no adoption')
            proof=self.observe(item,operation)
            if proof is None:raise Conflict('original TAP completion missing')
            return proof
    endpoints=Endpoints()
    def preflight(value):
        original=definitions.read(value['id'])
        return dict(definition_sha256=value['definition_sha256'],session_sha256=original['session_sha256'],
            context_sha256=fingerprint(context),session_namespace_verified=True,guest_writers_absent=not state['writer'])
    def make():return VMTaps(definitions,endpoints=endpoints,read_context=lambda:deepcopy(state['context']),preflight=preflight)
    driver=make();value=driver.prepare(birth['creator_operation_id'],context,requests)
    return driver,value,state,make,definitions,domains,session_proof


def test_original_full_set_is_reserved_and_retained_once(taps):
    driver,value,state,make,_,_,_=taps
    result=driver.apply(value['id'])
    assert result['phase']=='retained' and len(state['creates'])==len(value['items'])
    assert make().apply(value['id'])==result
    assert driver.prepare(value['id'],value['context'],[item['spec']['tap'] for item in value['items']])==result
    assert state['recovers']==[]
    assert 'vm_tap_intents' in cleanup_inventory(driver.journal,'lab')['blocked']
    assert driver.journal.db.execute('SELECT count(*) FROM vm_tap_ifindices').fetchone()[0]==len(value['items'])


def test_occupied_last_port_prevents_first_allocation(taps):
    driver,value,state,_,_,_,_=taps
    state['proofs'][value['items'][-1]['spec']['tap']['name']]={'foreign':True}
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='occupied'):driver.apply(value['id'])
    assert state['creates']==[] and driver.journal.db.total_changes==before


def test_lost_response_uses_original_worker_without_second_create(taps):
    driver,value,state,make,_,_,_=taps;state['lost']=True
    with pytest.raises(OSError):driver.apply(value['id'])
    with pytest.raises(Conflict,match='recovery'):driver.observe(value['id'])
    state['lost']=False
    result=make().apply(value['id'])
    assert result['phase']=='retained'
    assert state['recovers']==[value['items'][0]['spec']['tap']['name']]
    assert len(state['creates'])==len(value['items'])


def test_lost_original_creator_lease_remains_pending(taps):
    driver,value,state,make,_,_,_=taps;state['lost']=True
    with pytest.raises(OSError):driver.apply(value['id'])
    state['lease_lost']=True;before=driver.read(value['id'])
    with pytest.raises(Conflict,match='lease lost'):make().apply(value['id'])
    assert driver.read(value['id'])==before and len(state['creates'])==1


@pytest.mark.parametrize('fault',['writer','namespace','session','reservation','index','domain'])
def test_preflight_conflict_prevents_all_creates(taps,fault):
    driver,value,state,_,definitions,domains,session_proof=taps
    if fault=='writer':state['writer']=True
    elif fault=='namespace':state['context']['inode']+=1
    elif fault=='session':session_proof['daemon']['start_ticks']+=1
    elif fault=='reservation':driver.journal.db.execute("DELETE FROM resources WHERE key LIKE 'interface:%'")
    elif fault=='index':driver.journal.db.execute('DELETE FROM vm_tap_ifindices')
    else:domains['domains'][value['birth']['uuid']]=object()
    before=driver.read(value['id'])
    with pytest.raises(RuntimeErrorBase):driver.apply(value['id'])
    assert state['creates']==[] and driver.read(value['id'])==before


@pytest.mark.parametrize('fault',['missing','lease','birth','worker'])
def test_retained_receipt_cannot_be_replaced_or_recreated(taps,fault):
    driver,value,state,_,_,_,_=taps;ready=driver.apply(value['id'])
    name=value['items'][0]['spec']['tap']['name'];proof=state['proofs'][name]
    if fault=='missing':state['proofs'].pop(name)
    elif fault=='lease':proof['retention']['lease_token']='f'*32
    elif fault=='birth':proof['retention']['birth']['link']['ifindex']+=1
    else:proof['worker_reference_sha256']='f'*64
    count=len(state['creates'])
    with pytest.raises(Conflict,match='missing or replaced'):driver.apply(value['id'])
    assert driver.read(value['id'])==ready and len(state['creates'])==count


def test_postcheckpoint_conflict_stops_before_provider_create(taps,monkeypatch):
    driver,value,state,_,_,_,_=taps;save=driver._save
    def changed(current):
        save(current)
        if current['phase']=='creating':state['writer']=True
    monkeypatch.setattr(driver,'_save',changed)
    with pytest.raises(RuntimeErrorBase):driver.apply(value['id'])
    assert state['creates']==[] and driver.read(value['id'])['phase']=='creating'


def test_tap_set_independently_protects_cleanup_and_container_admission(taps):
    from test_vm_tap_reservations import native
    driver,value,_,_,_,_,_=taps
    driver.journal.db.execute('DELETE FROM vm_definition_intents')
    driver.journal.db.execute('DELETE FROM resources')
    inventory=cleanup_inventory(driver.journal,value['birth']['lab_id'])
    assert inventory['nodes']==[value['birth']['node_id']] and inventory['blocked']==['vm_tap_intents']
    request=native();request.update(lab_id=value['birth']['lab_id'],node_id=value['birth']['node_id'])
    with pytest.raises(Conflict,match='reserved by VM'):driver.journal.submit(request)


@pytest.mark.parametrize('fence',['closing','closed','held','applying'])
def test_lab_fence_blocks_tap_creates_and_replay(taps,fence):
    from test_vm_definition_fences import install_fence
    driver,value,state,_,_,_,_=taps
    install_fence(driver.journal,fence)
    with pytest.raises(Conflict):driver.apply(value['id'])
    with pytest.raises(Conflict):driver.prepare(value['id'],value['context'],[i['spec']['tap'] for i in value['items']])
    assert state['creates']==[] and driver.read(value['id'])==value


def test_first_receipt_changed_at_checkpoint_prevents_next_allocation(taps,monkeypatch):
    driver,value,state,_,_,_,_=taps;save=driver._save
    def replaced(current):
        save(current)
        if current['items'][0]['phase']=='retained':
            name=current['items'][0]['spec']['tap']['name']
            state['proofs'][name]['retention']['retained_proof']['link']['address']='02:00:00:00:00:aa'
    monkeypatch.setattr(driver,'_save',replaced)
    with pytest.raises(Conflict,match='missing or replaced'):driver.apply(value['id'])
    assert len(state['creates'])==1
    assert driver.read(value['id'])['items'][0]['phase']=='create_requested'


def test_second_vm_cannot_claim_same_ifindices_with_different_names(taps):
    from dnlab_runtime.libvirt_xml import OWNER_NS
    driver,value,state,_,definitions,_,_=taps
    other=deepcopy(value['birth'])
    other.update(uuid='22345678-1234-4234-8234-123456789abc',node_id='other-vd',
        creator_operation_id='e'*32,nonce='f'*32)
    root=ET.fromstring(definitions.read(value['id'])['xml'])
    root.find('uuid').text=other['uuid'];root.find('name').text='other-tap-vm'
    owner=root.find('metadata/{'+OWNER_NS+'}owner')
    for key in ('node_id','creator_operation_id','nonce'):owner.set(key,other[key])
    requests=[deepcopy(item['spec']['tap']) for item in value['items']]
    for index,(target,request) in enumerate(zip(root.findall('devices/interface/target'),requests)):
        request.update(name='dt-other'+str(index),nonce=str(index+5)*32);target.set('dev',request['name'])
    for disk in root.findall('devices/disk/source'):disk.set('file',disk.get('file')+'.other')
    definitions.prepare('other-tap-vm',other,ET.tostring(root,encoding='unicode'))
    before=[tuple(row) for row in driver.journal.db.execute('SELECT * FROM vm_tap_ifindices ORDER BY ifindex')]
    with pytest.raises(Conflict,match='ifindex already reserved'):
        driver.prepare(other['creator_operation_id'],value['context'],requests)
    assert [tuple(row) for row in driver.journal.db.execute('SELECT * FROM vm_tap_ifindices ORDER BY ifindex')]==before
    assert driver.journal.db.execute('SELECT count(*) FROM vm_tap_intents').fetchone()[0]==1
    assert state['creates']==[]


def test_changed_retry_request_cannot_rewrite_original_plan(taps):
    driver,value,state,_,_,_,_=taps
    requests=[deepcopy(item['spec']['tap']) for item in value['items']];requests[0]['ifindex']+=50
    with pytest.raises(Conflict,match='request differs'):driver.prepare(value['id'],value['context'],requests)
    assert driver.read(value['id'])==value and state['creates']==[]


@pytest.mark.parametrize('fault',['parent','claim','owner'])
def test_orphaned_or_changed_ifindex_claim_blocks_cleanup(taps,fault):
    driver,_,state,_,_,_,_=taps
    if fault=='parent':driver.journal.db.execute('DELETE FROM vm_tap_intents')
    elif fault=='claim':driver.journal.db.execute('DELETE FROM vm_tap_ifindices')
    else:driver.journal.db.execute("UPDATE vm_tap_ifindices SET operation_id='foreign'")
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict,match='ifindex reservation lineage'):cleanup_inventory(driver.journal,'lab')
    assert driver.journal.db.total_changes==before and state['creates']==[]


@pytest.mark.parametrize('fault',['up','master','device','initial-owner'])
def test_invalid_kernel_birth_is_not_accepted_before_next_create(taps,monkeypatch,fault):
    driver,value,state,_,_,_,_=taps;create=driver.endpoints.create
    def bad(item,operation):
        proof=create(item,operation)
        born=proof['retention']['birth']
        if fault=='up':born['link']['flags'].append('UP')
        elif fault=='master':born['link']['master']='foreign'
        elif fault=='device':born['device']['rdev']=0
        else:born['link']['linkinfo']['info_data']['user']=1001
        return proof
    monkeypatch.setattr(driver.endpoints,'create',bad)
    with pytest.raises(RuntimeErrorBase):driver.apply(value['id'])
    assert len(state['creates'])==1 and driver.read(value['id'])['items'][0]['phase']=='create_requested'
