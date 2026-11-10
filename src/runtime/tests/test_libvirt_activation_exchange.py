"""Completed exchange on private files with a synthetic acknowledged live daemon."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_activation_exchange import CompletedExchangeObserver
from dnlab_runtime.libvirt_activation_lineage import ActivationFiles
from dnlab_runtime.libvirt_activation_services import ActivationServices
from dnlab_runtime.libvirt_service_observer import ServiceGenerationObserver
from dnlab_runtime.manifest import Conflict,fingerprint
from tools.libvirt_service_units import observe_service_files
from test_libvirt_activation_lineage import activation_files,successor,configured,install,request_profile
from test_libvirt_service_observer import service


@pytest.fixture
def active_exchange(activation_files,service):
    lineage,_,source,driver,adapter,root=activation_files
    _,make=service
    specs=steps(source['profile']);items=[dict(spec=spec,nonce='b'*32,phase='prepared',proof=None) for spec in specs]
    reload=dict(activation_id='activation',nonce='b'*32,spec_sha256=fingerprint(specs[0]),identity={'synthetic_reload':True})
    items[0].update(phase='confirmed',proof=reload)
    unit=specs[1]['unit'];_,row,receipt,_,socket=make(specs[1]['role'])
    row['files']={item['spec']['path']:deepcopy(item['proof']) for item in source['items'] if item['spec']['kind']=='file'}
    row['unit']['fragment_sha256']=source['profile']['files']['/etc/systemd/system/'+unit]['sha256']
    row['process']['boot_id']=source['context']['boot_id'];row['process']['namespaces']=deepcopy(source['context']['namespaces'])
    receipt['identity']['service']=deepcopy(row);receipt['spec_sha256']=fingerprint(specs[1])
    items[1].update(phase='confirmed',proof=receipt)
    value=dict(id='activation',installation=deepcopy(source),installation_sha256=fingerprint(source),items=items)
    names=source['profile']['service_order']+source['profile']['forbidden_vendor_activation']
    inventory=dict(units={name:dict(active_state='inactive',job_id=0) for name in names},
        dedicated_uid=source['profile']['session']['uid'],processes=[{key:deepcopy(row['process'][key]) for key in ('pid','uids','gids','groups')}])
    inventory['units'][unit]['active_state']='active'
    receipts={spec['key']:None for spec in specs};receipts[specs[0]['key']]=reload;receipts[unit]=receipt
    state=dict(activation=value,inventory=inventory,receipts=receipts)
    def generation(value,item,proof):
        return ServiceGenerationObserver(source,item,value['id'],proof,socket_path=socket,
            command_sha256='c'*64,read=lambda:deepcopy(row))
    services=ActivationServices(source,generation_observer=generation)
    def resources(reference):
        return dict(revision_sha256=fingerprint(reference),unchanged_sha256=reference['plan']['unchanged_sha256'],context=deepcopy(source['context']))
    observer=CompletedExchangeObserver(adapter.swap,lineage.reference,activation_id='activation',resources=resources,
        services=services,state=lambda:deepcopy(state))
    files=ActivationFiles(lineage,adapter.files,revision_window=driver.window,preflight=adapter.preflight,completed_exchange=observer)
    return files,observer,state,row,driver,adapter,root,source


def test_acknowledged_active_service_can_observe_completed_exchange_without_inactive_claim(active_exchange,monkeypatch):
    files,observer,_,_,driver,adapter,_,source=active_exchange;preflight=adapter.preflight
    def active(value):return dict(preflight(value),services_inactive=False)
    monkeypatch.setattr(adapter,'preflight',active)
    with pytest.raises(Conflict,match='inactive session preflight'):driver.effective(observer.reference['id'])
    monkeypatch.setattr(driver.window,'observe',lambda:{})
    before=driver.journal.db.total_changes
    assert len(observe_service_files(files,source))==7
    assert driver.journal.db.total_changes==before


def test_reader_never_calls_mutation_sync_or_recovery(active_exchange,monkeypatch):
    files,observer,_,_,driver,adapter,_,source=active_exchange
    def forbidden(*a,**kw):pytest.fail('readonly exchange reached mutation')
    for name in ('_rename','_sync','execute','recover'):monkeypatch.setattr(adapter.swap,name,forbidden)
    for name in ('stage','recover'):monkeypatch.setattr(adapter.staging,name,forbidden)
    for name in ('create','recover'):monkeypatch.setattr(adapter.files,name,forbidden)
    before=driver.journal.db.total_changes
    assert observer.observe()==observer.reference['proof']
    assert len(observe_service_files(files,source))==7 and driver.journal.db.total_changes==before


def test_foreign_process_census_blocks_before_exchange_read(active_exchange,monkeypatch):
    _,observer,state,_,_,adapter,_,_=active_exchange
    state['inventory']['processes'].append(dict(pid=9999,uids=[1001]*4,gids=[1002]*4,groups=[]))
    monkeypatch.setattr(adapter.swap,'_read',lambda *a:pytest.fail('foreign census reached exchange'))
    with pytest.raises(Conflict,match='foreign, missing'):observer.observe()


def test_replaced_backup_is_preserved_and_rejected(active_exchange):
    _,observer,_,_,_,_,root,_=active_exchange
    path=root/observer.reference['backup'].lstrip('/');path.write_text('foreign preserve')
    with pytest.raises(Conflict):observer.observe()
    assert path.read_text()=='foreign preserve'


def test_resource_preflight_cannot_be_skipped(active_exchange,monkeypatch):
    _,observer,_,_,_,_,_,_=active_exchange
    monkeypatch.setattr(observer,'resources',lambda value:{})
    with pytest.raises(Conflict,match='resource preflight'):observer.observe()


def test_original_command_acknowledgement_is_required(active_exchange):
    _,observer,state,_,_,_,_,_=active_exchange
    first=state['activation']['items'][1]
    first.update(phase='prepared',proof=None)
    with pytest.raises(Conflict,match='original ordered request'):observer.observe()
