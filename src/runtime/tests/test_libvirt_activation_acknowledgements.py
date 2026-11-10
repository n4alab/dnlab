"""Temporary metadata journal, synthetic original monitor and daemon proofs."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_activation_acknowledgements import ActivationAcknowledgements
from dnlab_runtime.libvirt_activation_commands import command_plan
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_service_observer import service,install,request_profile


@pytest.fixture
def acknowledgements(service,install):
    source,make=service;source=deepcopy(source);source['request']['activation_policy']='requisite-after-v1'
    source['profile']=render_profile(**source['request'])
    for item in source['items']:
        if item['spec']['kind']=='file':
            item['spec'].update(source['profile']['files'][item['spec']['path']]);item['proof']['spec_sha256']=fingerprint(item['spec'])
    items=[dict(spec=spec,nonce=str(index+1)*32,phase='prepared',proof=None) for index,spec in enumerate(steps(source['profile']))]
    item=items[1];item['phase']='requested'
    value=dict(id='activation',installation=source,installation_sha256=fingerprint(source),items=items)
    binary=dict(path='/usr/bin/systemctl',sha256='b'*64);state=dict(command=None,intent=None,valid=True,reads=[],lost=False,inputs='c'*64)
    class Monitor:
        def verify(self,reference,request):return state['valid']
        def read_original(self,reference,request):
            state['reads'].append(deepcopy(reference))
            if state['lost']:raise OSError('synthetic original monitor response lost')
            return deepcopy(state['witness'])
    agreement=dict(operation_id='activation',context=deepcopy(source['context']),targets=[spec['key'] for spec in steps(source['profile'])],nonce='d'*32)
    window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    def preflight(request,receipt):
        return dict(qualified=True,installation_sha256=fingerprint(source),context_sha256=fingerprint(source['context']),resources_sha256=state['inputs'])
    journal=install[0].journal
    ledger=ActivationAcknowledgements(journal,binary=binary,activation_reader=lambda operation:deepcopy(value),
        command_reader=lambda item,op:deepcopy(state['command']),command_intent=lambda item,op:deepcopy(state['intent']),
        monitor=Monitor(),preflight=preflight,window=window)
    request,_=ledger._request(item,'activation')
    reference=dict(kind='original-activation-monitor-v1',token='e'*32,request_sha256=fingerprint(request),context_sha256=fingerprint(source['context']))
    _,row,_,_,_=make(item['spec']['role'])
    row['files']={i['spec']['path']:deepcopy(i['proof']) for i in source['items'] if i['spec']['kind']=='file'}
    row['unit']['fragment_sha256']=source['profile']['files']['/etc/systemd/system/'+item['spec']['unit']]['sha256']
    state['witness']=dict(request_sha256=fingerprint(request),monitor_sha256=fingerprint(reference),service=row)
    def complete():
        state['intent']={'original':'command intent'}
        state['command']=dict(sha256=fingerprint(command_plan(source,item,'activation',binary)),exit_code=0,process_reference_sha256='f'*64)
    return ledger,item,reference,state,complete,agreement


def test_monitor_registered_before_command_and_original_receipt_readonly(acknowledgements,monkeypatch):
    ledger,item,reference,state,complete,window=acknowledgements
    prepared=ledger.prepare(item,'activation',reference)
    assert ledger.prepare(item,'activation',reference)==prepared and state['reads']==[]
    complete();receipt=ledger.qualify(item,'activation')
    monkeypatch.setattr(ledger,'preflight',lambda *a:pytest.fail('original receipt recursed into resources'))
    before=ledger.journal.db.total_changes
    assert ledger.original_receipt(item,'activation')==receipt and ledger.journal.db.total_changes==before
    assert receipt['identity']['command']==state['command']


def test_command_intent_already_exists_cannot_register_monitor(acknowledgements):
    ledger,item,reference,state,_,_=acknowledgements;state['intent']={'already':'armed'}
    with pytest.raises(Conflict,match='before command intent'):ledger.prepare(item,'activation',reference)
    assert ledger.journal.db.execute('SELECT count(*) FROM libvirt_activation_acknowledgements').fetchone()[0]==0


def test_lost_monitor_response_recovers_same_reference_without_discovery(acknowledgements):
    ledger,item,reference,state,complete,_=acknowledgements
    ledger.prepare(item,'activation',reference);complete();state['lost']=True
    with pytest.raises(OSError,match='monitor response'):ledger.qualify(item,'activation')
    with pytest.raises(Conflict,match='requires recovery'):ledger.qualify(item,'activation')
    state['lost']=False;receipt=ledger.recover(item,'activation')
    assert ledger.original_receipt(item,'activation')==receipt
    assert all(entry==reference for entry in state['reads'])


@pytest.mark.parametrize('fault',['monitor','command','process','resources'])
def test_foreign_or_incomplete_proof_cannot_confirm(acknowledgements,fault):
    ledger,item,reference,state,complete,_=acknowledgements
    ledger.prepare(item,'activation',reference);complete()
    if fault=='monitor':state['valid']=False
    elif fault=='command':state['command']['sha256']='0'*64
    elif fault=='process':state['witness']['service']['process']['start_ticks']+=1;state['witness']['service']['process']['pidfd_alive']=False
    else:state['inputs']='0'*64
    with pytest.raises(Conflict):ledger.qualify(item,'activation')
    value,_=ledger._read(item,'activation') if fault!='monitor' else (None,None)
    if value is not None:assert value['phase']!='confirmed' and value['proof'] is None


def test_confirmed_generation_substitution_cannot_be_adopted(acknowledgements):
    ledger,item,reference,state,complete,_=acknowledgements
    ledger.prepare(item,'activation',reference);complete();ledger.qualify(item,'activation')
    state['witness']['service']['process']['start_ticks']+=1
    with pytest.raises(Conflict,match='generation changed'):ledger.original_receipt(item,'activation')


def test_lost_confirmation_reply_reuses_committed_receipt(acknowledgements,monkeypatch):
    ledger,item,reference,_,complete,_=acknowledgements;ledger.prepare(item,'activation',reference);complete();save=ledger._save
    def lost(value):
        save(value)
        if value['phase']=='confirmed':raise OSError('synthetic confirmation reply lost')
    monkeypatch.setattr(ledger,'_save',lost)
    with pytest.raises(OSError):ledger.qualify(item,'activation')
    before=ledger.journal.db.total_changes
    assert ledger.recover(item,'activation')==ledger.original_receipt(item,'activation')
    assert ledger.journal.db.total_changes==before
