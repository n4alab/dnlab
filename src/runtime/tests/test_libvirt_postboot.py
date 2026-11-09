"""Only synthetic history/observations and a temporary SQLite journal."""
from copy import deepcopy
import os

import pytest

from dnlab_runtime.libvirt_account_commands import command_plan
from dnlab_runtime.libvirt_account_history import HistoricalAccountCreation
from dnlab_runtime.libvirt_postboot import PostBootQualification,plan
from dnlab_runtime.libvirt_provisioning import account_request
from dnlab_runtime.manifest import Conflict,canonical,fingerprint
from test_libvirt_install import install,request_profile


@pytest.fixture
def postboot(install):
    installer,_,prepared,_=install;original=installer.apply(prepared['id']);journal=installer.journal
    namespaces={name:dict(device=1,inode=index+10) for index,name in enumerate(('pid','mnt','net','user'))}
    original['context']=dict(host_id='master',boot_id='old-synthetic-boot',namespaces=namespaces)
    profile=original['profile']
    original['prerequisites']=dict(profile_sha256=profile['profile_sha256'],packages='unchanged-synthetic-packages',
        provisioning_window_sha256='e'*64,services=dict(dedicated_uid=profile['session']['uid'],processes=[],
        units={name:dict(active_state='inactive',job_id=0) for name in profile['service_order']+profile['forbidden_vendor_activation']}))
    binaries={role:dict(path='/usr/sbin/'+role,sha256='a'*64) for role in ('useradd','groupadd')}
    worker_profile=dict(python=dict(path='/synthetic/python',sha256='b'*64),worker=dict(path='/synthetic/worker',sha256='c'*64))
    journal.db.executescript('''
        CREATE TABLE libvirt_install_account_births (operation_id TEXT,nonce TEXT,payload TEXT,fingerprint TEXT);
        CREATE TABLE libvirt_account_commands (request_sha256 TEXT,payload TEXT,fingerprint TEXT);
        CREATE TABLE libvirt_account_workers (token TEXT,payload TEXT,fingerprint TEXT);
        CREATE TABLE libvirt_account_processes (token TEXT,payload TEXT,fingerprint TEXT);
    ''')
    seeded=[]
    for index,item in enumerate(original['items'][:2]):
        request=account_request(item,original['id']);item['proof']['identity']=deepcopy(request['expected'])
        command=command_plan(request,binaries)
        reference=dict(token=str(index+1)*32,command_sha256=fingerprint(command),process_record=dict(
            boot_id=original['context']['boot_id'],pid=123+index,start_ticks=456,uid=0,gid=0,
            executable_sha256=worker_profile['python']['sha256'],namespace_sha256=fingerprint(namespaces)))
        outcome=dict(reference=reference,exit_code=0,stdout='',stderr='')
        prerequisites=deepcopy(original['prerequisites']);prerequisites.pop('provisioning_window_sha256')
        rows=[('libvirt_install_account_births',(original['id'],item['nonce']),dict(request=request,phase='created',
                window_sha256='e'*64,completion=dict(request_sha256=fingerprint(request),exit_code=0,identity=request['expected']))),
            ('libvirt_account_commands',(fingerprint(request),),dict(request=request,command=command,phase='completed',reference=reference,
                outcome=outcome,preflight=dict(qualified=True,command_sha256=fingerprint(command),
                    context_sha256=fingerprint(original['context']),inputs_sha256=fingerprint(prerequisites)))),
            ('libvirt_account_workers',(reference['token'],),dict(token=reference['token'],reference=reference,
                command=command,profile=worker_profile,phase='completed',outcome=outcome)),
            ('libvirt_account_processes',(reference['token'],),dict(reference=reference,command_sha256=fingerprint(command),
                snapshot=dict(record=reference['process_record'],namespaces=namespaces,proc_identity=[1,99+index],cmdline_sha256='f'*64),
                exit=dict(exit_code=0,process_record=reference['process_record'])))]
        for table,keys,value in rows:
            slots=','.join('?' for _ in range(len(keys)+2))
            journal.db.execute('INSERT INTO '+table+' VALUES('+slots+')',(*keys,canonical(value),fingerprint(value)))
            seeded.append((table,keys,deepcopy(value)))
    with journal.transaction():installer._save(original)
    current=deepcopy(original['context']);current['boot_id']='new-synthetic-boot'
    history=HistoricalAccountCreation(journal,installation=original,worker_profile=worker_profile,binaries=binaries,source_reader=installer.read)
    layout=plan(original,current)
    prerequisites=deepcopy(original['prerequisites']);prerequisites.pop('provisioning_window_sha256')
    observed=dict(context=current,prerequisites=prerequisites,
        persistent={item['spec']['key']:deepcopy(item['proof']) for item in original['items'] if item['spec']['key'] in layout['persistent']},
        volatile={key:dict(state='absent') for key in layout['volatile']})
    driver=PostBootQualification(journal,source_reader=installer.read,observer=lambda value:deepcopy(observed),account_history=history)
    value=driver.prepare('postboot-check',original,current)
    return driver,value,installer,history,observed,seeded


def test_separate_persistent_qualification_preserves_source_and_blocks_revision(postboot):
    driver,value,installer,_,_,_=postboot;original=deepcopy(installer.read(value['installation']['id']))
    receipt=driver.qualify_persistent(value['id'])
    assert receipt['qualified'] is False and receipt['pending_volatile']==value['plan']['volatile']
    assert len(receipt['pending_volatile'])==2
    assert installer.read(original['id'])==original
    assert driver.read(value['id'])['phase']=='persistent_qualified'
    with pytest.raises(Conflict,match='volatile'):driver.require_revision_ready(value['id'])
    before=driver.journal.db.total_changes
    assert driver.qualify_persistent(value['id'])==receipt
    assert driver.prepare(value['id'],original,value['context'])==driver.read(value['id'])
    assert driver.journal.db.total_changes==before


def test_historical_account_receipt_never_observes_a_current_process(postboot,monkeypatch):
    driver,value,_,history,_,_=postboot
    # Acquire this fixture's original journal gate before forbidding new opens.
    # The reader then reenters that same gate without opening another lock FD.
    with driver.journal.execution_lock:
        with monkeypatch.context() as patch:
            patch.setattr(os,'pidfd_open',lambda *a:pytest.fail('history cannot adopt current PID'))
            patch.setattr(os,'open',lambda *a,**kw:pytest.fail('history cannot open procfs or host files'))
            driver.journal.db.execute('PRAGMA query_only=ON')
            before=driver.journal.db.total_changes
            result=history(value['installation']['items'][1])
            assert result['kind']=='historical-account-creation-v1'
            assert result['creation_context_sha256']==fingerprint(value['installation']['context'])
            assert result['creation_context_sha256']!=fingerprint(value['context'])
            assert driver.journal.db.total_changes==before


@pytest.mark.parametrize('fault',['persistent','static','context','volatile-reuse','active-service','missing-volatile'])
def test_foreign_missing_or_unqualified_resources_never_become_ready(postboot,fault):
    driver,value,_,_,observed,_=postboot
    if fault=='persistent':observed['persistent'][next(iter(observed['persistent']))]={'foreign':'preserve'}
    elif fault=='static':observed['prerequisites']['packages']='changed'
    elif fault=='context':observed['context']['boot_id']='third-synthetic-boot'
    elif fault=='volatile-reuse':observed['volatile'][next(iter(observed['volatile']))]=dict(state='qualified',proof='old-kernel-identity')
    elif fault=='active-service':next(iter(observed['prerequisites']['services']['units'].values()))['active_state']='active'
    else:observed['volatile'].pop(next(iter(observed['volatile'])))
    with pytest.raises(Conflict):driver.qualify_persistent(value['id'])
    assert driver.read(value['id'])['phase']=='prepared'


@pytest.mark.parametrize('table',['libvirt_install_account_births','libvirt_account_commands','libvirt_account_workers','libvirt_account_processes'])
def test_incomplete_or_changed_historical_chain_is_refused(postboot,table):
    driver,value,_,history,_,rows=postboot
    table,keys,record=next(row for row in rows if row[0]==table)
    if table=='libvirt_install_account_births':record['phase']='create_requested'
    elif table=='libvirt_account_commands':record['outcome']['exit_code']=1
    elif table=='libvirt_account_workers':record['reference']['token']='f'*32
    else:record['exit']=None
    where='operation_id=? AND nonce=?' if table=='libvirt_install_account_births' else 'request_sha256=?' if table=='libvirt_account_commands' else 'token=?'
    driver.journal.db.execute('UPDATE '+table+' SET payload=?,fingerprint=? WHERE '+where,(canonical(record),fingerprint(record),*keys))
    with pytest.raises(Conflict):history(value['installation']['items'][0])
    assert driver.read(value['id'])['phase']=='prepared'


def test_namespace_change_and_source_change_during_observation_are_refused(postboot,monkeypatch):
    driver,value,installer,_,observed,_=postboot;calls=[]
    def changed(current):
        calls.append(1)
        result=deepcopy(observed)
        if len(calls)==2:result['context']['namespaces']['pid']['inode']+=1
        return result
    monkeypatch.setattr(driver,'observer',changed)
    with pytest.raises(Conflict):driver.qualify_persistent(value['id'])
    assert driver.read(value['id'])['phase']=='prepared'
    source=deepcopy(value['installation']);source['context']['boot_id']='changed-original'
    with driver.journal.transaction():installer._save(source)
    with pytest.raises(Conflict,match='original installation'):driver.qualify_persistent(value['id'])


def test_reopen_validates_saved_observation_and_history(postboot):
    driver,value,_,_,_,_=postboot;driver.qualify_persistent(value['id'])
    stored=driver.read(value['id']);stored['receipt']['account_history'].clear()
    driver.journal.db.execute('UPDATE libvirt_postboot_qualifications SET payload=?,fingerprint=? WHERE id=?',
        (canonical(stored),fingerprint(stored),value['id']))
    with pytest.raises(Conflict,match='historical account inventory'):driver.read(value['id'])
