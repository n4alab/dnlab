"""Synthetic procfs; no real process, Docker or service operation."""
from copy import deepcopy
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_activity import ActivityChanged, ImageBuildActivity, builder_reason
from image_build_observation import ImageBuildObservation
from image_build_healthcheck import KIND as HEALTHCHECK_KIND
from cleanup_container_observer import config_digest
from test_image_build_observation import observation
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def activity(tmp_path):
    proc=tmp_path/'proc';proc.mkdir();(proc/'self').symlink_to(str(os.getpid()))
    own=proc/str(os.getpid());(own/'ns').mkdir(parents=True)
    context=dict(host_id='master',boot_id='synthetic',namespaces={})
    for name in ('pid','mnt','net','user'):
        path=own/'ns'/name;path.write_bytes(b'namespace');info=path.stat()
        context['namespaces'][name]=dict(device=info.st_dev,inode=info.st_ino)
    boot=proc/'sys/kernel/random/boot_id';boot.parent.mkdir(parents=True);boot.write_text('synthetic\n')
    cid='a'*64;image='sha256:'+'b'*64
    inspected=dict(Id=cid,Image=image,RestartCount=0,Config={},HostConfig={},Mounts=[],Path='python3',Args=['api.py'],
                   State=dict(Pid=44,Running=True,Status='running',StartedAt='original'))
    state=dict(inspect=inspected,context=deepcopy(context))
    def add(pid,argv,*,container=False,cwd='/outside',ticks=55):
        root=proc/str(pid);root.mkdir(exist_ok=True)
        (root/'stat').write_bytes(str(pid).encode()+b' (synthetic process) S 1 '+b'0 '*17+str(ticks).encode()+b'\n')
        (root/'cmdline').write_bytes(b'\0'.join(os.fsencode(value) for value in argv)+b'\0' if argv else b'')
        (root/'cgroup').write_text('0::/docker-'+cid+'.scope\n' if container else '0::/unrelated\n')
        p=root/'cwd'
        if p.is_symlink():p.unlink()
        p.symlink_to(cwd)
    add(os.getpid(),['python3','inert.py']);add(44,['python3','/opt/dnlab-image-build/api.py'],container=True)
    class API:
        def inspect(self,original):assert original==cid;return deepcopy(state['inspect'])
    info=proc.stat()
    driver=ImageBuildActivity(API(),context=context,read_context=lambda:deepcopy(state['context']),
        proc_identity=dict(device=info.st_dev,inode=info.st_ino),roots=['/opt/vrnetlab','/image-workspace'],proc_root=str(proc))
    value=dict(actor=dict(container_id=cid,image_id=image,context_sha256=fingerprint(context)),scope=dict(host_id='master',boot_id='synthetic'))
    return driver,value,state,add,proc


def test_original_api_only_and_stopped_container_empty_are_reported(activity):
    driver,value,state,_,proc=activity
    assert driver(value)==dict(container_pids=[44],host_build_processes=[],complete=True)
    root=proc/'44'
    for path in root.iterdir():path.unlink()
    root.rmdir();state['inspect']['State'].update(Pid=0,Running=False,Status='exited')
    assert driver(value)==dict(container_pids=[],host_build_processes=[],complete=True)


def test_extra_container_child_and_orphan_are_never_hidden(activity):
    driver,value,state,add,_=activity;add(45,['unknown-child'],container=True)
    assert driver(value)['container_pids']==[44,45]
    state['inspect']['State'].update(Pid=0,Running=False,Status='exited')
    assert driver(value)['container_pids']==[44,45]


@pytest.mark.parametrize('argv,cwd',[
    (['make','version-test'],'/opt/vrnetlab/cisco'),
    (['make','-C','../opt/vrnetlab/cisco','all'],'/tmp'),
    (['python3','-B','/opt/dnlab-image-build/build_image.py','n9kv'],'/outside'),
    (['docker','--host','unix:///socket','build','.'],'/outside'),
    (['docker','buildx','--builder','local','build','.'],'/outside'),
    (['qemu-img','convert','../opt/vrnetlab/disk','target'],'/tmp')])
def test_recognized_host_builds_are_reported_without_raw_arguments(activity,argv,cwd):
    driver,value,_,add,_=activity;add(88,argv,cwd=cwd)
    proof=driver(value)
    assert proof['container_pids']==[44] and len(proof['host_build_processes'])==1
    row=proof['host_build_processes'][0]
    assert row['pid']==88 and row['reason'] and 'argv' not in row


def test_unrelated_payload_and_runtime_overlay_formatter_are_not_build_claims(activity):
    driver,value,_,add,_=activity
    add(80,['python3','-c','print("build_image.py make docker build")'])
    add(81,['qemu-img','create','-b','/var/lib/dnlab-vm-templates/base','/proc/self/fd/7'],cwd='/')
    assert driver(value)['host_build_processes']==[]


@pytest.mark.parametrize('fault',['context','boot','missing-field','container','scope'])
def test_incomplete_or_foreign_observation_refuses(activity,fault):
    driver,value,state,_,proc=activity
    if fault=='context':state['context']['namespaces']['net']['inode']+=1
    elif fault=='boot':(proc/'sys/kernel/random/boot_id').write_text('other')
    elif fault=='missing-field':(proc/'44/cgroup').unlink()
    elif fault=='container':state['inspect']['Id']='c'*64
    else:value['scope']['boot_id']='other'
    with pytest.raises((TemplateError,RuntimeError)):driver(value)


def test_process_added_between_passes_prevents_complete_snapshot(activity,monkeypatch):
    driver,value,_,add,_=activity;scan=driver._scan;calls=[]
    def changing(cid):
        result=scan(cid)
        if not calls:add(89,['make'],cwd='/opt/vrnetlab');calls.append(True)
        return result
    monkeypatch.setattr(driver,'_scan',changing)
    with pytest.raises(TemplateError,match='between activity'):driver(value)


@pytest.mark.parametrize('argv',[
    ['docker','ps','--format','build'],['docker','run','example','docker','build'],
    ['python3','-c','build_image.py'],['make','unrelated-target']])
def test_classifier_does_not_search_arbitrary_payload_positions(argv):
    assert builder_reason(argv,'/unrelated',['/opt/vrnetlab']) is None


def test_native_activity_reader_composes_with_running_hold_observer(activity,observation):
    reader,_,processes,add,_=activity
    original,owner,_,profile=observation
    profile=deepcopy(profile);profile['context']=deepcopy(processes['context'])
    profile['actor']['context_sha256']=fingerprint(profile['context'])
    owner=deepcopy(owner);owner['actor']=deepcopy(profile['actor'])
    owner['scope']=dict(host_id=profile['context']['host_id'],boot_id=profile['context']['boot_id'])
    observer=ImageBuildObservation(original.api,profile,context=reader.read_context,query=original.query,
        binding=original.binding,ledger=original.ledger,activity=reader,exit_receipt=original.exit_receipt,
        startup=original.startup,process=original.process)
    assert observer(owner)['idle'] is True
    add(45,['unrecognized-child'],container=True)
    with pytest.raises(TemplateError,match='busy or ambiguous'):observer(owner)


def test_unrelated_argv_transition_is_recorded_without_becoming_a_gate_actor(activity,monkeypatch):
    driver,value,_,add,proc=activity;add(88,['python3','private-a'])
    original=os.read;changed=[]
    def read(fd,size):
        data=original(fd,size)
        path=os.readlink('/proc/self/fd/'+str(fd))
        if path==str(proc/'88'/'cmdline') and data and not changed:
            (proc/'88'/'cmdline').write_bytes(b'python3\0private-b\0');changed.append(True)
        return data
    monkeypatch.setattr(os,'read',read)
    assert driver(value)==dict(container_pids=[44],host_build_processes=[],complete=True)
    assert len(driver.diagnostics)==1
    diagnostic=driver.diagnostics[0]
    assert diagnostic['kind']=='unrelated-transition'
    assert diagnostic['pid']==88 and diagnostic['changed_fields']==['cmdline']
    assert diagnostic['original_container_member'] is False and diagnostic['original_builder_reason'] is None
    assert diagnostic['command_sha256']!=diagnostic['observed_command_sha256']
    assert diagnostic['observed_container_member'] is False and diagnostic['observed_builder_reason'] is None
    assert 'private-a' not in str(diagnostic) and 'private-b' not in str(diagnostic)


@pytest.mark.parametrize('before,after,cwd',[
    (['python3','private-a'],['python3','build_image.py'],'/outside'),
    (['python3','build_image.py'],['python3','private-b'],'/outside'),
    (['python3','private-a'],['make','-C','/opt/vrnetlab'],'/outside'),
    (['python3','private-a'],['qemu-img','commit','/image-workspace/disk'],'/outside')])
def test_builder_in_either_observation_refuses_transition(activity,monkeypatch,before,after,cwd):
    driver,value,_,add,proc=activity;add(88,before,cwd=cwd)
    original=os.read;changed=[]
    def read(fd,size):
        data=original(fd,size)
        if os.readlink('/proc/self/fd/'+str(fd))==str(proc/'88/cmdline') and data and not changed:
            (proc/'88/cmdline').write_bytes(b'\0'.join(os.fsencode(word) for word in after)+b'\0');changed.append(True)
        return data
    monkeypatch.setattr(os,'read',read)
    with pytest.raises(ActivityChanged):driver(value)
    assert driver.diagnostics[-1]['kind']=='candidate-conflict'


@pytest.mark.parametrize('initial_member',[False,True])
def test_container_membership_in_either_observation_refuses_transition(activity,monkeypatch,initial_member):
    driver,value,_,add,proc=activity;add(88,['unknown'],container=initial_member)
    original=os.read;changed=[]
    def read(fd,size):
        data=original(fd,size)
        if os.readlink('/proc/self/fd/'+str(fd))==str(proc/'88/cgroup') and data and not changed:
            group='0::/unrelated\n' if initial_member else '0::/docker-'+value['actor']['container_id']+'.scope\n'
            (proc/'88/cgroup').write_text(group);changed.append(True)
        return data
    monkeypatch.setattr(os,'read',read)
    with pytest.raises(ActivityChanged):driver(value)
    diagnostic=driver.diagnostics[-1]
    assert diagnostic['original_container_member'] is initial_member
    assert diagnostic['observed_container_member'] is not initial_member


def test_non_candidate_pid_generation_change_is_not_an_unrelated_transition(activity,monkeypatch):
    driver,value,_,add,proc=activity;add(88,['unknown'])
    original=os.read;changed=[]
    def read(fd,size):
        data=original(fd,size)
        if os.readlink('/proc/self/fd/'+str(fd))==str(proc/'88/stat') and data and not changed:
            add(88,['unknown'],ticks=56);changed.append(True)
        return data
    monkeypatch.setattr(os,'read',read)
    with pytest.raises(ActivityChanged) as error:driver(value)
    assert error.value.diagnostic['changed_fields']==['stat']


def test_cwd_moving_into_build_root_refuses_even_without_argv_change(activity,monkeypatch):
    driver,value,_,add,proc=activity;add(88,['make'],cwd='/outside')
    original=os.readlink;changed=[]
    def readlink(path,**kwargs):
        result=original(path,**kwargs)
        if path=='cwd' and result=='/outside' and not changed:
            (proc/'88/cwd').unlink();(proc/'88/cwd').symlink_to('/opt/vrnetlab');changed.append(True)
        return result
    monkeypatch.setattr(os,'readlink',readlink)
    with pytest.raises(ActivityChanged) as error:driver(value)
    assert error.value.diagnostic['observed_builder_reason']=='scoped-make'


def test_only_qualified_healthcheck_can_finish_between_census_passes(activity):
    driver,value,_,add,proc=activity;add(45,['synthetic-healthcheck'],container=True)
    def qualify(owner,inspected,rows):
        assert owner==value
        proof=dict(kind=HEALTHCHECK_KIND,container_id=inspected['Id'],image_id=inspected['Image'],
            config_sha256=config_digest(inspected),generation_sha256='1'*64,evidence_sha256='2'*64,
            main_process=rows[0],processes=rows[1:])
        for path in (proc/'45').iterdir():path.unlink()
        (proc/'45').rmdir()
        return proof
    driver.qualify_healthcheck=qualify
    assert driver(value)==dict(container_pids=[44],host_build_processes=[],complete=True)
    assert driver.diagnostics[0]['kind']=='healthcheck-candidates'
    assert driver.diagnostics[0]['processes'][0]['pid']==45
    assert driver.diagnostics[1]['kind']==HEALTHCHECK_KIND


@pytest.mark.parametrize('fault',['kind','main','processes','container','generation'])
def test_incomplete_healthcheck_proof_cannot_hide_container_process(activity,fault):
    driver,value,_,add,_=activity;add(45,['synthetic-healthcheck'],container=True)
    def qualify(owner,inspected,rows):
        proof=dict(kind=HEALTHCHECK_KIND,container_id=inspected['Id'],image_id=inspected['Image'],
            config_sha256=config_digest(inspected),generation_sha256='1'*64,evidence_sha256='2'*64,
            main_process=rows[0],processes=rows[1:])
        if fault=='kind':proof['kind']='generic-shell'
        elif fault=='main':proof['main_process']=rows[1]
        elif fault=='processes':proof['processes']=[]
        elif fault=='container':proof['container_id']='0'*64
        else:proof['generation_sha256']='unknown'
        return proof
    driver.qualify_healthcheck=qualify
    with pytest.raises(TemplateError,match='healthcheck evidence'):driver(value)
    assert len(driver.diagnostics)==1
    assert driver.diagnostics[0]['kind']=='healthcheck-candidates'
    assert driver.diagnostics[0]['processes'][0]['pid']==45


@pytest.mark.parametrize('duplicate',[False,True])
def test_rejected_healthcheck_candidates_are_saved_before_qualification(activity,duplicate):
    driver,value,state,add,_=activity;add(45,['unknown-private-command'],container=True)
    if duplicate:add(46,['unknown-private-command'],container=True)
    persisted=[];driver.record=lambda proof:persisted.append(deepcopy(proof))
    def qualify(owner,inspected,rows):
        assert len(persisted)==1
        assert persisted[0]['main_process']==rows[0]
        assert persisted[0]['processes']==rows[1:]
        raise TemplateError('only one exact configured shell/Python healthcheck eligible')
    driver.qualify_healthcheck=qualify
    with pytest.raises(TemplateError,match='only one exact'):driver(value)
    assert persisted==driver.diagnostics
    assert len(persisted[0]['processes'])==(2 if duplicate else 1)
    assert persisted[0]['generation']['Pid']==state['inspect']['State']['Pid']
    assert 'unknown-private-command' not in str(persisted)


def test_candidate_writer_failure_prevents_healthcheck_exemption(activity):
    driver,value,_,add,_=activity;add(45,['candidate'],container=True)
    called=[]
    def fail(proof):raise OSError('diagnostic write failed')
    driver.record=fail
    driver.qualify_healthcheck=lambda *args:called.append(True)
    with pytest.raises(OSError,match='diagnostic write failed'):driver(value)
    assert called==[]
