"""Synthetic procfs; no real process, Docker or service operation."""
from copy import deepcopy
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_activity import ImageBuildActivity, builder_reason
from image_build_observation import ImageBuildObservation
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
    inspected=dict(Id=cid,Image=image,RestartCount=0,State=dict(Pid=44,Running=True,Status='running',StartedAt='original'))
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
