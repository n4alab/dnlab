"""Real temporary job files, readonly; no image-build process or service."""
from copy import deepcopy
import json
import os
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_ledger import JobLedger, capture_ledger, identity
from image_build_observation import terminal_jobs_digest
from image_build_observation import ImageBuildObservation
from test_image_build_observation import observation, stop_receipt
from dnlab_runtime.image_build_hold import NO_RESTART
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def ledger(tmp_path):
    root=tmp_path/'state';root.mkdir(mode=0o755)
    jobs=root/'jobs';logs=root/'logs';jobs.mkdir(mode=0o755);logs.mkdir(mode=0o755)
    job=dict(id='a'*16,status='success',kind='synthetic',source_path='/never/follow/image.qcow2',with_persistence=True,
        generic_spec=dict(cpus=2),created_at='2026-11-16T10:00:00+00:00',started_at='2026-11-16T10:00:01+00:00',
        finished_at='2026-11-16T10:00:02+00:00',returncode=0,log=['original log'])
    payload={key:value for key,value in job.items() if key!='log'};payload['log_path']='/state/logs/'+job['id']+'.log'
    (jobs/(job['id']+'.json')).write_text(json.dumps(payload))
    (logs/(job['id']+'.log')).write_text('original log\n')
    context=dict(host_id='master',boot_id='synthetic');current=deepcopy(context)
    actor=dict(container_id='1'*64,image_id='sha256:'+'2'*64,config_sha256='3'*64,artifact_sha256='4'*64,
               process_sha256='5'*64,context_sha256=fingerprint(context))
    def capture():return capture_ledger(paths=dict(jobs=str(jobs),logs=str(logs)),
        identities=dict(jobs=identity(jobs.stat()),logs=identity(logs.stat())),container_log_dir='/state/logs',
        api_jobs=[job],original_actor=actor,context=context,read_context=lambda:deepcopy(current))
    receipt=capture()
    def make():return JobLedger(receipt,expected_sha256=fingerprint(receipt),read_context=lambda:deepcopy(current))
    value=dict(actor=actor,jobs_sha256=terminal_jobs_digest([job]))
    return make(),value,jobs,logs,receipt,make,capture,job,current


def test_original_metadata_logs_and_reopen_are_readonly(ledger):
    driver,value,jobs,logs,receipt,make,_,_,_=ledger
    before={str(p):p.read_bytes() for root in (jobs,logs) for p in root.iterdir()}
    expected=dict(ledger_sha256=fingerprint(receipt),jobs_sha256=value['jobs_sha256'])
    assert driver(value)==make()(value)==expected
    assert before=={str(p):p.read_bytes() for root in (jobs,logs) for p in root.iterdir()}


@pytest.mark.parametrize('fault',['append-log','missing-json','extra-json','replace-log','metadata','context','directory'])
def test_changed_original_ledger_never_becomes_an_accepted_baseline(ledger,fault):
    driver,value,jobs,logs,receipt,_,_,job,current=ledger
    old=deepcopy(receipt);path=logs/(job['id']+'.log')
    if fault=='append-log':path.write_text('changed history\n')
    elif fault=='missing-json':(jobs/(job['id']+'.json')).unlink()
    elif fault=='extra-json':(jobs/('b'*16+'.json')).write_text('{}')
    elif fault=='replace-log':
        raw=path.read_bytes();path.rename(logs.parent/'original-log');path.write_bytes(raw)
    elif fault=='metadata':
        p=jobs/(job['id']+'.json');data=json.loads(p.read_text());data['generic_spec']['cpus']=3;p.write_text(json.dumps(data))
    elif fault=='context':current['boot_id']='other-boot'
    else:jobs.rename(jobs.parent/'old-jobs');jobs.mkdir(mode=0o755)
    with pytest.raises((TemplateError,OSError)):driver(value)
    assert receipt==old


@pytest.mark.parametrize('kind',['symlink','fifo','hardlink'])
def test_unqualified_log_inode_is_refused_before_data_open(ledger,kind,monkeypatch):
    driver,value,_,logs,_,_,_,job,_=ledger;path=logs/(job['id']+'.log')
    original=logs.parent/'original-log';path.rename(original)
    if kind=='symlink':path.symlink_to(original)
    elif kind=='fifo':os.mkfifo(path)
    else:os.link(original,path)
    real_open=os.open
    def guarded(name,flags,*args,**kwargs):
        if name==path.name:assert flags&os.O_PATH
        return real_open(name,flags,*args,**kwargs)
    monkeypatch.setattr(os,'open',guarded)
    with pytest.raises(TemplateError,match='regular job ledger'):driver(value)


def test_explicit_original_empty_log_absence_is_preserved(ledger):
    _,value,_,logs,_,_,capture,job,current=ledger
    path=logs/(job['id']+'.log');path.unlink();job['log']=[]
    receipt=capture();driver=JobLedger(receipt,expected_sha256=fingerprint(receipt),read_context=lambda:deepcopy(current))
    assert driver(value)['ledger_sha256']==fingerprint(receipt)
    path.write_text('unexpected later log')
    with pytest.raises(TemplateError):driver(value)


def test_api_log_projection_is_not_read_as_a_host_path(ledger):
    driver,value,_,_,_,_,_,job,_=ledger
    job['log']=['different truncated API view'];job['source_path']='/untrusted/data/path'
    assert driver(value)['jobs_sha256']==value['jobs_sha256']


def test_other_actor_cannot_use_original_ledger_receipt(ledger):
    driver,value,*_=ledger;value=deepcopy(value);value['actor']['process_sha256']='9'*64
    with pytest.raises(TemplateError,match='owner/jobs'):driver(value)


def test_ancestor_symlink_substitution_during_hashing_is_refused(ledger,monkeypatch):
    import image_build_ledger as module
    driver,value,jobs,_,_,_,_,_,_=ledger
    original=module._file;changed=[]
    def replace(parent,name,*args,**kwargs):
        result=original(parent,name,*args,**kwargs)
        if name.endswith('.log') and not changed:
            root=jobs.parent;retained=root.with_name('retained-state');root.rename(retained);root.symlink_to(retained)
            changed.append(True)
        return result
    monkeypatch.setattr(module,'_file',replace)
    with pytest.raises((TemplateError,OSError)):driver(value)
    assert changed


def test_real_job_ledger_composes_with_running_and_stopped_observer(ledger,observation):
    _,_,jobs,logs,_,_,_,job,_=ledger
    original,owner,state,profile=observation
    state['jobs']=[deepcopy(job)];owner['jobs_sha256']=terminal_jobs_digest(state['jobs'])
    receipt=capture_ledger(paths=dict(jobs=str(jobs),logs=str(logs)),
        identities=dict(jobs=identity(jobs.stat()),logs=identity(logs.stat())),container_log_dir='/state/logs',
        api_jobs=state['jobs'],original_actor=profile['actor'],context=profile['context'],read_context=original.context)
    profile=deepcopy(profile);profile['ledger_sha256']=fingerprint(receipt)
    provider=JobLedger(receipt,expected_sha256=fingerprint(receipt),read_context=original.context)
    observer=ImageBuildObservation(original.api,profile,context=original.context,query=original.query,
        binding=original.binding,ledger=provider,activity=original.activity,exit_receipt=original.exit_receipt,
        startup=original.startup,process=original.process)
    assert observer(owner)['running'] is True
    count=state['queries'];stop_receipt(owner,state)
    state['inspect']['HostConfig']['RestartPolicy']=deepcopy(NO_RESTART)
    assert observer(owner)['running'] is False and state['queries']==count
    (logs/(job['id']+'.log')).write_text('changed while stopped\n')
    with pytest.raises(TemplateError,match='history changed'):observer(owner)
