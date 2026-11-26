"""Synthetic proc directory, procfs checker and existing service I/O doubles."""
from copy import deepcopy
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))

from dnlab_runtime.vm_template import TemplateError
from dnlab_runtime.procfs_context import check as real_check_procfs
import image_build_unreleased_observation as native
from image_build_unreleased_retirement import retire_unreleased
from test_image_build_unreleased_retirement import unreleased
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def observed(unreleased,executor,tmp_path,monkeypatch):
    _,_,_,_,proof,request,expected=unreleased
    adapter=executor[-1];context=deepcopy(adapter.observation.profile['context'])
    proc=tmp_path/'synthetic-proc';proc.mkdir()
    info=proc.stat();proc_identity=dict(device=info.st_dev,inode=info.st_ino)
    state=dict(context=context,sources=request['sources_sha256'],fence_checks=0,proc_checks=0,diagnostics=[])
    def fence():state['fence_checks']+=1
    def procfs(fd,**kwargs):
        state['proc_checks']+=1
        assert kwargs['context']==context and kwargs['read_context']()==context
        assert kwargs['proc_root']==str(proc)
        assert kwargs['proc_identity']==proc_identity
        assert list(kwargs['proc_identity'].values())!=proof['epoch']['snapshot']['proc_identity']
    monkeypatch.setattr(native,'check_procfs',procfs)
    driver=native.UnreleasedObservation(request,proof,service=adapter.observation,
        networks=executor[3]['inspect']['NetworkSettings']['Networks'],fence=SimpleNamespace(check=fence),
        verify_sources=lambda:state['sources'],read_context=lambda:deepcopy(state['context']),proc_root=str(proc),
        proc_identity=proc_identity,record=lambda proof:state['diagnostics'].append(deepcopy(proof)))
    return driver,state,executor[3],proc,expected,executor[2]


def test_qualified_synthetic_absence_and_original_service_return_bound_observation(observed):
    driver,state,_,_,expected,actions=observed
    assert driver()==expected
    assert state['fence_checks']==state['proc_checks']==2
    assert actions['actions']==[]


@pytest.mark.parametrize('fault',['pid','pid_after_query','source','context','process','policy','attachment','binding'])
def test_live_or_reused_pid_and_service_conflicts_never_authorize_retirement(observed,fault):
    driver,state,service,proc,_,actions=observed
    pid=str(driver.original['epoch']['snapshot']['record']['pid'])
    if fault=='pid':(proc/pid).mkdir()
    elif fault=='pid_after_query':service['after_query']=lambda:(proc/pid).mkdir()
    elif fault=='source':state['sources']='0'*64
    elif fault=='context':state['context']['boot_id']='foreign'
    elif fault=='process':service['capture']['process']['start_ticks']='foreign'
    elif fault=='policy':service['inspect']['HostConfig']['RestartPolicy']['Name']='no'
    elif fault=='attachment':service['inspect']['NetworkSettings']['Networks']['mgmt']['EndpointID']='foreign'
    else:service['binding']['state']='drift'
    with pytest.raises(TemplateError):driver()
    assert actions['actions']==[]


def test_original_fence_failure_is_preserved_without_service_observation(observed):
    driver,_,service,_,_,actions=observed
    def fail():raise TemplateError('physical original journal changed')
    driver.fence.check=fail
    queries=service['queries']
    with pytest.raises(TemplateError,match='physical original journal changed'):driver()
    assert service['queries']==queries and actions['actions']==[]


def test_observer_and_atomic_retirement_compose_without_native_actions(observed,unreleased):
    driver,state,_,_,_,actions=observed
    hold,_,_,args,proof,request,_=unreleased
    receipt=retire_unreleased(hold.journal.db,request,**args,observe=driver)
    assert receipt['claim_released'] is True and receipt['service_actions_performed']==0
    assert state['fence_checks']==state['proc_checks']==6
    assert actions['actions']==[]
    assert hold.read(args['hold_id'])==proof['hold']


def test_changed_captured_owner_cannot_prove_absence_of_another_pid(observed):
    driver,_,_,_,_,actions=observed
    driver.original['epoch']['snapshot']['record']['pid']+=1
    with pytest.raises(TemplateError,match='original administrative bindings differ'):driver()
    assert actions['actions']==[]


def test_process_directory_identity_is_not_the_procfs_root(observed,monkeypatch):
    driver,state,service,_,_,actions=observed
    driver.proc_identity=dict(zip(('device','inode'),driver.original['epoch']['snapshot']['proc_identity'],strict=True))
    monkeypatch.setattr(native,'check_procfs',real_check_procfs)
    queries=service['queries']
    with pytest.raises(TemplateError,match='procfs replaced'):driver()
    proof=state['diagnostics'][-1]
    assert proof['expected']!=proof['observed']
    assert list(proof['expected'].values())==proof['original_process_directory']
    assert service['queries']==queries and actions['actions']==[]
