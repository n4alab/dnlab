"""Assembly with original runtime/controller and explicitly simulated service I/O."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_session import ImageBuildSession
from dnlab_runtime.vm_template import TemplateError
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def session(executor):
    hold,op,state,native,commands,adapter=executor;observer=adapter.observation
    kwargs=dict(jobs_sha256=native['ledger']['jobs_sha256'],api=observer.api,read_context=observer.context,
        binding=observer.binding,ledger=observer.ledger,activity=observer.activity,window=hold.window,cleanup=hold.cleanup,
        query=observer.query,process=observer.process,engine=adapter.engine,term=adapter.term)
    def make(profile=None,**overrides):
        return ImageBuildSession(commands.runtime,observer.profile if profile is None else profile,**(kwargs|overrides))
    return make(),hold,op,state,native,commands,make


def test_observe_adds_no_hold_or_command_and_prepare_reuses_original_intent(session):
    driver,hold,op,state,_,_,_=session;scope=hold.read(op)['scope']
    before=hold.journal.db.total_changes
    assert driver.observe(scope)['running'] is True
    assert hold.journal.db.total_changes==before and state['actions']==[]
    assert driver.prepare(op,scope=scope)==hold.read(op)


def test_assembled_lifecycle_preserves_startup_receipt_and_original_policy(session):
    driver,hold,op,state,_,_,_=session
    assert driver.acquire(op)['held'] is True
    state['cleanup']=True
    assert driver.restore(op)['phase']=='restored'
    proof=driver.commands.details(hold.read(op)['actions']['start']['reference'])['details']['startup']
    assert proof['capture']['process']['pid']==45
    assert state['actions']==['policy','term','logs','start','policy']


def test_inactive_window_cannot_become_a_hold(session):
    driver,hold,op,state,_,_,_=session;state['window']=False
    with pytest.raises(TemplateError,match='window'):driver.acquire(op)
    assert hold.read(op)['phase']=='prepared' and state['actions']==[]


def test_foreign_context_refused_before_assembly_writes(session):
    driver,hold,_,state,_,_,make=session;profile=deepcopy(driver.profile)
    profile['context']['boot_id']='foreign';before=hold.journal.db.total_changes
    with pytest.raises(TemplateError,match='context'):make(profile)
    assert hold.journal.db.total_changes==before and state['actions']==[]


@pytest.mark.parametrize('provider',['window','cleanup'])
def test_window_and_cleanup_have_no_permissive_defaults(session,provider):
    _,_,_,state,_,_,make=session
    with pytest.raises(TemplateError,match='explicit window/cleanup'):make(**{provider:None})
    assert state['actions']==[]
