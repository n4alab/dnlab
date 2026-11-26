"""Recipe wiring only; no installed journal, Docker, procfs or libvirt I/O."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))

from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
import image_build_unreleased_recipe as recipe
from test_image_build_unreleased_execution import physical
from test_image_build_unreleased_retirement import unreleased
from test_image_build_executor import executor
from test_image_build_observation import observation
from test_vm_runtime_process import runtime_process


@pytest.fixture
def configured(physical,executor,monkeypatch):
    root,binding,_,_,original,request,observed=physical
    profile=deepcopy(executor[-1].observation.profile)
    inputs=dict(schema_version=1,execution_allowed=True,request=request,original=original,profile=profile,
        networks=deepcopy(executor[3]['inspect']['NetworkSettings']['Networks']),binding={},ledger={},
        shell_asset={},build_roots=['/synthetic/build'],directory=str(root),physical=binding)
    calls=[]
    def observer(value,fence,**providers):
        assert value==inputs;calls.append('observer')
        return lambda:deepcopy(observed)
    monkeypatch.setattr(recipe,'native_observer',observer)
    return inputs,calls


def test_recipe_runs_only_bound_original_metadata_flow(configured,tmp_path):
    inputs,calls=configured;saved={}
    def persist(name,value):saved[name]=deepcopy(value);return fingerprint(value)
    result=recipe.execute_recipe(inputs,snapshot=tmp_path/'snapshot',persist=persist,record=lambda p:None,
        verify_sources=lambda:inputs['request']['sources_sha256'],read_context=lambda:inputs['profile']['context'])
    assert result['service_actions_performed']==0 and calls==['observer']
    assert list(saved)==['intent.json','write-binding.json','retirement.json']


def test_disabled_recipe_does_not_read_context_sources_or_journal(configured,tmp_path,monkeypatch):
    inputs,calls=configured;inputs['execution_allowed']=False
    def forbidden(*args,**kwargs):pytest.fail('disabled recipe must not inspect or persist')
    monkeypatch.setattr(recipe.os,'lstat',forbidden)
    with pytest.raises(TemplateError,match='explicit frozen recipe'):
        recipe.execute_recipe(inputs,snapshot=tmp_path/'snapshot',persist=forbidden,record=forbidden,
            verify_sources=forbidden,read_context=forbidden)
    assert calls==[]


@pytest.mark.parametrize('fault',['sources','context','intent'])
def test_initial_preflight_and_durability_failures_do_not_open_fence(configured,tmp_path,fault):
    inputs,calls=configured
    sources='0'*64 if fault=='sources' else inputs['request']['sources_sha256']
    context={} if fault=='context' else inputs['profile']['context']
    with pytest.raises(TemplateError):
        recipe.execute_recipe(inputs,snapshot=tmp_path/'snapshot',persist=lambda *a:None,record=lambda p:None,
            verify_sources=lambda:sources,read_context=lambda:context)
    assert calls==[] and not (tmp_path/'snapshot').exists()


@pytest.mark.parametrize('action',['start','policy','other-container','other-route'])
def test_recipe_transports_refuse_every_mutating_or_foreign_request(action):
    api=recipe.ReadonlyService('a'*64);engine=recipe.ReadonlyLockAsset('a'*64)
    with pytest.raises(TemplateError,match='only original'):
        if action=='start':engine.start()
        elif action=='policy':engine.update_policy(dict(Name='no',MaximumRetryCount=0))
        elif action=='other-container':api.inspect('b'*64)
        else:api.request('GET','/containers/json')
