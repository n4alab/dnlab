"""Policy-only administrative generation qualification with synthetic I/O."""
from copy import deepcopy

import pytest

from dnlab_runtime.image_build_hold import NO_RESTART
from dnlab_runtime.vm_template import TemplateError
from image_build_admin_service import AdministrativeService
from test_image_build_observation import observation


@pytest.fixture
def service(observation):
    original,hold,state,profile=observation
    state['capture']['process'].update(pid=45,start_ticks='56')
    state['inspect']['State'].update(Pid=45,StartedAt='administrative')
    state['inspect']['HostConfig']['RestartPolicy']=deepcopy(NO_RESTART)
    generation=dict(started_at='administrative',restart_count=0)
    driver=AdministrativeService(profile,hold,capture=state['capture'],generation=generation,
        networks=state['inspect']['NetworkSettings']['Networks'],
        api=original.api,read_context=original.context,query_factory=lambda profile:original.query,
        binding=original.binding,ledger=original.ledger,process=original.process)
    return driver,state,hold


def test_only_policy_restoration_qualifies_without_fabricated_start_or_idle(service):
    driver,state,hold=service;old=deepcopy(hold)
    proof=driver.observe(NO_RESTART)
    assert proof==dict(service_sha256=driver.service_sha256,restart_policy=NO_RESTART,generation_verified=True)
    assert not {'idle','original_start_verified','startup'}&set(proof)
    state['inspect']['HostConfig']['RestartPolicy']=deepcopy(driver.profile['policy'])
    assert driver.observe(driver.profile['policy'])['generation_verified'] is True
    assert hold==old


@pytest.mark.parametrize('fault',['pid','starttime','generation','image','config','policy','network','context','binding','ledger','jobs','source'])
def test_admin_generation_conflicts_refuse(service,fault):
    driver,state,_=service
    if fault=='pid':state['inspect']['State']['Pid']=99
    elif fault=='starttime':state['capture']['process']['start_ticks']='999'
    elif fault=='generation':state['inspect']['State']['StartedAt']='replacement'
    elif fault=='image':state['inspect']['Image']='sha256:'+'0'*64
    elif fault=='config':state['inspect']['Config']['Labels']={'foreign':'true'}
    elif fault=='policy':state['inspect']['HostConfig']['RestartPolicy']['Name']='always'
    elif fault=='network':state['inspect']['NetworkSettings']['Networks']['mgmt']['EndpointID']='foreign'
    elif fault=='context':state['context']['boot_id']='foreign'
    elif fault=='binding':state['binding']['state']='drift'
    elif fault=='ledger':state['ledger']['ledger_sha256']='0'*64
    elif fault=='jobs':state['jobs'][0]['status']='running'
    else:state['capture']['sources']['/opt/dnlab-image-build/api.py']['sha256']='0'*64
    with pytest.raises(TemplateError):driver.observe(NO_RESTART)


def test_change_during_readonly_query_refuses(service):
    driver,state,_=service
    state['after_query']=lambda:state['inspect']['State'].update(StartedAt='replacement')
    with pytest.raises(TemplateError):driver.observe(NO_RESTART)
