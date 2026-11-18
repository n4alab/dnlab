"""Pure isolated-canary payload/identity checks; no image or container required."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_canary import payload, qualify, POLICY
from dnlab_runtime.backend import LABEL
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def canary():
    image=dict(Id='sha256:'+'a'*64,Config=dict(Env=['PATH=/usr/bin','DNLAB_LOG_ROOT=/old/log'],
        Volumes={'/opt/vrnetlab':{},'/var/lib/dnlab-image-build':{}},Labels={'com.docker.compose.service':'image-build'}))
    paths=dict(checkout='/opt/vrnetlab',workspace='/private/output/workspace',logs='/private/output/logs')
    request=payload(image,'1'*32,**paths);config=deepcopy(request['config'])
    config['Labels'].update({LABEL+'.creator':'2'*32,LABEL+'.birth':'3'*32})
    actual=dict(Id='b'*64,Image=image['Id'],Name='/'+request['spec']['container_name'],
        Config={key:deepcopy(value) for key,value in config.items() if key!='HostConfig'},
        HostConfig=deepcopy(config['HostConfig']),State=dict(Status='running',OOMKilled=False,Error=''),
        Mounts=[dict(Type='bind',Source=source,Destination=destination,RW=mode=='rw')
                for source,destination,mode in [item.rsplit(':',2) for item in config['HostConfig']['Binds']]])
    def check(value=actual,phase='running'):
        return qualify(value,container_id='b'*64,name=request['spec']['container_name'],
                       effective_config=config,phase=phase,restart_policy=POLICY)
    return image,paths,request,actual,check


def test_canary_neutralizes_production_role_and_exposes_no_host_engine_or_lab_network(canary):
    image,_,request,actual,check=canary;config=request['config']
    assert check() is True
    assert image['Config']['Labels']['com.docker.compose.service']=='image-build'
    assert config['Labels']['com.docker.compose.service']==''
    assert config['HostConfig']['NetworkMode']=='none' and config['HostConfig']['ReadonlyRootfs'] is True
    assert config['HostConfig']['CapDrop']==['ALL'] and not config['HostConfig']['PortBindings']
    assert config['HostConfig']['Binds'][0]=='/opt/vrnetlab:/opt/vrnetlab:ro'


@pytest.mark.parametrize('phase',['created','exited'])
def test_unrealized_bind_mounts_allowed_only_in_nonrunning_phases(canary,phase):
    _,_,_,actual,check=canary;actual['State']['Status']=phase;actual['Mounts']=[]
    assert check(phase=phase) is True
    actual['State']['Status']='running'
    with pytest.raises(TemplateError,match='realized'):check()


@pytest.mark.parametrize('fault',['extra_mount','checkout_writable','privilege','role','container','policy','birth'])
def test_foreign_or_relaxed_canary_isolation_is_refused(canary,fault):
    _,_,_,actual,check=canary
    if fault=='extra_mount':actual['Mounts'].append(dict(Type='bind',Source='/var/run/docker.sock',Destination='/socket',RW=True))
    elif fault=='checkout_writable':actual['Mounts'][0]['RW']=True
    elif fault=='privilege':actual['HostConfig']['CapAdd']=['NET_ADMIN']
    elif fault=='role':actual['Config']['Labels']['com.docker.compose.service']='image-build'
    elif fault=='container':actual['Id']='c'*64
    elif fault=='policy':actual['HostConfig']['RestartPolicy']={'Name':'always','MaximumRetryCount':0}
    else:actual['Config']['Labels'][LABEL+'.birth']='4'*32
    with pytest.raises(TemplateError):check()


def test_nested_writable_path_cannot_alias_checkout(canary):
    image,paths,_,_,_=canary;paths['workspace']='/opt/vrnetlab/private'
    with pytest.raises(TemplateError,match='separate readonly'):payload(image,'1'*32,**paths)


def test_unexpected_image_volume_cannot_create_anonymous_state(canary):
    image,paths,_,_,_=canary;image['Config']['Volumes']['/unexpected']={}
    with pytest.raises(TemplateError,match='anonymous volumes'):payload(image,'1'*32,**paths)
