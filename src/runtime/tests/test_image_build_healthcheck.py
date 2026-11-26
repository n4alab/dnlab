"""Exact configured healthcheck provenance with synthetic process providers."""
from contextlib import contextmanager
from copy import deepcopy
import hashlib

import pytest

from cleanup_container_observer import config_digest
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
from image_build_healthcheck import ImageBuildHealthcheck, HASHES, KIND, TEST
from image_build_observation import artifact_digest, process_digest


@pytest.fixture
def healthcheck():
    cid='a'*64;image='sha256:'+'b'*64
    namespaces={name:dict(device=4,inode=index) for index,name in enumerate(('pid','mnt','net'),1)}
    context=dict(host_id='master',boot_id='original',namespaces=dict(user=dict(device=4,inode=9)))
    copies={'/opt/dnlab-image-build/api.py':'e'*64}
    primary=dict(pid=44,start_ticks='55',cmdline_sha256='f'*64,exe='/usr/local/bin/python3.13',
        cwd='/opt/dnlab-image-build',import_env_sha256='1'*64,cgroup='0::/docker-'+cid+'.scope\n',namespaces=namespaces)
    capture=dict(process=primary,sources={path:dict(sha256=sha,metadata=[]) for path,sha in copies.items()},executable=dict(sha256='c'*64))
    generation=dict(started_at='original',restart_count=0);policy=dict(Name='unless-stopped',MaximumRetryCount=0)
    inspected=dict(Id=cid,Image=image,Config=dict(Healthcheck=dict(Test=deepcopy(TEST)),User=''),
        HostConfig=dict(RestartPolicy=policy),Mounts=[],Path='python',Args=['api.py'],RestartCount=0,
        State=dict(Pid=44,Running=True,Status='running',StartedAt='original',OOMKilled=False,Error=''),
        NetworkSettings=dict(Networks=dict(mgmt=dict(NetworkID='original-network'))))
    actor=dict(container_id=cid,image_id=image,config_sha256=config_digest(inspected),context_sha256=fingerprint(context),
        artifact_sha256=artifact_digest(image,copies,capture['executable']['sha256']),process_sha256=process_digest(capture,generation))
    profile=dict(actor=actor,context=context,policy=policy,capture=capture,generation=generation,copies=copies,networks=dict(mgmt='original-network'))
    value=dict(actor=deepcopy(actor),actions={})
    def extended(original,pid,ticks,kind=None,parent=1):
        part=deepcopy(original);part['process'].update(pid=pid,start_ticks=ticks,parent_pid=parent,
            credentials=dict(uid=0,gid=0),user_namespace=deepcopy(context['namespaces']['user']))
        if kind:
            part['process']['cmdline_sha256']=HASHES[kind]
            if kind=='shell':part['process']['exe']='/usr/bin/dash';part['executable']['sha256']='d'*64
        return part
    state=dict(inspect=deepcopy(inspected),context=deepcopy(context),captures={
        44:extended(capture,44,'55'),45:extended(capture,45,'56','shell'),46:extended(capture,46,'57','python',45)},
        startup=None,after=None)
    class API:
        def inspect(self,wanted):assert wanted==cid;return deepcopy(state['inspect'])
    class Process:
        @contextmanager
        def capture(self,pid,wanted,files):
            assert wanted==cid and files==copies
            current=deepcopy(state['captures'][pid]);yield current
            if state['after']:state['after'](pid)
            if state['captures'][pid]!=current:raise TemplateError('synthetic process changed')
    shell=dict(container_id=cid,image_id=image,path='/usr/bin/dash',sha256='d'*64)
    driver=ImageBuildHealthcheck(API(),profile,shell_asset=shell,read_context=lambda:deepcopy(state['context']),
        startup=lambda value:deepcopy(state['startup']),process=Process())
    def rows():
        return [dict(pid=pid,start_ticks=part['process']['start_ticks'],command_sha256=part['process']['cmdline_sha256'],
            cgroup_sha256=hashlib.sha256(part['process']['cgroup'].encode()).hexdigest(),container=True,reason=None)
            for pid,part in sorted(state['captures'].items())]
    return driver,value,state,rows,extended


@pytest.mark.parametrize('members',[[44,45],[44,46],[44,45,46]])
def test_only_exact_processes_of_original_configured_healthcheck_qualify(healthcheck,members):
    driver,value,state,rows,_=healthcheck
    selected=[row for row in rows() if row['pid'] in members]
    proof=driver(value,deepcopy(state['inspect']),selected)
    assert proof['kind']==KIND and proof['main_process']['pid']==44
    assert proof['processes']==selected[1:] and len(proof['evidence_sha256'])==64


@pytest.mark.parametrize('fault',['argv','shell','python','namespace','userns','credentials','environment','cwd',
    'cgroup','parent','starttime','generation','image','source','config','policy','primary','context'])
def test_changed_healthcheck_provenance_refuses(healthcheck,fault):
    driver,value,state,rows,_=healthcheck;selected=rows();child=state['captures'][46]
    if fault=='argv':selected[-1]['command_sha256']='0'*64
    elif fault=='shell':state['captures'][45]['executable']['sha256']='0'*64
    elif fault=='python':child['executable']['sha256']='0'*64
    elif fault=='namespace':child['process']['namespaces']['net']['inode']=99
    elif fault=='userns':child['process']['user_namespace']['inode']=99
    elif fault=='credentials':child['process']['credentials']['uid']=65534
    elif fault=='environment':child['process']['import_env_sha256']='0'*64
    elif fault=='cwd':child['process']['cwd']='/foreign'
    elif fault=='cgroup':child['process']['cgroup']='0::/foreign\n'
    elif fault=='parent':child['process']['parent_pid']=99
    elif fault=='starttime':child['process']['start_ticks']='99'
    elif fault=='generation':state['inspect']['State']['StartedAt']='replacement'
    elif fault=='image':state['inspect']['Image']='sha256:'+'0'*64
    elif fault=='source':child['sources']['/opt/dnlab-image-build/api.py']['sha256']='0'*64
    elif fault=='config':state['inspect']['Config']['Healthcheck']['Test']=['CMD-SHELL','other']
    elif fault=='policy':state['inspect']['HostConfig']['RestartPolicy']['Name']='always'
    elif fault=='primary':selected[0]['start_ticks']='99'
    else:state['context']['boot_id']='foreign'
    with pytest.raises(TemplateError):driver(value,deepcopy(state['inspect']),selected)


def test_natural_health_log_update_does_not_replace_primary_generation(healthcheck):
    driver,value,state,rows,_=healthcheck
    state['after']=lambda pid:state['inspect']['State'].update(Health=dict(Log=['updated']))
    assert driver(value,deepcopy(state['inspect']),rows())['main_process']['pid']==44


def test_secondary_start_requires_saved_same_command_first_generation(healthcheck):
    driver,value,state,rows,extended=healthcheck
    original=deepcopy(driver.profile['capture']);original['process'].update(pid=144,start_ticks='155')
    original['process']['namespaces']['pid']['inode']=101
    generation=dict(started_at='restarted',restart_count=0)
    state['inspect']['State'].update(Pid=144,StartedAt='restarted')
    state['captures']={144:extended(original,144,'155'),145:extended(original,145,'156','shell'),146:extended(original,146,'157','python',145)}
    command=dict(actor=deepcopy(driver.profile['actor']),action='start');reference=dict(token='7'*32)
    value['actions']['start']=dict(command=command,reference=reference)
    current_actor=deepcopy(driver.profile['actor']);current_actor['process_sha256']=process_digest(original,generation)
    state['startup']=dict(reference=reference,command_sha256=fingerprint(command),capture=original,generation=generation,
                          actor=current_actor,original_start_verified=True)
    assert driver(value,deepcopy(state['inspect']),rows())['main_process']['pid']==144
    state['startup']['reference']=dict(token='8'*32)
    with pytest.raises(TemplateError):driver(value,deepcopy(state['inspect']),rows())
