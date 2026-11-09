"""Fake procfs and captured systemctl-shaped text only; no host command or census."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict
from tools.libvirt_install_activity import InstallationActivity,parse_units
from test_libvirt_service_profile import request_profile


@pytest.fixture
def activity(tmp_path,request_profile):
    proc=tmp_path/'proc';(proc/'self/ns').mkdir(parents=True)
    for name in ('pid','mnt','net','user'):(proc/'self/ns'/name).write_text('synthetic namespace marker')
    profile=render_profile(**request_profile);names=profile['service_order']+profile['forbidden_vendor_activation']
    raw='\n\n'.join('Id='+name+'\nLoadState=not-found\nActiveState=inactive\nJob=' for name in names)+'\n'
    state=dict(response=dict(exit_code=0,stdout=raw,stderr=''),calls=[])
    def query(argv,**kwargs):state['calls'].append((argv,kwargs));return deepcopy(state['response'])
    def process(pid,uid=0,gid=0,groups='0'):
        path=proc/str(pid);path.mkdir()
        (path/'status').write_text(f'Uid:\t{uid}\t{uid}\t{uid}\t{uid}\nGid:\t{gid}\t{gid}\t{gid}\t{gid}\nGroups:\t{groups}\n')
    return InstallationActivity(profile,query=query,proc_root=proc),state,proc,names,process


def test_original_fixed_readonly_query_and_only_candidate_process_scope(activity):
    observer,state,proc,names,process=activity;process(123,uid=2000,gid=2000,groups='2000')
    result=observer()
    assert result['processes']==[] and set(result['units'])==set(names)
    assert all(v==dict(active_state='inactive',job_id=0) for v in result['units'].values())
    argv,options=state['calls'][0]
    assert argv[:2]==['/usr/bin/systemctl','show'] and argv[-len(names):]==names
    assert options['timeout']==5 and options['env']['LC_ALL']=='C'
    assert set(observer.namespaces())=={'pid','mnt','net','user'}
    assert observer.diagnostics[0]['response']==state['response']


@pytest.mark.parametrize('uid,gid,groups',[(1001,0,'0'),(0,1002,'0'),(0,0,'0 1002')])
def test_candidate_uid_or_gid_is_a_blocker_never_an_adopted_process(activity,uid,gid,groups):
    observer,_,_,_,process=activity;process(123,uid,gid,groups)
    rows=observer()['processes'];assert len(rows)==1 and rows[0]['pid']==123
    assert observer.diagnostics[-1]['observation']['processes']==rows


@pytest.mark.parametrize('fault',['duplicate','missing','foreign','load','job','error','stderr','empty'])
def test_unqualified_unit_or_transport_response_refused_with_diagnostic(activity,fault):
    observer,state,_,names,_=activity
    if fault=='duplicate':state['response']['stdout']+='\n'+state['response']['stdout'].split('\n\n')[0]+'\n'
    elif fault=='missing':state['response']['stdout']='\n\n'.join(state['response']['stdout'].split('\n\n')[1:])
    elif fault=='foreign':state['response']['stdout']=state['response']['stdout'].replace(names[0],'foreign.service',1)
    elif fault=='load':state['response']['stdout']=state['response']['stdout'].replace('not-found','bad-setting',1)
    elif fault=='job':state['response']['stdout']=state['response']['stdout'].replace('Job=','Job=garbage',1)
    elif fault=='error':state['response']['exit_code']=1
    elif fault=='stderr':state['response']['stderr']='synthetic D-Bus denial'
    else:state['response']['stdout']=''
    with pytest.raises(Conflict):observer()
    assert observer.diagnostics[0]['response']==state['response']


def test_active_or_queued_state_is_reported_for_prerequisite_provider_to_refuse(activity):
    observer,state,_,names,_=activity
    state['response']['stdout']=state['response']['stdout'].replace('ActiveState=inactive','ActiveState=active',1).replace('Job=','Job=17',1)
    unit=observer()['units'][names[0]]
    assert unit==dict(active_state='active',job_id=17)


def test_proc_access_failure_is_not_silently_treated_as_absence(activity):
    observer,_,proc,_,process=activity;process(123)
    (proc/'123/status').write_text('Uid: 0\nGid: 0\n')
    with pytest.raises(Conflict,match='credentials incomplete'):observer()
