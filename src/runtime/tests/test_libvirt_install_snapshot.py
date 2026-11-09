"""Fixture filesystem and injected service/namespaces; never observe the master."""
from copy import deepcopy
import subprocess

import pytest

from dnlab_runtime.libvirt_account_commands import command_plan
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.manifest import Conflict,fingerprint
from tools.libvirt_account_tool_inventory import collect as account_tools
from tools.libvirt_install_snapshot import InstallationSnapshot,ACCOUNT_INPUTS
from test_libvirt_install_preflight import fixture,request_profile


@pytest.fixture
def snapshot(fixture):
    root,request,_,write=fixture;profile=render_profile(**request)
    (root/'run').mkdir()
    packages=profile['package_request']['roots']
    write('var/lib/dpkg/status','\n\n'.join('Package: '+n+'\nVersion: '+v+'\nArchitecture: amd64\nStatus: install ok installed' for n,v in packages.items()))
    for binary in request['binaries'].values():(root/binary['path'].lstrip('/')).chmod(0o755)
    write('usr/sbin/useradd','synthetic useradd');(root/'usr/sbin/useradd').chmod(0o755)
    write('usr/sbin/groupadd','synthetic groupadd');(root/'usr/sbin/groupadd').chmod(0o755)
    write('etc/nsswitch.conf','passwd: files systemd\ngroup: files systemd\n')
    write('etc/login.defs','USERGROUPS_ENAB yes\n');write('etc/default/useradd','SHELL=/bin/sh\n')
    observed=account_tools(root)['observed']['paths']
    approved={path:observed[path] for path in ACCOUNT_INPUTS}
    state=dict(namespaces={name:dict(device=1,inode=index+10) for index,name in enumerate(('pid','mnt','net','user'))},
        services=dict(units={name:dict(active_state='inactive',job_id=0) for name in profile['service_order']+profile['forbidden_vendor_activation']},
            dedicated_uid=request['session']['uid'],processes=[]))
    provider=InstallationSnapshot(root,request,packages,approved,namespaces=lambda:deepcopy(state['namespaces']),
        services=lambda:deepcopy(state['services']))
    return provider,state,root,write,request,approved


def test_stable_prerequisites_are_readonly_and_separate_from_created_targets(snapshot,monkeypatch):
    provider,state,root,write,_,_=snapshot
    monkeypatch.setattr(subprocess,'run',lambda *a,**k:pytest.fail('no commands in snapshot provider'))
    first=provider()
    write('etc/passwd','root:x:0:0:root:/root:/bin/sh\ndnlab-libvirt:x:1001:1002:fixture:/x:/usr/sbin/nologin\n')
    write('etc/group','root:x:0:\nkvm:x:108:\ndnlab-libvirt:x:1002:\n')
    write('etc/systemd/system/dnlab-libvirtd.service','synthetic owned target, verified by separate adapter')
    assert provider()==first
    assert first['context']['boot_id']=='synthetic-boot'
    assert first['prerequisites']['kvm_group']==dict(name='kvm',gid=108)
    assert 'etc/passwd' not in first['prerequisites']['account_inputs']


@pytest.mark.parametrize('fault',['package','daemon','mask','config','tool','hook','kvm'])
def test_changed_static_input_is_refused_before_admission(snapshot,fault):
    provider,_,root,write,request,_=snapshot
    if fault=='package':write('var/lib/dpkg/status','')
    elif fault=='daemon':write('usr/sbin/libvirtd','foreign daemon')
    elif fault=='mask':(root/'etc/systemd/system/libvirtd.service').unlink()
    elif fault=='config':write('etc/default/useradd','foreign defaults')
    elif fault=='tool':write('usr/sbin/groupadd','foreign groupadd')
    elif fault=='hook':write('etc/shadow-maint/useradd-pre.d/foreign','never execute')
    else:write('etc/group','root:x:0:\nkvm:x:109:\n')
    with pytest.raises(Conflict):provider()


@pytest.mark.parametrize('fault',['active','job','process','missing_unit','namespace'])
def test_live_observation_must_be_complete_inactive_and_unambiguous(snapshot,fault):
    provider,state,_,_,_,_=snapshot
    unit=next(iter(state['services']['units']))
    if fault=='active':state['services']['units'][unit]['active_state']='active'
    elif fault=='job':state['services']['units'][unit]['job_id']=17
    elif fault=='process':state['services']['processes']=[dict(pid=123,uid=1001)]
    elif fault=='missing_unit':del state['services']['units'][unit]
    else:del state['namespaces']['pid']
    with pytest.raises(Conflict):provider()


def test_namespace_change_during_collection_is_rejected(snapshot):
    provider,state,_,_,_,_=snapshot;calls=[]
    def namespaces():
        value=deepcopy(state['namespaces'])
        if calls:value['pid']['inode']+=1
        calls.append(True);return value
    provider.namespaces=namespaces
    with pytest.raises(Conflict,match='observation changed'):provider()


def test_os_parent_replaced_during_collection_is_rejected(snapshot,monkeypatch):
    import tools.libvirt_install_snapshot as module
    provider,_,root,_,_,_=snapshot
    original=module.collect_parents;calls=[]
    def changing(*args):
        if calls:
            (root/'run').rename(root/'original-run')
            (root/'run').mkdir()
        calls.append(True)
        return original(*args)
    monkeypatch.setattr(module,'collect_parents',changing)
    with pytest.raises(Conflict,match='OS parent identity changed'):provider()
    assert (root/'original-run').is_dir()


def test_complete_static_receipt_binds_command_and_original_context(snapshot):
    provider,state,_,_,_,approved=snapshot;original=provider()
    request=dict(intent_id='install',nonce='d'*32,spec_sha256='e'*64,kind='group',expected=dict(name='dnlab-libvirt',gid=1002))
    command=command_plan(request,{'groupadd':dict(path='/usr/sbin/groupadd',sha256=approved['usr/sbin/groupadd']['sha256'])})
    receipt=provider.command_preflight(command,original=original)
    assert receipt==dict(qualified=True,command_sha256=fingerprint(command),context_sha256=fingerprint(original['context']),inputs_sha256=fingerprint(original['prerequisites']))
    state['namespaces']['pid']['inode']+=1
    with pytest.raises(Conflict,match='prerequisites changed'):provider.command_preflight(command,original=original)


def test_proc_and_systemctl_adapters_compose_with_snapshot_on_fixtures(snapshot):
    from tools.libvirt_install_activity import InstallationActivity
    provider,_,root,write,_,_=snapshot
    for name in ('pid','mnt','net','user'):write('proc/self/ns/'+name,'synthetic namespace marker')
    write('proc/123/status','Uid: 0 0 0 0\nGid: 0 0 0 0\nGroups: 0\n')
    names=provider.profile['service_order']+provider.profile['forbidden_vendor_activation']
    stdout='\n\n'.join('Id='+name+'\nLoadState=masked\nActiveState=inactive\nJob=' for name in names)+'\n'
    calls=[]
    def query(argv,**kwargs):calls.append(argv);return dict(exit_code=0,stdout=stdout,stderr='')
    observer=InstallationActivity(provider.profile,query=query,proc_root=root/'proc')
    provider.namespaces=observer.namespaces;provider.services=observer
    value=provider()
    assert value['prerequisites']['services']['processes']==[] and len(calls)==2
    assert set(value['context']['namespaces'])=={'pid','mnt','net','user'}


def test_historical_layout_cannot_qualify_a_mutating_command(snapshot):
    provider,_,root,_,request,approved=snapshot
    request=deepcopy(request);request.pop('layout_version');request.pop('driver_config_root')
    legacy=InstallationSnapshot(root,request,provider.packages,approved,
        namespaces=lambda:pytest.fail('legacy command must stop before observation'),
        services=lambda:pytest.fail('legacy command must stop before observation'))
    with pytest.raises(Conflict,match='layout_version=2'):legacy.command_preflight({},original={})
