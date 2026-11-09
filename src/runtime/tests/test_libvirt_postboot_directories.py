"""Exact directory capability and recovery; all resource mutations simulated."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_postboot_session import PostBootRecoverySession
from dnlab_runtime.manifest import Conflict
from tools import libvirt_postboot_assembly as observers
from tools import libvirt_postboot_directories as module
from test_libvirt_postboot_assembly import wiring,boot_parent,installed_packages,install,request_profile
from test_libvirt_run_parent import PinnedDirectories


@pytest.fixture
def directories(wiring,monkeypatch):
    arguments,_,_,observed,installer=wiring
    prepared=observers.PostBootPrepareAssembly(**arguments).session.prepare()
    files=PinnedDirectories(arguments['journal'],observed,arguments['run_parent']['identity'])
    monkeypatch.setattr(observers.PostBootObserver,'_volatile',
        lambda self,item,entry:deepcopy(observed['volatile'][item['spec']['key']]))
    monkeypatch.setattr(module.PreparedDirectoryFiles,'observe',lambda self,item,operation:files.observe(item,operation))
    monkeypatch.setattr(module.PreparedDirectoryFiles,'_birth',lambda self,item,operation:files._birth(item,operation))
    monkeypatch.setattr(observers.InstallationFiles,'create',lambda self,*a,**kw:files.create(*a,**kw))
    monkeypatch.setattr(observers.InstallationFiles,'recover',lambda self,*a,**kw:files.recover(*a,**kw))
    monkeypatch.setattr(PostBootRecoverySession,'prepare',lambda *a,**kw:pytest.fail('directory entry cannot prepare'))
    arguments={**arguments,'prepared_reference':prepared}
    return arguments,files,observed,installer


def test_directory_assembly_applies_original_without_preparing_or_enabling_services(directories):
    arguments,files,_,installer=directories
    built=module.PostBootDirectoryAssembly(**arguments)
    assert files.calls==[] and built.readonly.files.readonly is True and built.files.readonly is False
    source=installer.read(arguments['installation']['id'])
    result=built.apply_original()
    assert result['daemon_ready'] is False and result['scope']=='session-directories-only'
    assert len(files.calls)==2 and built.apply_original()==result
    assert built.effective()['daemon_ready'] is False and installer.read(source['id'])==source


def test_reopened_directory_assembly_recovers_only_original_birth(directories):
    arguments,files,_,_=directories;built=module.PostBootDirectoryAssembly(**arguments)
    files.lose_after=True
    with pytest.raises(OSError,match='lost after'):built.apply_original()
    reopened=module.PostBootDirectoryAssembly(**arguments)
    result=reopened.recover_original()
    assert result['daemon_ready'] is False and len(files.calls)==2
    assert reopened.reference==arguments['prepared_reference']


@pytest.mark.parametrize('fault',['nonce','spec','journal'])
def test_foreign_prepared_reference_is_refused_before_directory_allocation(directories,fault):
    arguments,files,_,_=directories;arguments={**arguments,'prepared_reference':deepcopy(arguments['prepared_reference'])}
    reference=arguments['prepared_reference']
    if fault=='nonce':reference['recovery']['items'][0]['nonce']='0'*32
    elif fault=='spec':reference['recovery']['items'][0]['spec']['path']='/run/foreign'
    else:reference['journal_identity']='foreign'
    with pytest.raises(Conflict):module.PostBootDirectoryAssembly(**arguments)
    assert files.calls==[]


def test_directory_mutator_refuses_other_operation_or_non_directory_targets(directories):
    arguments,files,_,_=directories;built=module.PostBootDirectoryAssembly(**arguments)
    item=deepcopy(arguments['prepared_reference']['recovery']['items'][0]);item['phase']='create_requested'
    with pytest.raises(Conflict,match='mutation binding'):built.files.create(item,'foreign')
    item['spec']['kind']='file'
    with pytest.raises(Conflict,match='mutation binding'):built.files.recover(item,arguments['recovery_id'])
    assert files.calls==[]


def test_current_service_conflict_blocks_directory_mutation(directories):
    arguments,files,observed,_=directories;built=module.PostBootDirectoryAssembly(**arguments)
    next(iter(observed['prerequisites']['services']['units'].values()))['active_state']='active'
    with pytest.raises(Conflict):built.apply_original()
    assert files.calls==[]
