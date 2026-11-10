"""Current-session retirement: real temp path absence, synthetic resource leaves."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import ConfigurationRevision,UNIT
from dnlab_runtime.libvirt_current_session import CurrentConfigurationSession
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict
from test_libvirt_configuration import Replacement
from test_libvirt_postboot_unit_prepare import unit_prepare,directories,wiring,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def current_retirement(unit_prepare):
    built,source,window,_,parent,files,observed,installer=unit_prepare
    original=installer.read(source['id'])
    agreement=dict(operation_id='old-unit-policy',context=deepcopy(original['context']),targets=['file:'+UNIT],nonce='2'*32)
    old_window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    old=ConfigurationRevision(built.session.journal,Replacement(),window=old_window)
    reference=old.prepare('old-unit-policy',original)
    readonly=built.readonly
    def dependency(spec):return readonly.dependencies(spec)
    from dnlab_runtime.libvirt_current_session import CurrentSessionView
    view=CurrentSessionView(built.session.recovery,built.reference['recovery']['id'])
    session=CurrentConfigurationSession(view,snapshot=readonly.snapshot,identity=readonly.identity,
        directory_dependency=dependency,window=window,journal_identity=built.reference['journal_identity'])
    agreement=dict(operation_id='retire-previous-unit',context=deepcopy(source['context']),targets=['file:'+UNIT],nonce='3'*32)
    retire_window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    return session,reference,retire_window,parent,files,observed,old


def test_real_current_lineage_allows_metadata_retirement_then_new_prepare(current_retirement):
    session,reference,window,parent,files,_,old=current_retirement;calls=list(files.calls)
    result=session.retire_original(reference,window=window)
    prepared=session.prepare()
    assert prepared['predecessor']['revision_id']==reference['id']
    assert result['revision_id']==reference['id'] and old.read(reference['id'])==reference
    assert list(parent.iterdir())==[] and files.calls==calls


@pytest.mark.parametrize('which',['staging','backup'])
def test_occupied_historical_path_preserved(current_retirement,which):
    session,reference,window,parent,files,_,_=current_retirement;calls=list(files.calls)
    path=parent/reference[which].rsplit('/',1)[1];path.write_text('foreign')
    with pytest.raises(Conflict,match='candidate or backup is present'):
        session.retire_original(reference,window=window)
    assert path.read_text()=='foreign' and files.calls==calls
    assert session.journal.db.execute('SELECT count(*) FROM libvirt_configuration_retirements').fetchone()[0]==0


def test_active_service_blocks_retirement_before_metadata(current_retirement):
    session,reference,window,_,_,observed,_=current_retirement
    next(iter(observed['prerequisites']['services']['units'].values()))['active_state']='active'
    with pytest.raises(Conflict):session.retire_original(reference,window=window)
    assert session.journal.db.execute('SELECT count(*) FROM libvirt_configuration_retirements').fetchone()[0]==0


def test_new_generation_reference_cannot_replace_predecessor(current_retirement):
    session,reference,window,_,files,_,_=current_retirement;calls=list(files.calls)
    session.retire_original(reference,window=window);prepared=session.prepare()
    foreign=deepcopy(prepared);foreign['predecessor']['retirement_sha256']='0'*64
    with pytest.raises(Conflict,match='predecessor differs'):session._binding(foreign)
    assert files.calls==calls
