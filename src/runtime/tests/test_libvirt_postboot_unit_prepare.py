"""Current unit metadata preparation with synthetic resources and private paths."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import UNIT
from dnlab_runtime.libvirt_current_session import CurrentSessionView
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_directories import PostBootDirectoryAssembly
from tools.libvirt_postboot_unit_prepare import PostBootUnitPrepare
from test_libvirt_postboot_directories import directories,wiring,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def unit_prepare(directories,tmp_path):
    arguments,files,observed,installer=directories
    root=tmp_path/'filesystem';parent=root/'etc/systemd/system';parent.mkdir(parents=True,mode=0o755)
    arguments={**arguments,'root':root};built=PostBootDirectoryAssembly(**arguments);built.apply_original()
    source=CurrentSessionView(built.session.recovery,arguments['recovery_id']).read()
    for item in source['items']:
        if item['spec']['kind'] in ('file','directory') and item['spec']['key'] not in observed['volatile']:
            files.resources[item['spec']['key']]=deepcopy(item['proof'])
    agreement=dict(operation_id='current-unit-metadata',context=deepcopy(source['context']),
        targets=['file:'+UNIT],nonce='9'*32)
    live=deepcopy(agreement);window=ProvisioningWindow(agreement,lambda:deepcopy(live))
    arguments['window'].observe=lambda:None
    return built,source,window,live,parent,files,observed,installer


def test_unit_prepare_retains_original_lineage_without_staging_or_reopening_directory_window(unit_prepare):
    directories,source,window,_,parent,files,_,installer=unit_prepare
    before=list(files.calls);original=installer.read(source['id'])
    prepared=PostBootUnitPrepare(directories,effective_source=source,window=window)
    reference=prepared.prepare()
    assert reference['phase']=='prepared' and reference['installation']==source
    content=reference['plan']['target_spec']['content']
    assert 'Requisite=' in content and 'Requires=' not in content
    assert list(parent.iterdir())==[] and files.calls==before and installer.read(source['id'])==original
    assert prepared.prepare()==reference
    for method in (prepared.revision.apply_original,prepared.revision.recover_original):
        with pytest.raises(Conflict,match='metadata-only unit'):method(reference)
    assert list(parent.iterdir())==[] and files.calls==before


def test_foreign_effective_source_is_refused_before_revision_metadata(unit_prepare):
    directories,source,window,_,_,files,_,_=unit_prepare
    foreign=deepcopy(source);foreign['postboot']['recovery_sha256']='0'*64
    before=directories.session.journal.db.total_changes;calls=list(files.calls)
    with pytest.raises(Conflict,match='effective directory source differs'):
        PostBootUnitPrepare(directories,effective_source=foreign,window=window)
    assert directories.session.journal.db.total_changes==before and files.calls==calls


def test_closed_revision_window_does_not_create_unit_intent_or_file(unit_prepare):
    directories,source,window,live,parent,files,_,_=unit_prepare
    prepared=PostBootUnitPrepare(directories,effective_source=source,window=window)
    live['nonce']='0'*32;before=directories.session.journal.db.total_changes;calls=list(files.calls)
    with pytest.raises(Conflict):prepared.prepare()
    assert directories.session.journal.db.total_changes==before and list(parent.iterdir())==[] and files.calls==calls


def test_current_service_conflict_blocks_unit_metadata_preparation(unit_prepare):
    directories,source,window,_,parent,files,observed,_=unit_prepare
    prepared=PostBootUnitPrepare(directories,effective_source=source,window=window)
    next(iter(observed['prerequisites']['services']['units'].values()))['active_state']='active'
    before=directories.session.journal.db.total_changes;calls=list(files.calls)
    with pytest.raises(Conflict):prepared.prepare()
    assert directories.session.journal.db.total_changes==before and list(parent.iterdir())==[] and files.calls==calls
