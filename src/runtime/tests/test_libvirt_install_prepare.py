"""Prepare-only entry with temporary snapshot files and synthetic NSS."""
from copy import deepcopy

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_install import targets
from dnlab_runtime.libvirt_install_dependencies import InstallationDirectoryDependencies
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict
from tools.libvirt_install_prepare import PreparationOnlyRunner, directory_receipts, prepare_only
from tools.libvirt_install_preflight import collect
from test_libvirt_install_snapshot import snapshot, fixture, request_profile


@pytest.fixture
def preparation(snapshot, tmp_path):
    provider, _, root, _, request, _ = snapshot
    (root/'etc/dnlab').mkdir()
    baseline = dict(status='collected', snapshot=provider(), targets=collect(root, request, provider.packages))
    receipt = dict(operation_id='install', context=baseline['snapshot']['context'],
        targets=[item['key'] for item in targets(provider.profile)], nonce='e'*32)
    window = ProvisioningWindow(receipt, lambda:deepcopy(receipt))
    def query(database, key):
        if key not in ('root', 0):return None
        return dict(name='root',gid=0,**({'uid':0} if database=='passwd' else {}))
    return tmp_path/'journal', dict(root=root, request=request, baseline=baseline,
        snapshot_provider=provider,window=window,nss_query=query,dependency_paths=['/etc/dnlab'])


def test_saved_inventory_produces_same_receipt_as_live_reader(preparation):
    _, args = preparation
    profile=args['snapshot_provider'].profile
    receipts=directory_receipts(profile,args['baseline']['snapshot'],args['baseline']['targets'],['/etc/dnlab'])
    spec=next(item for item in targets(profile) if item['key']=='directory:/etc/dnlab')
    assert receipts['/etc/dnlab']==InstallationDirectoryDependencies(args['root'],[spec])(spec)


def test_prepare_only_reopens_original_intent_without_account_or_file_creation(preparation):
    directory, args=preparation
    journal=Journal(directory)
    try:first=prepare_only(journal,**args)
    finally:journal.close()
    journal=Journal(directory)
    try:assert prepare_only(journal,**args)==first
    finally:journal.close()
    assert first['phase']=='prepared'
    assert all(item['phase'] in ('prepared','dependency') for item in first['items'])
    assert not (args['root']/'etc/dnlab/libvirt').exists()
    assert 'dnlab-libvirt' not in (args['root']/'etc/passwd').read_text()


@pytest.mark.parametrize('fault',['inventory','unselected','ancestor','changed_directory'])
def test_incomplete_or_changed_dependency_cannot_prepare(preparation,fault):
    directory,args=preparation
    if fault=='inventory':args['baseline']['targets']['observation_sha256']='0'*64
    elif fault=='unselected':args['dependency_paths']=[]
    elif fault=='ancestor':del args['baseline']['snapshot']['prerequisites']['os_parents']['/etc']
    else:(args['root']/'etc/dnlab').chmod(0o777)
    journal=Journal(directory)
    try:
        with pytest.raises(Conflict):prepare_only(journal,**args)
        table=journal.db.execute("SELECT 1 FROM sqlite_master WHERE name='libvirt_install_intents'").fetchone()
        if table:assert journal.db.execute('SELECT COUNT(*) FROM libvirt_install_intents').fetchone()[0]==0
    finally:journal.close()


@pytest.mark.parametrize('method',['arm','verify','release','outcome'])
def test_prepare_runner_refuses_all_worker_actions(method):
    with pytest.raises(Conflict,match='prepare-only'):getattr(PreparationOnlyRunner(),method)({})
