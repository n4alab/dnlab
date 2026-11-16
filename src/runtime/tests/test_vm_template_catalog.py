"""Readonly original catalog capability on temporary files only."""
from copy import deepcopy
import fcntl
import hashlib
import os
from pathlib import Path
import sqlite3

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template import template_digest
from dnlab_runtime.vm_template_assets import PublishedTemplateAssets
from dnlab_runtime.vm_template_files import identity
from dnlab_runtime.vm_template_install import TemplateBundleInstall, bundle_plan
from tools.vm_template_catalog import open_catalog
from test_vm_bundle import bundle, template
from test_vm_template import instance


@pytest.fixture
def original(bundle,tmp_path,instance):
    source,template,_ = bundle;root = tmp_path/'store';state_dir = tmp_path/'state'
    journal = Journal(state_dir);files = InstallationFiles(journal=journal)
    item = dict(spec=dict(kind='directory',key='directory:'+str(root),path=str(root),uid=0,gid=0,mode=0o755),nonce='b'*32)
    context = dict(host_id='worker',boot_id='synthetic');store_operation = 'store-create'
    agreement = dict(operation_id=store_operation,context=context,targets=[item['spec']['key']],nonce='c'*32)
    store_proof = files.create(item,store_operation,window=ProvisioningWindow(agreement,lambda:deepcopy(agreement)))
    raw = (source/'manifest.json').read_bytes()
    plan = bundle_plan(str(root),str(source),template,dict(sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)))
    agreement = dict(operation_id='bundle-import',context=context,targets=[s['key'] for s in plan],nonce='d'*32)
    driver = TemplateBundleInstall(journal,root=str(root),parent_identity=identity(root.stat()),
        window=ProvisioningWindow(agreement,lambda:deepcopy(agreement)),
        preflight=lambda r:dict(request_sha256=fingerprint(r),exclusive_writer=True))
    driver.prepare('bundle-import',source=str(source),template_sha256=template_digest(template))
    publication = driver.apply('bundle-import');logical = journal.identity;journal.close()
    binding = dict(directory=str(state_dir),identity=logical,directory_identity=identity(state_dir.stat()),
                   database_identity=identity((state_dir/'journal.sqlite3').stat()),lock_identity=identity((state_dir/'workload.lock').stat()))
    state = dict(context=True)
    def verify():
        if not state['context']:raise Conflict('current context changed')
    options = dict(store_item=item,store_operation=store_operation,store_proof=store_proof,import_window=agreement,verify=verify)
    birth = {k:instance['domain'][k] for k in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256'] = template_digest(template)
    value = dict(id=birth['creator_operation_id'],birth=birth,template=template,bundle_root=publication['directory'])
    return binding,options,publication,value,state


def test_original_catalog_is_readonly_and_capability_expires(original):
    binding,options,publication,value,_ = original
    directory = Path(binding['directory']);before = {p.name:p.stat().st_ino for p in directory.iterdir()}
    with open_catalog(binding,**options) as catalog:
        assert catalog.observe(publication['operation_id']) == publication
        provider = PublishedTemplateAssets(catalog,host_id='worker',publication=publication)
        assert provider(value) == dict(template_sha256=value['birth']['template_sha256'],assets_verified=True)
        changes = catalog.journal.db.total_changes
        with pytest.raises(sqlite3.OperationalError,match='readonly'):
            catalog.journal.db.execute('DELETE FROM vm_template_bundle_imports')
        for action in (catalog.prepare,catalog.apply,catalog.recover):
            with pytest.raises(Conflict,match='readonly'):action('anything')
        assert catalog.journal.db.total_changes == changes == 0
    assert catalog.journal.closed
    with pytest.raises(Conflict,match='closed'):provider(value)
    with pytest.raises(Conflict,match='closed'):catalog.read(publication['operation_id'])
    assert {p.name:p.stat().st_ino for p in directory.iterdir()} == before
    assert not list(directory.glob('*-wal')) and not list(directory.glob('*-shm'))


@pytest.mark.parametrize('fault',['directory','database','lock','logical','store'])
def test_foreign_binding_refused_without_sidecars_or_initialization(original,fault):
    binding,options,_,_,_ = deepcopy(original);directory = Path(binding['directory'])
    before = {p.name:p.read_bytes() for p in directory.iterdir() if p.is_file()}
    if fault == 'directory':binding['directory_identity']['inode'] += 1
    elif fault == 'database':binding['database_identity']['inode'] += 1
    elif fault == 'lock':binding['lock_identity']['inode'] += 1
    elif fault == 'logical':binding['identity'] = 'f'*32
    else:options['store_proof']['identity']['inode'] += 1
    with pytest.raises(Conflict):
        with open_catalog(binding,**options):pytest.fail('foreign binding admitted')
    assert {p.name:p.read_bytes() for p in directory.iterdir() if p.is_file()} == before


def test_pending_sqlite_state_is_preserved_and_refused(original):
    binding,options,_,_,_ = original;directory = Path(binding['directory'])
    sidecar = directory/'journal.sqlite3-wal';sidecar.write_bytes(b'pending; do not open or remove')
    before = sidecar.read_bytes()
    with pytest.raises(Conflict,match='pending SQLite'):
        with open_catalog(binding,**options):pytest.fail('pending state admitted')
    assert sidecar.read_bytes() == before and not (directory/'journal.sqlite3-shm').exists()


def test_existing_busy_lock_is_not_replaced_or_waited_on(original):
    binding,options,_,_,_ = original
    fd = os.open(Path(binding['directory'])/'workload.lock',os.O_RDONLY)
    try:
        fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        with pytest.raises(Conflict,match='in use'):
            with open_catalog(binding,**options):pytest.fail('busy catalog admitted')
        assert identity(os.fstat(fd)) == binding['lock_identity']
    finally:os.close(fd)


def test_lock_replacement_is_detected_before_another_read(original):
    binding,options,publication,_,_ = original;directory = Path(binding['directory'])
    with pytest.raises(Conflict,match='changed during observation'):
        with open_catalog(binding,**options) as catalog:
            path = directory/'workload.lock';path.rename(directory/'original.lock')
            path.write_bytes(b'foreign lock');path.chmod(0o600)
            catalog.observe(publication['operation_id'])
    assert (directory/'workload.lock').read_bytes() == b'foreign lock'
    assert (directory/'original.lock').exists()


def test_changed_context_invalidates_current_capability(original):
    binding,options,publication,_,state = original
    with pytest.raises(Conflict,match='context changed'):
        with open_catalog(binding,**options) as catalog:
            state['context'] = False
            catalog.observe(publication['operation_id'])


def test_no_lock_is_created_when_original_lock_is_missing(original):
    binding,options,_,_,_ = original;path = Path(binding['directory'])/'workload.lock';path.unlink()
    with pytest.raises(FileNotFoundError):
        with open_catalog(binding,**options):pytest.fail('missing original lock admitted')
    assert not path.exists()


def test_unavailable_connection_is_not_reopened(original):
    binding,options,publication,_,_ = original
    with pytest.raises(Conflict,match='connection unavailable'):
        with open_catalog(binding,**options) as catalog:
            catalog.journal.db.close()
            catalog.observe(publication['operation_id'])
