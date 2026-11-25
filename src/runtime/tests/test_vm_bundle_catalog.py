"""Later imports retain the original store birth in its own readonly journal."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path
import shutil
import sqlite3

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template import template_digest
from dnlab_runtime.vm_template_assets import PublishedTemplateAssets
from dnlab_runtime.vm_template_files import identity
from dnlab_runtime.vm_template_install import TemplateBundleInstall, bundle_plan
from tools.vm_template_catalog import open_catalog, open_bundle_catalog, store_reference
from test_vm_template_catalog import original, bundle, template, instance


@pytest.fixture
def later(original, tmp_path):
    binding, options, first, value, state = original
    second = deepcopy(value['template']);second['id'] = 'second-template'
    source = tmp_path/'second-source';source.mkdir(mode=0o700)
    for asset in second['assets'].values():
        target = source/asset['path'];target.parent.mkdir(parents=True,exist_ok=True)
        shutil.copyfile(Path(first['directory'])/asset['path'],target)
    raw = (json.dumps(second,sort_keys=True)+'\n').encode();(source/'manifest.json').write_bytes(raw)
    directory = tmp_path/'second-journal';journal = Journal(directory)
    try:
        with open_catalog(binding,**options) as store:
            reference = store_reference(store)
            specs = bundle_plan(store.root,str(source),second,dict(sha256=hashlib.sha256(raw).hexdigest(),size=len(raw)))
            agreement = dict(operation_id='second-import',context=options['import_window']['context'],
                             nonce='e'*32,targets=[spec['key'] for spec in specs])
            def active():
                assert store_reference(store) == reference
                return deepcopy(agreement)
            def preflight(request):
                active();return dict(request_sha256=fingerprint(request),exclusive_writer=True)
            driver = TemplateBundleInstall(journal,root=store.root,parent_identity=store.parent,
                window=ProvisioningWindow(agreement,active),preflight=preflight)
            driver.prepare('second-import',source=str(source),template_sha256=template_digest(second))
            published = driver.apply('second-import')
            assert journal.db.execute('SELECT 1 FROM libvirt_install_file_births WHERE operation_id=?',
                                      (options['store_operation'],)).fetchone() is None
            logical = journal.identity
    finally:journal.close()
    later_binding = dict(directory=str(directory),identity=logical,directory_identity=identity(directory.stat()),
        database_identity=identity((directory/'journal.sqlite3').stat()),lock_identity=identity((directory/'workload.lock').stat()))
    request = deepcopy(value);request['template'] = second;request['birth']['template_sha256'] = template_digest(second)
    request['bundle_root'] = published['directory']
    return original,later_binding,reference,published,agreement,request


def files(binding):
    return {path.name:path.read_bytes() for path in Path(binding['directory']).iterdir() if path.is_file()}


def test_later_publication_is_readonly_and_keeps_both_original_journals(later):
    (binding,options,_,_,_),second,reference,publication,agreement,request = later
    before = [files(binding),files(second)]
    with open_catalog(binding,**options) as store:
        with open_bundle_catalog(second,store=store,original_store=reference,
                publication=publication,import_window=agreement,verify=options['verify']) as catalog:
            provider = PublishedTemplateAssets(catalog,host_id='worker',publication=publication)
            assert provider(request) == dict(template_sha256=publication['template_sha256'],assets_verified=True)
            assert catalog.journal.identity != store.journal.identity
            receipt = deepcopy(catalog.binding)
            with pytest.raises(sqlite3.OperationalError,match='readonly'):
                catalog.journal.db.execute('DELETE FROM vm_template_bundle_imports')
            for action in (catalog.prepare,catalog.apply,catalog.recover):
                with pytest.raises(Conflict,match='readonly'):action('anything')
            assert catalog.journal.db.total_changes == store.journal.db.total_changes == 0
        assert catalog.journal.closed
        with pytest.raises(Conflict,match='closed'):provider(request)
        with open_bundle_catalog(second,store=store,original_store=reference,publication=publication,
                import_window=agreement,verify=options['verify'],expected_binding=receipt) as reopened:
            assert reopened.observe(publication['operation_id']) == publication
    assert [files(binding),files(second)] == before


@pytest.mark.parametrize('fault', ['directory','database','lock','logical','store','publication'])
def test_foreign_dependencies_are_refused_without_sidecars_or_writes(later,fault):
    (binding,options,_,_,_),second,reference,publication,agreement,_ = later
    second,reference,publication = deepcopy((second,reference,publication))
    before = [files(binding),files(second)]
    if fault in ('directory','database','lock'):second[fault+'_identity']['inode'] += 1
    elif fault == 'logical':second['identity'] = 'f'*32
    elif fault == 'store':reference['parent']['inode'] += 1
    else:publication['bundle']['assets']['base']['sha256'] = 'f'*64
    with open_catalog(binding,**options) as store:
        with pytest.raises(Conflict):
            with open_bundle_catalog(second,store=store,original_store=reference,
                    publication=publication,import_window=agreement,verify=options['verify']):
                pytest.fail('foreign later publication accepted')
    assert [files(binding),files(second)] == before


def test_pending_later_wal_is_preserved_without_opening_it(later):
    (binding,options,_,_,_),second,reference,publication,agreement,_ = later
    wal = Path(second['directory'])/'journal.sqlite3-wal';wal.write_bytes(b'pending original bytes')
    with open_catalog(binding,**options) as store:
        with pytest.raises(Conflict,match='pending SQLite'):
            with open_bundle_catalog(second,store=store,original_store=reference,
                    publication=publication,import_window=agreement,verify=options['verify']):
                pytest.fail('pending later journal accepted')
    assert wal.read_bytes() == b'pending original bytes'
    assert not (wal.parent/'journal.sqlite3-shm').exists()


def test_store_dependency_cannot_be_replaced_while_later_reader_is_live(later):
    (binding,options,_,_,_),second,reference,publication,agreement,_ = later
    with open_catalog(binding,**options) as store:
        with open_bundle_catalog(second,store=store,original_store=reference,
                publication=publication,import_window=agreement,verify=options['verify']) as catalog:
            check = store.check
            try:
                store.check = lambda:None
                with pytest.raises(Conflict,match='dependency changed'):catalog.observe(publication['operation_id'])
            finally:store.check = check


def test_closed_original_store_cannot_authorize_a_later_reader(later):
    (binding,options,_,_,_),second,reference,publication,agreement,_ = later
    with open_catalog(binding,**options) as store:pass
    with pytest.raises(Conflict,match='live original'):
        with open_bundle_catalog(second,store=store,original_store=reference,
                publication=publication,import_window=agreement,verify=options['verify']):
            pytest.fail('closed store accepted')
