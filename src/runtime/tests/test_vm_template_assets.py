"""Published temporary bundles feeding real VM storage contracts, no hypervisor."""
from copy import deepcopy
import hashlib

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_xml import render_domain
from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from dnlab_runtime.vm_storage import VMStorage
from dnlab_runtime.vm_template import template_digest
from dnlab_runtime.vm_template_assets import PublishedTemplateAssets
from dnlab_runtime.vm_template_files import identity
from dnlab_runtime.vm_template_install import TemplateBundleInstall, bundle_plan
from test_vm_bundle import bundle, template
from test_vm_definition import definition
from test_vm_template import instance


@pytest.fixture
def catalog(bundle,tmp_path):
    source,template,_ = bundle
    root = tmp_path/'catalog';root.mkdir(mode=0o755);root.chmod(0o755)
    raw = (source/'manifest.json').read_bytes()
    manifest = dict(sha256=hashlib.sha256(raw).hexdigest(),size=len(raw))
    plan = bundle_plan(str(root),str(source),template,manifest)
    agreement = dict(operation_id='catalog-import',context=dict(host_id='worker',boot_id='synthetic'),
                     targets=[s['key'] for s in plan],nonce='a'*32)
    window = ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    journal = Journal(tmp_path/'catalog-journal')
    def make(readonly):
        return TemplateBundleInstall(journal,root=str(root),parent_identity=identity(root.stat()),
            window=window,preflight=lambda r:dict(request_sha256=fingerprint(r),exclusive_writer=True),readonly=readonly)
    writer = make(False);writer.prepare('catalog-import',source=str(source),template_sha256=template_digest(template))
    publication = writer.apply('catalog-import');readonly = make(True)
    # Consumption cannot revive the import window or run import preflight.
    window.observe = lambda:pytest.fail('asset admission cannot reopen an administrative window')
    writer.preflight = readonly.preflight = lambda r:pytest.fail('readonly catalog cannot import')
    yield writer,readonly,publication,deepcopy(publication['bundle']['template']),source
    journal.close()


@pytest.fixture
def consumer(catalog,instance):
    _,readonly,publication,template,_ = catalog
    provider = PublishedTemplateAssets(readonly,host_id='worker',publication=publication)
    birth = {k:instance['domain'][k] for k in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256'] = template_digest(template)
    value = dict(id=birth['creator_operation_id'],birth=birth,template=template,bundle_root=publication['directory'])
    return provider,value


def test_original_publication_is_consumed_readonly_without_staging(consumer,catalog):
    provider,value = consumer
    import shutil
    shutil.rmtree(catalog[-1])
    before = catalog[1].journal.db.total_changes
    assert provider(value) == dict(template_sha256=value['birth']['template_sha256'],assets_verified=True)
    assert catalog[1].journal.db.total_changes == before


@pytest.mark.parametrize('fault',['host','template','digest','path','owner'])
def test_vm_request_cannot_substitute_template_host_path_or_owner(consumer,fault):
    provider,value = consumer;value = deepcopy(value)
    if fault == 'host':value['birth']['host_id'] = 'another-worker'
    elif fault == 'template':value['template']['hardware']['memory_mib'] += 1
    elif fault == 'digest':value['birth']['template_sha256'] = 'f'*64
    elif fault == 'path':value['bundle_root'] = '/another/store/'+value['birth']['template_sha256']
    else:value['id'] = 'another-storage-operation'
    with pytest.raises(Conflict):provider(value)


def test_writer_catalog_cannot_be_used_for_vm_asset_admission(catalog):
    writer,_,publication,_,_ = catalog
    with pytest.raises(Conflict,match='readonly'):
        PublishedTemplateAssets(writer,host_id='worker',publication=publication)


def test_live_publication_state_is_required_even_with_identical_files(consumer,catalog):
    provider,value = consumer;writer,_,publication,_,_ = catalog
    state = writer.read(publication['operation_id']);state.update(phase='installing',proof=None)
    writer._save(state)
    with pytest.raises(Conflict,match='publication missing'):provider(value)


@pytest.mark.parametrize('fault',['logical-journal','journal-object','host-capability','publication-reply','closed-during-observation'])
def test_catalog_capability_changes_cannot_rebind_the_provider(consumer,catalog,monkeypatch,fault):
    from types import SimpleNamespace
    provider,value = consumer;readonly = catalog[1]
    if fault == 'logical-journal':monkeypatch.setattr(readonly.journal,'identity','f'*32)
    elif fault == 'journal-object':monkeypatch.setattr(readonly,'journal',SimpleNamespace(identity=readonly.journal.identity))
    elif fault == 'host-capability':
        provider.host_id = 'another-worker';value = deepcopy(value);value['birth']['host_id'] = 'another-worker'
    elif fault == 'publication-reply':
        changed = deepcopy(catalog[2]);changed['operation_id'] = 'another-import'
        monkeypatch.setattr(readonly,'observe',lambda operation:deepcopy(changed))
    else:
        observe = readonly.observe
        def closed(operation):
            result = observe(operation)
            monkeypatch.setattr(readonly.journal,'closed',True)
            return result
        monkeypatch.setattr(readonly,'observe',closed)
    with pytest.raises(Conflict):provider(value)


@pytest.fixture
def store_vm(catalog,definition,instance,tmp_path):
    original = definition[0]
    provider = PublishedTemplateAssets(catalog[1],host_id='worker',publication=catalog[2])
    template = catalog[3];instance = deepcopy(instance)
    instance['bundle_root'] = catalog[2]['directory']
    instance['domain'].update(name='catalog-vd',uuid='87654321-1234-4234-8234-123456789abc',
                              lab_id='catalog-lab',node_id='catalog-vd',creator_operation_id='e'*32,nonce='f'*32)
    birth = {k:instance['domain'][k] for k in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
    birth['template_sha256'] = template_digest(template)
    journal = Journal(tmp_path/'vm-journal')
    definitions = VMDefinitionDriver(journal,original.connection,original.session,original.preflight,no_domain_code=42)
    definitions.prepare('catalog-vm',birth,render_domain(template,**instance))
    state = dict(files={},creates=0)
    class Files:
        def observe(self,item,operation):return deepcopy(state['files'].get(item['spec']['path']))
        def create(self,item,operation):
            state['creates'] += 1;spec = item['spec']
            proof = dict(operation_id=operation,nonce=item['nonce'],spec_sha256=fingerprint(spec),
                identity=dict(device=4,inode=1234,uid=spec['uid'],gid=spec['gid'],mode=spec['mode']),
                creation=dict(request_sha256=fingerprint(dict(operation_id=operation,nonce=item['nonce'],spec=spec)),
                              worker_reference_sha256='d'*64,exit_code=0))
            state['files'][spec['path']] = proof
            return deepcopy(proof)
        def recover(self,*args):pytest.fail('no original formatter is pending in this fixture')
    driver = VMStorage(definitions,assets=provider,files=Files(),writers=lambda value:[])
    yield driver,birth,template,catalog[2],state
    journal.close()


def test_real_storage_preflight_uses_published_catalog_and_rejects_changed_assets(store_vm):
    from pathlib import Path
    driver,birth,template,publication,state = store_vm;operation = birth['creator_operation_id']
    driver.prepare(operation,template,publication['directory'])
    ready = driver.apply(operation)
    assert ready['phase'] == 'ready' and state['creates'] == 1
    assert ready['items'][0]['spec']['base_path'] == publication['directory']+'/disks/base.qcow2'
    original = deepcopy(state['files'])
    path = Path(ready['items'][0]['spec']['base_path']);path.chmod(0o600);path.write_bytes(b'foreign');path.chmod(0o444)
    with pytest.raises(Conflict):driver.observe(operation)
    assert state['creates'] == 1 and state['files'] == original


def test_wrong_bundle_path_blocks_real_storage_before_allocations(store_vm):
    driver,birth,template,publication,state = store_vm
    with pytest.raises(Conflict,match='bundle path differs'):
        driver.prepare(birth['creator_operation_id'],template,publication['directory']+'-alias')
    assert state['creates'] == 0 and state['files'] == {}
    assert driver.journal.db.execute('SELECT count(*) FROM vm_storage_intents').fetchone()[0] == 0
