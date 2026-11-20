"""Initial VM composition with real controllers and inert host/SDK providers."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.backend_reservations import available
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.vm_initial_start import VMInitialStart
from dnlab_runtime.vm_resources import VMResourceRegistry
from test_vm_directory_storage import storage as storage_fixture, directories, definition, template, instance
from test_vm_taps import taps as taps_fixture
from test_vm_boot import boot as boot_fixture
from test_vm_definition_fences import install_fence


@pytest.fixture
def initial(directories, definition, template, monkeypatch):
    directory,definitions,birth,dstate,_,_=directories;operation=birth['creator_operation_id']
    local=(definitions,birth,definitions.read(operation)['xml'],definition[3],definition[4],definition[5])
    taps,value,tstate,_,_,_,_=taps_fixture.__wrapped__(local)
    registry=VMResourceRegistry(definitions);definitions.preflight=registry
    state=dict(storage=None,boot=None,storage_calls=0,asset_scope=True)
    def writers(value):
        record=definitions.read(operation).get('boot',{}).get('process_record')
        return [deepcopy(record)] if record else []
    taps.writers=writers;host=taps.preflight
    def preflight(value):
        result=host(value);result['guest_writers_absent']=not bool(writers(value));return result
    taps.preflight=preflight
    def storage_factory(op):
        assert op==operation
        state['storage_calls']+=1
        if state['storage'] is None:
            storage=storage_fixture.__wrapped__(directories,template,monkeypatch)
            state['storage'],state['files']=storage[0],storage[2]
            state['storage'].writers=writers
        return state['storage']
    def boot_factory(op):
        assert op==operation
        if state['boot'] is None:state['boot']=boot_fixture.__wrapped__(local,monkeypatch)
        return state['boot'][0]
    def assets(**request):
        assert request['birth']==birth and request['template']==template
        if not state['asset_scope'] or request['bundle_root']!='/templates/synthetic':return {}
        return dict(template_sha256=birth['template_sha256'],assets_verified=True)
    def make():
        return VMInitialStart(directory,taps,resources=registry,assets=SimpleNamespace(verify=assets),
                              storage_factory=storage_factory,boot_factory=boot_factory)
    requests=[deepcopy(item['spec']['tap']) for item in value['items']]
    args=(operation,template,'/templates/synthetic',value['context'],requests)
    return SimpleNamespace(driver=make(),make=make,operation=operation,args=args,state=state,
                           directory=dstate,taps=tstate,definitions=definitions,domains=definition[3])


def test_initial_intent_precedes_resources_and_retry_reuses_original_boot(initial):
    e=initial;prepared=e.driver.prepare(*e.args)
    assert prepared['phase']=='pending' and e.directory['creates']==0 and e.state['storage'] is None
    assert not e.taps['creates'] and not e.domains['domains']
    running=e.driver.apply(e.operation)
    assert running['phase']=='running' and running['receipt']['birth']==prepared['birth']
    assert e.directory['creates']==e.state['files']['creates']==1
    assert e.domains['calls'].count(('define',))==1
    assert e.state['boot'][2]['starts']==e.state['boot'][2]['resumes']==1
    assert e.make().prepare(*e.args)==running and e.make().apply(e.operation)==running
    assert e.state['boot'][2]['starts']==e.state['boot'][2]['resumes']==1


def test_lost_directory_reply_recovers_original_without_allocating_disks_twice(initial):
    e=initial;e.driver.prepare(*e.args);e.directory['lost']=True
    with pytest.raises(OSError):e.driver.apply(e.operation)
    assert e.driver.read(e.operation)['last_step']=='directory' and e.state['storage'] is None
    with pytest.raises(RuntimeErrorBase,match='explicit initial recovery'):e.driver.apply(e.operation)
    e.directory['lost']=False
    assert e.make().apply(e.operation,recover=True)['phase']=='running'
    assert e.directory['creates']==e.directory['recovers']==1 and e.state['files']['creates']==1


@pytest.mark.parametrize('fault',['bundle','tap'])
def test_changed_retry_inputs_are_rejected_without_effects(initial,fault):
    e=initial;before=e.driver.prepare(*e.args);args=list(deepcopy(e.args))
    if fault=='bundle':args[2]='/templates/foreign'
    else:args[4][0]['ifindex']+=1
    with pytest.raises(RuntimeErrorBase):e.make().prepare(*args)
    assert e.driver.read(e.operation)==before and not e.taps['creates'] and e.directory['creates']==0


def test_changed_bundle_before_apply_stops_all_resource_effects(initial):
    e=initial;e.driver.prepare(*e.args);e.state['asset_scope']=False
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert e.directory['creates']==0 and not e.taps['creates'] and e.state['storage'] is None


def test_initial_pending_intent_is_an_independent_cleanup_and_backend_fence(initial):
    e=initial;value=e.driver.prepare(*e.args);birth=value['birth'];journal=e.driver.journal
    assert 'vm_initial_starts' in cleanup_inventory(journal,birth['lab_id'])['blocked']
    # Corrupt/incomplete child history is not permission to reuse the node.
    with journal.transaction():journal.db.execute('DELETE FROM vm_definition_intents WHERE id=?',(e.operation,))
    with pytest.raises(RuntimeErrorBase):available(journal,birth['lab_id'],birth['node_id'],'docker')
    assert e.driver.read(e.operation)==value and e.directory['creates']==0


def test_lost_resume_reply_completes_original_boot_without_second_resume(initial):
    e=initial;e.driver.prepare(*e.args);factory=e.driver.boot_factory
    def lost(op):
        driver=factory(op);e.state['boot'][2]['lost_resume']=True;return driver
    e.driver.boot_factory=lost
    with pytest.raises(OSError,match='lost resume'):e.driver.apply(e.operation)
    assert e.driver.read(e.operation)['phase']=='pending'
    assert e.make().apply(e.operation,recover=True)['phase']=='running'
    assert e.state['boot'][2]['starts']==e.state['boot'][2]['resumes']==1


def test_uncertain_start_is_not_reissued_by_parent_retry(initial):
    e=initial;e.driver.prepare(*e.args);factory=e.driver.boot_factory
    def lost(op):
        driver=factory(op);e.state['boot'][2]['lost_start']=True;return driver
    e.driver.boot_factory=lost
    with pytest.raises(OSError,match='lost start'):e.driver.apply(e.operation)
    with pytest.raises(RuntimeErrorBase):e.make().apply(e.operation)
    with pytest.raises(RuntimeErrorBase):e.make().apply(e.operation,recover=True)
    assert e.state['boot'][2]['starts']==1 and e.state['boot'][2]['resumes']==0
    assert e.directory['creates']==e.state['files']['creates']==1


def test_fence_after_boot_keeps_initial_publication_pending_without_stopping_guest(initial):
    e=initial;e.driver.prepare(*e.args);factory=e.driver.boot_factory
    def fenced(op):
        driver=factory(op);apply=driver.apply
        def run(operation):
            result=apply(operation)
            with driver.journal.transaction():install_fence(driver.journal,'held')
            return result
        driver.apply=run
        return driver
    e.driver.boot_factory=fenced
    with pytest.raises(RuntimeErrorBase):e.driver.apply(e.operation)
    assert e.definitions.read(e.operation)['boot']['phase']=='running'
    assert e.driver.read(e.operation)['phase']=='pending' and e.driver.read(e.operation)['receipt'] is None
    assert e.state['boot'][2]['starts']==e.state['boot'][2]['resumes']==1
