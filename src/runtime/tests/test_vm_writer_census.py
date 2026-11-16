"""Synthetic procfs and original service/QEMU receipts; no real processes."""
from copy import deepcopy
import os

import pytest

from dnlab_runtime.manifest import Conflict, fingerprint
from dnlab_runtime.vm_template import TemplateError
from dnlab_runtime.vm_writer_census import DedicatedProcessInventory, SessionWriterCensus, UNITS
from test_vm_definition import definition, template, instance
from test_vm_storage import writer_record
from test_vm_directory_storage import storage as directory_storage, directories


@pytest.fixture
def proc_inventory(tmp_path):
    proc = tmp_path/'proc';proc.mkdir()
    (proc/'self').symlink_to(str(os.getpid()))
    own = proc/str(os.getpid());(own/'ns').mkdir(parents=True)
    context = dict(host_id='worker',boot_id='fake-boot',namespaces={})
    for name in ('pid','mnt','net','user'):
        p = own/'ns'/name;p.write_bytes(b'namespace')
        info = p.stat();context['namespaces'][name] = dict(device=info.st_dev,inode=info.st_ino)
    boot = proc/'sys/kernel/random/boot_id';boot.parent.mkdir(parents=True);boot.write_text('fake-boot\n')
    def status(pid,uid=1001,gid=1002,groups='993'):
        root = proc/str(pid);root.mkdir(exist_ok=True)
        (root/'status').write_text(f'Uid:\t{uid} {uid} {uid} {uid}\nGid:\t{gid} {gid} {gid} {gid}\nGroups:\t{groups}\n')
    status(os.getpid(),uid=0,gid=0,groups='0');status(1234);status(4321,uid=0,gid=0,groups='0')
    info = proc.stat();state = deepcopy(context)
    def make():return DedicatedProcessInventory(uid=1001,gid=1002,context=context,read_context=lambda:deepcopy(state),
        proc_identity=dict(device=info.st_dev,inode=info.st_ino),proc_root=str(proc))
    return make(),make,proc,status,state


def test_proc_inventory_selects_credentials_without_claiming_process_birth(proc_inventory):
    inventory,_,proc,_,_ = proc_inventory
    before = {str(p.relative_to(proc)):p.read_bytes() for p in proc.rglob('status')}
    assert inventory()==[dict(pid=1234,uids=[1001]*4,gids=[1002]*4,groups=[993])]
    assert {str(p.relative_to(proc)):p.read_bytes() for p in proc.rglob('status')}==before


@pytest.mark.parametrize('fault',['namespace','boot','status','symlink'])
def test_incomplete_or_changed_inventory_refuses(proc_inventory,fault):
    inventory,_,proc,_,state = proc_inventory
    if fault=='namespace':state['namespaces']['pid']['inode'] += 1
    elif fault=='boot':(proc/'sys/kernel/random/boot_id').write_text('new-boot')
    elif fault=='status':(proc/'1234/status').write_text('Uid: 1001\n')
    else:
        (proc/'1234').rename(proc/'original');(proc/'1234').symlink_to('original')
    with pytest.raises((Conflict,TemplateError,OSError)):inventory()


def test_supplementary_session_group_is_also_a_candidate(proc_inventory):
    inventory,_,_,status,_ = proc_inventory;status(4321,uid=0,gid=0,groups='0 1002')
    assert {row['pid'] for row in inventory()}=={1234,4321}


@pytest.fixture
def census(definition):
    definitions,birth,_,_,_,_ = definition
    namespaces = {name:dict(device=4,inode=i+100) for i,name in enumerate(('pid','mnt','net','user'))}
    services = {unit:dict(pid=i,start_ticks=i+100,boot_id='fake-boot',namespaces=deepcopy(namespaces),pidfd_alive=True,
        uids=[1001]*4,gids=[1001]*4,groups=[],executable_sha256='e'*64,argv=['synthetic'],environment={})
        for i,unit in enumerate(UNITS,10)}
    rows = [{key:value[key] for key in ('pid','uids','gids','groups')} for value in services.values()]
    state = dict(rows=deepcopy(rows),services=deepcopy(services),inventory_hook=None,observer_hook=None,calls=0)
    def inventory():
        result = deepcopy(state['rows'])
        if state['inventory_hook']:state['inventory_hook']()
        return result
    def observer(reference,record):
        def observe(original):
            state['calls'] += 1
            assert reference['birth']==original==record['birth']
            if state['observer_hook']:state['observer_hook']()
            return dict(birth=deepcopy(original),process=deepcopy(record['process']),config_sha256='f'*64)
        return observe
    driver = SessionWriterCensus(definitions,inventory=inventory,services=services,
        observe_services=lambda:deepcopy(state['services']),observer=observer)
    owner = definitions.read(birth['creator_operation_id'])
    storage = dict(id=birth['creator_operation_id'],birth=deepcopy(birth),definition_sha256=owner['request_fingerprint'])
    def boot():
        value = definitions.read(birth['creator_operation_id']);record = writer_record(birth)
        record['process']['boot_id'] = 'fake-boot'
        reference = dict(birth=deepcopy(birth),process_sha256=fingerprint(record['process']),uri='qemu:///session')
        value['boot'] = dict(phase='paused',process_record=record,reference=reference)
        with definitions.journal.transaction():definitions._save(birth['creator_operation_id'],value)
        state['rows'].append(dict(pid=record['process']['pid'],uids=[1001]*4,gids=[1001]*4,groups=[]))
        return record
    return driver,storage,state,boot,definitions


def test_no_guest_writer_with_only_original_daemons(census):
    driver,storage,state,_,_ = census
    before = driver.journal.db.total_changes
    assert driver(storage)==[] and state['calls']==0
    assert driver.journal.db.total_changes==before


def test_original_registered_qemu_is_verified_before_and_after_census(census):
    driver,storage,state,boot,_ = census;record = boot()
    assert driver(storage)==[record] and state['calls']==2


@pytest.mark.parametrize('fault',['foreign-process','missing-daemon','changed-daemon','missing-qemu','changed-qemu','duplicate-pid'])
def test_unqualified_session_never_authorizes_storage(census,fault):
    driver,storage,state,boot,_ = census
    if fault in ('missing-qemu','changed-qemu'):boot()
    if fault=='foreign-process':state['rows'].append(dict(pid=999,uids=[1001]*4,gids=[1001]*4,groups=[]))
    elif fault=='missing-daemon':state['rows'].pop(0)
    elif fault=='changed-daemon':state['services'][UNITS[0]]['start_ticks'] += 1
    elif fault=='missing-qemu':state['rows'].pop()
    elif fault=='changed-qemu':state['rows'][-1]['uids'][1] = 0
    else:state['rows'].append(deepcopy(state['rows'][0]))
    with pytest.raises((Conflict,TemplateError)):driver(storage)


def test_inventory_drift_during_observation_refuses(census):
    driver,storage,state,_,_ = census
    state['inventory_hook'] = lambda:state['rows'].pop() if state['rows'] else None
    with pytest.raises(TemplateError,match='changed during'):driver(storage)


def test_vm_generation_change_during_observation_refuses(census):
    driver,storage,state,boot,definitions = census;boot()
    def change():
        value = definitions.read(storage['id']);value['diagnostic'] = 'changed'
        with definitions.journal.transaction():definitions._save(storage['id'],value)
    state['observer_hook'] = change
    with pytest.raises(TemplateError,match='generation changed'):driver(storage)


def test_uncertain_boot_without_record_does_not_prove_absence(census):
    driver,storage,_,_,definitions = census
    value = definitions.read(storage['id']);value['boot'] = dict(phase='start_requested',process_record=None)
    with definitions.journal.transaction():definitions._save(storage['id'],value)
    with pytest.raises(TemplateError,match='uncertain QEMU'):driver(storage)


def test_other_vm_owner_is_rejected_before_census(census):
    driver,storage,state,_,_ = census;storage['birth']['nonce'] = 'a'*32
    with pytest.raises(TemplateError,match='original VM owner'):driver(storage)
    assert state['calls']==0


def test_composed_directory_storage_uses_session_census_at_overlay_checkpoints(census,directory_storage):
    _,_,state,_,_ = census
    storage,operation,files,_,_,_,definitions,_ = directory_storage
    services = deepcopy(state['services'])
    storage.writers = SessionWriterCensus(definitions,inventory=lambda:deepcopy(state['rows']),
        services=services,observe_services=lambda:deepcopy(state['services']))
    ready = storage.apply(operation)
    assert ready['phase']=='ready' and files['creates']==1
    state['rows'].append(dict(pid=999,uids=[1001]*4,gids=[1001]*4,groups=[]))
    before = definitions.journal.db.total_changes
    with pytest.raises(TemplateError,match='unqualified process'):storage.observe(operation)
    assert files['creates']==1 and definitions.journal.db.total_changes==before
