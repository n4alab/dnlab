"""Existing worker dispatch and parked TAP attempts with synthetic resources."""
from contextlib import contextmanager
from copy import deepcopy
import threading
import time
from types import SimpleNamespace

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.inspection import cleanup_inventory
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, RuntimeErrorBase, fingerprint
from dnlab_runtime.transport import Server, Client
from dnlab_runtime.vm_tap_device import TUNSETIFF
from dnlab_runtime.vm_tap_retention import TUNSETOWNER
from dnlab_runtime.vm_tap_tasks import TapTasks
from fakes import FakeDocker, FakeLinux
from test_vm_tap_local import local, definition, template, instance, kernel


@pytest.fixture
def task(local):
    taps,provider,original,state,devices,make_provider,make_sets=local
    tasks=TapTasks(taps);queued=tasks.submit(original['id'],state['reference'])
    return tasks,queued,taps,provider,state,devices,make_provider,make_sets


def test_task_execution_is_once_and_completion_is_historical(task):
    tasks,queued,taps,_,state,_,_,_=task
    assert tasks.pending()==[queued['id']] and state['calls']==[]
    done=tasks.execute(queued['id'])
    assert done['phase']=='completed' and done['result_sha256']==fingerprint(taps.observe(queued['id']))
    assert tasks.pending()==[] and state['calls'].count(TUNSETIFF)==2
    assert tasks.submit(queued['id'],state['reference'])==done
    calls=state['calls'][:];state['writer']=True
    assert tasks.execute(queued['id'])==done and state['calls']==calls
    with pytest.raises(RuntimeErrorBase):taps.observe(queued['id'])


def test_lost_response_parks_then_recovers_same_actor_and_fds(task):
    tasks,queued,_,_,state,devices,_,_=task;state['lost_change']=TUNSETOWNER
    parked=tasks.execute(queued['id'])
    assert parked['phase']=='recovery_required' and parked['error_type']=='OSError'
    assert tasks.pending()==[] and state['calls'].count(TUNSETIFF)==1
    fd=devices[0]._fd;birth=deepcopy(devices[0]._birth_proof)
    with pytest.raises(Conflict,match='explicit'):tasks.execute(queued['id'])
    state.pop('lost_change')
    assert tasks.recover(queued['id'])['phase']=='queued'
    assert tasks.execute(queued['id'])['phase']=='completed'
    assert devices[0]._fd==fd and devices[0]._birth_proof==birth
    assert state['calls'].count(TUNSETIFF)==state['calls'].count(TUNSETOWNER)==2


def test_recovery_cannot_adopt_leases_from_a_previous_provider(task):
    tasks,queued,_,_,state,_,make_provider,make_sets=task;state['lost_change']=TUNSETOWNER
    parked=tasks.execute(queued['id']);state.pop('lost_change')
    reopened=TapTasks(make_sets(make_provider()))
    before=state['calls'][:]
    with pytest.raises(Conflict,match='lease unavailable'):reopened.recover(queued['id'])
    assert reopened.read(queued['id'])==parked and state['calls']==before


def test_new_process_identity_cannot_execute_or_replace_original_reference(task,monkeypatch):
    tasks,queued,_,provider,state,devices,_,_=task
    monkeypatch.setattr(provider,'process_id',lambda:9999)
    parked=tasks.execute(queued['id'])
    assert parked['phase']=='recovery_required' and devices==[]
    replacement=deepcopy(state['reference']);replacement['process_record']['pid']=9999
    with pytest.raises(Conflict,match='reference cannot change'):tasks.submit(queued['id'],replacement)
    assert tasks.read(queued['id'])==parked and state['calls']==[]


def test_writer_after_task_checkpoint_blocks_all_kernel_mutations(task,monkeypatch):
    tasks,queued,_,_,state,devices,_,_=task;save=tasks._save
    def changed(value):
        save(value)
        if value['phase']=='applying':state['writer']=True
    monkeypatch.setattr(tasks,'_save',changed)
    assert tasks.execute(queued['id'])['phase']=='recovery_required'
    assert devices==[] and TUNSETIFF not in state['calls']


def test_lost_completion_commit_reply_preserves_completion(task,monkeypatch):
    tasks,queued,_,_,state,_,_,_=task;transaction=tasks.journal.transaction;failed=[]
    @contextmanager
    def lost():
        with transaction():yield
        if tasks.read(queued['id'])['phase']=='completed' and not failed:
            failed.append(True);raise OSError('lost completion reply')
    monkeypatch.setattr(tasks.journal,'transaction',lost)
    completed=tasks.execute(queued['id'])
    assert failed and completed['phase']=='completed' and completed['error']==''
    assert state['calls'].count(TUNSETIFF)==2


def test_interrupted_applying_task_is_not_automatically_resubmitted(task):
    tasks,queued,taps,_,state,_,_,_=task
    current=tasks.read(queued['id']);current['phase']='applying'
    with tasks.journal.transaction():tasks._save(current)
    reopened=TapTasks(taps)
    assert reopened.pending()==[] and reopened.read(queued['id'])==current
    with pytest.raises(Conflict,match='explicit'):reopened.execute(queued['id'])
    assert state['calls']==[]
    reopened.recover(queued['id'])
    assert reopened.execute(queued['id'])['phase']=='completed'


def test_fence_blocks_requeue_without_replacing_the_original_error(task):
    from test_vm_definition_fences import install_fence
    tasks,queued,_,_,state,_,_,_=task;state['writer']=True
    parked=tasks.execute(queued['id']);state['writer']=False
    install_fence(tasks.journal,'held')
    with pytest.raises(Conflict):tasks.recover(queued['id'])
    assert tasks.read(queued['id'])==parked and state['calls']==[]


def test_task_record_alone_blocks_cleanup_and_docker_admission(task):
    from test_vm_tap_reservations import native
    tasks,queued,_,_,_,_,_,_=task
    for table in ('vm_definition_intents','vm_tap_intents','vm_tap_ifindices','vm_tap_actors','resources'):
        tasks.journal.db.execute('DELETE FROM '+table)
    result=cleanup_inventory(tasks.journal,queued['birth']['lab_id'])
    assert result==dict(nodes=[queued['birth']['node_id']],blocked=['vm_tap_tasks'])
    request=native();request.update(lab_id=queued['birth']['lab_id'],node_id=queued['birth']['node_id'])
    with pytest.raises(Conflict,match='reserved by VM'):tasks.journal.submit(request)


def test_engine_accepts_only_optional_service_for_its_original_journal(task,tmp_path):
    tasks,_,_,_,_,_,_,_=task;backend=Backend(FakeDocker(),FakeLinux())
    assert Engine(tasks.journal,backend,vm_tap_tasks=tasks).vm_tap_tasks is tasks
    with pytest.raises(Conflict,match='original runtime journal'):
        other=Journal(tmp_path/'other')
        try:Engine(other,Backend(FakeDocker(),FakeLinux()),vm_tap_tasks=tasks)
        finally:other.close()


def cycle(tasks,order):
    """Run the real sequential loop inline, without creating sockets/threads."""
    server=object.__new__(Server);server.stopping=threading.Event()
    server.engine=SimpleNamespace(journal=SimpleNamespace(pending=lambda:['container']),
        execute=lambda operation:order.append(operation),
        links=SimpleNamespace(pending=lambda:['link'],execute=lambda operation:order.append(operation)),vm_tap_tasks=tasks)
    def wait(timeout):server.stopping.set()
    server.wake=SimpleNamespace(clear=lambda:None,wait=wait)
    Server._work(server)


def test_existing_worker_executes_container_link_then_tap_in_same_cycle(task,monkeypatch):
    tasks,queued,_,_,_,_,_,_=task;order=[];execute=tasks.execute
    def tracked(operation):
        order.append('tap');return execute(operation)
    monkeypatch.setattr(tasks,'execute',tracked)
    cycle(tasks,order)
    assert order==['container','link','tap'] and tasks.read(queued['id'])['phase']=='completed'


def test_parked_tap_failure_does_not_abort_existing_worker_loop(task):
    tasks,queued,_,_,state,_,_,_=task;order=[];state['actor_alive']=False
    cycle(tasks,order)
    assert order==['container','link'] and tasks.read(queued['id'])['phase']=='recovery_required'
    assert tasks.pending()==[]
    state['actor_alive']=True;tasks.recover(queued['id']);cycle(tasks,order)
    assert order==['container','link','container','link'] and tasks.read(queued['id'])['phase']=='completed'


def test_task_replaced_after_checkpoint_is_preserved_without_allocating(task,monkeypatch):
    tasks,queued,_,_,state,devices,_,_=task;save=tasks._save
    def replaced(value):
        save(value)
        if value['phase']=='applying':
            foreign=deepcopy(value);foreign['reference']['token']='f'*32;save(foreign)
    monkeypatch.setattr(tasks,'_save',replaced)
    with pytest.raises(Conflict,match='failure metadata not overwritten'):tasks.execute(queued['id'])
    assert devices==[] and state['calls']==[]
    saved=tasks.read(queued['id'])
    assert saved['phase']=='applying' and saved['reference']['token']=='f'*32 and saved['error']==''


def test_failed_task_commit_never_opens_tun(task,monkeypatch):
    tasks,queued,_,_,state,devices,_,_=task;save=tasks._save
    def fail(value):
        save(value)
        if value['phase']=='applying':raise OSError('synthetic task commit failure')
    monkeypatch.setattr(tasks,'_save',fail)
    result=tasks.execute(queued['id'])
    assert result['phase']=='recovery_required' and result['error_type']=='OSError'
    assert devices==[] and state['calls']==[]


@pytest.mark.parametrize('method',['read','pending'])
def test_readers_do_not_observe_uncommitted_worker_state(task,method):
    from concurrent.futures import ThreadPoolExecutor, TimeoutError
    tasks,queued,_,_,_,_,_,_=task;started=threading.Event()
    def read():
        started.set()
        return tasks.read(queued['id']) if method=='read' else tasks.pending()
    with ThreadPoolExecutor(max_workers=1) as pool:
        try:
            with tasks.journal.transaction():
                tasks.journal.db.execute("UPDATE vm_tap_tasks SET phase='applying' WHERE id=?",(queued['id'],))
                future=pool.submit(read)
                assert started.wait(1)
                with pytest.raises(TimeoutError):future.result(timeout=0.05)
                raise OSError('rollback synthetic incomplete transaction')
        except OSError:pass
        assert future.result(timeout=2)==(queued if method=='read' else [queued['id']])


def test_unix_worker_with_optional_tap_tasks_preserves_container_api(task,tmp_path):
    from test_runtime import request
    tasks,queued,_,_,state,_,_,_=task
    engine=Engine(tasks.journal,Backend(FakeDocker(),FakeLinux()),vm_tap_tasks=tasks)
    socket=tmp_path/'runtime.sock';server=Server(str(socket),engine)
    thread=threading.Thread(target=server.serve_forever);thread.start()
    client=Client(str(socket))
    try:
        assert client.request('GET','/v1/capabilities')['vrnetlab'] is False
        assert client.request('POST','/v1/plan',request())['mutations_performed'] is False
        container=client.request('POST','/v1/operations',request())
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            native=client.request('GET','/v1/operations/'+container['id'])
            if tasks.read(queued['id'])['phase']=='completed' and native['phase']=='completed':break
            time.sleep(0.01)
        assert native['phase']=='completed' and tasks.read(queued['id'])['phase']=='completed'
        assert client.request('GET','/v1/nodes/demo/R1')['container_state']=='running'
        assert state['calls'].count(TUNSETIFF)==2
    finally:
        server.shutdown();server.server_close();thread.join()
