import copy
import json
import multiprocessing
from pathlib import Path
import threading

import pytest

from dnlab_runtime.engine import Engine
from dnlab_runtime.backend import Backend
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.transport import Client,Server
from fakes import FakeDocker,FakeLinux
from test_runtime import request


@pytest.fixture
def runtime(tmp_path):
    journal=Journal(tmp_path/'state');docker=FakeDocker();linux=FakeLinux();engine=Engine(journal,Backend(docker,linux))
    yield engine,journal,docker,linux
    journal.close()


def test_cancel_before_submit_seals_request_without_resources(runtime):
    engine,journal,docker,linux=runtime;raw=request()
    assert journal.find_request('demo','R1','start-1') is None
    cancelled=journal.cancel_request(raw)
    assert cancelled['phase']=='cancelled' and cancelled['cancel_requested']
    assert journal.submit(raw)['id']==cancelled['id'] and engine.execute(cancelled['id'])['phase']=='cancelled'
    assert journal.find_request('demo','R1','start-1')['id']==cancelled['id']
    assert journal.node('demo','R1') is None and not docker.calls and not linux.commands
    assert journal.db.execute('SELECT count(*) FROM resources').fetchone()[0]==0


def test_cancel_with_lost_submit_ack_finds_same_operation(runtime):
    engine,journal,docker,_=runtime;raw=request();accepted=journal.submit(raw)
    cancelled=journal.cancel_request(raw)
    assert cancelled['id']==accepted['id'] and cancelled['cancel_requested']
    assert engine.execute(cancelled['id'])['phase']=='cancelled' and not docker.calls
    assert journal.cancel_request(raw)['id']==accepted['id']


def test_request_lookup_and_cancel_enforce_lab_node_and_content(runtime):
    _,journal,_,_=runtime;raw=request();first=journal.cancel_request(raw)
    with pytest.raises(Conflict):journal.find_request('demo','other','start-1')
    assert journal.find_request('other','R1','start-1') is None
    modified=copy.deepcopy(raw);modified['spec']['command']=['sleep','999']
    with pytest.raises(Conflict):journal.cancel_request(modified)
    with pytest.raises(Conflict):journal.submit(modified)
    other=copy.deepcopy(raw);other['lab_id']='other'
    assert journal.cancel_request(other)['id']!=first['id']
    assert journal.node('other','R1') is None


def test_tombstone_does_not_hide_earlier_active_or_recovery_operation(runtime):
    _,journal,_,_=runtime;raw=request();active=journal.submit(raw)
    journal.cancel_request({**raw,'request_id':'later-cancelled'})
    with pytest.raises(Conflict,match='active'):journal.submit({**raw,'request_id':'third'})
    journal.phase(active['id'],'recovery_required')
    with pytest.raises(Conflict,match='recovery'):journal.submit({**raw,'request_id':'fourth'})
    assert journal.get(active['id'])['phase']=='recovery_required'


def test_cancel_completed_request_does_not_change_workload_or_claim_cancellation(runtime):
    engine,journal,docker,_=runtime;raw=request();op=journal.submit(raw)
    assert engine.execute(op['id'])['phase']=='completed';before=copy.deepcopy(docker.containers)
    value=journal.cancel_request(raw)
    assert value['phase']=='completed' and value['cancel_requested'] is False
    assert docker.containers==before and journal.node('demo','R1')['revision']==1
    assert 'payload' not in value and 'hash' not in value


def test_lookup_and_pre_cancel_through_unix_api(runtime,tmp_path):
    engine,journal,docker,_=runtime;raw=request();server=Server(str(tmp_path/'socket'),engine)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start();client=Client(str(tmp_path/'socket'))
    try:
        path='/v1/operation-requests/demo/R1/start-1'
        assert client.request('GET',path)['operation'] is None
        cancelled=client.request('POST','/v1/cancel-requests',raw)
        assert cancelled['phase']=='cancelled'
        assert client.request('POST','/v1/operations',raw)['id']==cancelled['id']
        assert client.request('GET',path)['operation']['id']==cancelled['id']
        assert not docker.calls
    finally:server.shutdown();server.server_close();thread.join(5)


def test_cross_process_submit_cancel_converge_to_one_operation(runtime):
    _,journal,_,_=runtime;directory=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    context=multiprocessing.get_context('fork');start=context.Event();read,write=context.Pipe(duplex=False)
    def child():
        fresh=Journal(directory);start.wait(5)
        try:write.send(fresh.cancel_request(request())['id'])
        finally:fresh.close()
    process=context.Process(target=child);process.start();start.set();submitted=journal.submit(request())
    process.join(5)
    if process.is_alive():process.kill();process.join();pytest.fail('request cancellation worker timeout')
    assert process.exitcode==0 and read.poll(1) and read.recv()==submitted['id']
    state=journal.get(submitted['id']);assert state['cancel_requested']
    assert journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]==1


def test_pre_cancelled_stop_dedupes_without_touching_current_links(runtime,tmp_path):
    engine,journal,docker,_=runtime;raw=request(action='stop');raw.pop('spec')
    def forbidden(*args):pytest.fail('cancelled stop must not inspect or detach current links')
    engine.links.node_free=forbidden
    server=Server(str(tmp_path/'socket'),engine);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    client=Client(str(tmp_path/'socket'))
    try:
        cancelled=client.request('POST','/v1/cancel-requests',raw)
        assert client.request('POST','/v1/operations',raw)['id']==cancelled['id']
        assert not docker.calls
    finally:server.shutdown();server.server_close();thread.join(5)


@pytest.mark.parametrize('boundary',['before','after'])
def test_cancel_request_survives_actual_process_death(runtime,boundary):
    import os
    import signal
    _,journal,_,_=runtime;directory=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    context=multiprocessing.get_context('fork')
    def child():
        import sqlite3
        fresh=Journal(directory)
        if boundary=='before':
            def interrupt(action,argument,*args):
                if action==sqlite3.SQLITE_TRANSACTION and argument=='COMMIT':os.kill(os.getpid(),signal.SIGKILL)
                return sqlite3.SQLITE_OK
            fresh.db.set_authorizer(interrupt)
        fresh.cancel_request(request())
        os.kill(os.getpid(),signal.SIGKILL)
    process=context.Process(target=child);process.start();process.join(5)
    if process.is_alive():process.kill();process.join();pytest.fail('cancel commit worker timeout')
    assert process.exitcode==-signal.SIGKILL
    found=journal.find_request('demo','R1','start-1')
    assert (found is None)==(boundary=='before')
    sealed=journal.cancel_request(request());assert sealed['phase']=='cancelled'
    assert journal.submit(request())['id']==sealed['id']
    assert journal.db.execute('SELECT count(*) FROM resources').fetchone()[0]==0


def test_pinned_journal_mismatch_refuses_before_any_request_mutation(runtime,tmp_path):
    engine,journal,docker,_=runtime;server=Server(str(tmp_path/'socket'),engine)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        client=Client(str(tmp_path/'socket'),expected_journal_id='0'*32)
        from dnlab_runtime.manifest import RuntimeErrorBase
        for path in ('/v1/operations','/v1/cancel-requests'):
            with pytest.raises(RuntimeErrorBase,match='journal identity'):client.request('POST',path,request())
        assert journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0 and not docker.calls
        assert Client(str(tmp_path/'socket')).request('GET','/v1/capabilities')['journal_id']==journal.identity
    finally:server.shutdown();server.server_close();thread.join(5)


def test_runtime_journal_identity_is_stable_and_distinct(tmp_path):
    first=Journal(tmp_path/'one');identity=first.identity;first.close()
    first=Journal(tmp_path/'one');second=Journal(tmp_path/'two')
    try:assert first.identity==identity and second.identity!=identity
    finally:first.close();second.close()


def test_matching_lookup_verifies_body_without_disclosing_it(runtime,tmp_path):
    engine,journal,docker,_=runtime;raw=request();op=journal.submit(raw)
    changed=copy.deepcopy(raw);changed['spec']['command']=['sleep','999']
    with pytest.raises(Conflict,match='different content'):journal.find_matching_request(changed)
    assert journal.find_matching_request(raw)['id']==op['id']
    assert 'payload' not in journal.find_matching_request(raw) and 'hash' not in journal.find_matching_request(raw)
    server=Server(str(tmp_path/'socket'),engine);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        client=Client(str(tmp_path/'socket'),expected_journal_id=journal.identity)
        assert client.request('POST','/v1/operation-requests',raw)['operation']['id']==op['id']
        from dnlab_runtime.manifest import RuntimeErrorBase
        with pytest.raises(RuntimeErrorBase,match='different content'):client.request('POST','/v1/operation-requests',changed)
    finally:server.shutdown();server.server_close();thread.join(5)
