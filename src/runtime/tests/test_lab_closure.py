from copy import deepcopy
import threading

import pytest

from dnlab_runtime.lab_closure import control,get
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict
from test_runtime import runtime,request,stop,run

TOKEN='c'*32


def start_and_park(runtime):
    engine,journal,docker,linux=runtime
    linux.network_identity=lambda:{'boot':'test','namespace':'fixture'}
    start=request();start['spec']['endpoints']=[]
    assert run(engine,journal,start)['phase']=='completed'
    shutdown=stop(stop_mode='coordinated')
    op=run(engine,journal,shutdown)
    assert op['phase']=='awaiting_link_cleanup',op
    return engine,journal,docker,linux,start,shutdown,op


def close(engine,shutdown,**options):
    return control(engine,'demo','close',{'closure_id':TOKEN,'generation':1,'stops':[shutdown],**options})


def finish_stop(engine,journal,op):
    for stage in ('cleanup','finalize'):
        engine.stops.request_stage(op['id'],'demo','R1',stage)
        result=engine.execute(op['id'])
    assert result['phase']=='completed'


def test_fence_blocks_delayed_start_and_precancel_but_allows_original_stop(runtime):
    engine,journal,docker,linux,start,shutdown,op=start_and_park(runtime)
    assert close(engine,shutdown)['phase']=='closing'
    before=deepcopy(docker.containers);calls=list(docker.calls)
    for method in (journal.submit,journal.cancel_request,engine.plan):
        with pytest.raises(Conflict,match='closing or closed'):
            method({**start,'request_id':'late-start','expected_revision':1,'node_id':'other'})
    with pytest.raises(Conflict,match='still pending'):control(engine,'demo','finish',{'closure_id':TOKEN,'generation':1})
    assert docker.containers==before and docker.calls==calls
    finish_stop(engine,journal,op)
    assert control(engine,'demo','finish',{'closure_id':TOKEN,'generation':1})['phase']=='closed'
    with pytest.raises(Conflict,match='closing or closed'):journal.submit({**start,'request_id':'late','expected_revision':2})


def test_closed_tombstone_survives_connection_restart_and_reopen_needs_new_generation(runtime):
    engine,journal,docker,linux,start,shutdown,op=start_and_park(runtime)
    close(engine,shutdown);finish_stop(engine,journal,op)
    control(engine,'demo','finish',{'closure_id':TOKEN,'generation':1})
    from pathlib import Path
    other=Journal(Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent)
    try:
        assert get(other,'demo')['phase']=='closed'
        with pytest.raises(Conflict):other.submit({**start,'request_id':'stale','expected_revision':2})
    finally:other.close()
    raw={'closure_id':TOKEN,'generation':1,'request_id':'explicit-reopen'}
    reopened=control(engine,'demo','reopen',raw)
    assert reopened['generation']==2 and reopened['phase']=='open'
    assert control(engine,'demo','reopen',raw)==reopened
    with pytest.raises(Conflict,match='generation'):journal.submit({**start,'request_id':'stale','expected_revision':2})
    assert run(engine,journal,{**start,'request_id':'new-generation','expected_revision':2,'lab_generation':2})['phase']=='completed'
    assert journal.db.execute('SELECT count(*) FROM lab_closure_history').fetchone()[0]==1


@pytest.mark.parametrize('tamper',['token','epoch','manifest'])
def test_conflicting_closure_cannot_replace_existing_fence(runtime,tamper):
    engine,journal,docker,linux,start,shutdown,op=start_and_park(runtime)
    first=close(engine,shutdown);before=get(journal,'demo')
    options={'closure_id':'d'*32} if tamper=='token' else {'generation':2} if tamper=='epoch' else {'stops':[{**shutdown,'request_id':'wrong'}]}
    with pytest.raises(Conflict):close(engine,shutdown,**options)
    assert get(journal,'demo')==before
    assert close(engine,shutdown)==first


def test_non_teardown_intent_prevents_closure_without_mutating_workload(runtime):
    engine,journal,docker,linux=runtime
    linux.network_identity=lambda:{'boot':'test','namespace':'fixture'}
    start=request();start['spec']['endpoints']=[]
    queued=journal.submit(start)
    with pytest.raises(Conflict,match='outside the qualified'):close(engine,stop(stop_mode='coordinated'))
    assert get(journal,'demo') is None and docker.containers=={}
    assert journal.get(queued['id'])['phase']=='queued'


def test_concurrent_submit_and_close_cannot_both_commit(runtime):
    engine,journal,docker,linux,start,shutdown,op=start_and_park(runtime)
    from pathlib import Path
    other=Journal(Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent)
    barrier=threading.Barrier(2);results={}
    def submit():
        barrier.wait()
        try:other.submit({**start,'node_id':'R2','request_id':'race','spec':{**start['spec'],'container_name':'other'}});results['submit']='ok'
        except Conflict:results['submit']='rejected'
    worker=threading.Thread(target=submit);worker.start();barrier.wait()
    try:
        try:close(engine,shutdown);results['close']='ok'
        except Conflict:results['close']='rejected'
        worker.join(5);assert not worker.is_alive()
        assert sorted(results.values())==['ok','rejected']
    finally:other.close()
