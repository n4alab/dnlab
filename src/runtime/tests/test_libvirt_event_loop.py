"""Supervisor with fake SDK/thread; no native loop, daemon or guest runs."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_event_loop import EventLoopRegistry, LibvirtEventLoop
from dnlab_runtime.manifest import RuntimeErrorBase
from test_vm_runtime_process import runtime_process
from test_libvirt_sdk import case


@pytest.fixture
def event_loop(runtime_process):
    runtime,epoch,_,runtime_state,_=runtime_process
    calls=[];state=dict(clock=0.0,tid=700,register=0,iteration=0,no_heartbeat=False,error=None,timer=7,starts=0)
    sdk=SimpleNamespace()
    def register():calls.append('register');return state['register']
    def add_timeout(interval,callback,opaque):
        calls.append(('timer',interval));state.update(callback=callback,opaque=opaque)
        return state['timer']
    def iterate():
        calls.append('iterate')
        if state['error']:raise state['error']
        state['clock']+=0.1
        if not state['no_heartbeat']:state['callback'](state['timer'],state['opaque'])
        return state['iteration']
    sdk.virEventRegisterDefaultImpl=register
    sdk.virEventAddTimeout=add_timeout
    sdk.virEventRunDefaultImpl=iterate
    class Thread:
        def __init__(self,*,target,name,daemon):
            assert daemon is True and name.startswith('dnlab-libvirt-events-')
            self.target,self.native_id,self.alive=target,state['tid'],False
        def start(self):
            state['starts']+=1;self.alive=True
            owner=self.target.__self__
            owner._begin_thread();owner._iterate()
        def is_alive(self):return self.alive
    registry=EventLoopRegistry()
    def make():
        return LibvirtEventLoop(runtime,sdk,thread_factory=Thread,clock=lambda:state['clock'],
                                process_id=lambda:runtime_state['pid'],native_id=lambda:state['tid'],
                                registry=registry,startup_timeout=0.001)
    return SimpleNamespace(runtime=runtime,epoch=epoch,runtime_state=runtime_state,calls=calls,state=state,
                           sdk=sdk,make=make,loop=make())


def test_original_loop_receipt_is_stable_while_heartbeat_advances(event_loop):
    e=event_loop;receipt=e.loop.start()
    assert e.calls==['register',('timer',100),'iterate']
    assert e.loop.check()==receipt
    e.loop._iterate()
    assert e.loop.check()==receipt and e.loop.ticks==2 and e.loop.iterations==2
    row=e.runtime.journal.db.execute('SELECT * FROM vm_libvirt_event_loops').fetchone()
    assert row['epoch_id']==e.epoch['id'] and e.loop.thread.native_id==700
    assert e.state['starts']==1


def test_process_global_reservation_prevents_second_loop_even_with_same_epoch(event_loop):
    e=event_loop;e.loop.start()
    with pytest.raises(RuntimeErrorBase,match='already reserved'):e.make().start()
    assert e.calls.count('register')==1 and e.state['starts']==1


@pytest.mark.parametrize('fault',['dead_thread','tid','stale','clock_back','epoch','journal','callback','configuration'])
def test_lost_continuity_never_becomes_valid_again(event_loop,fault):
    e=event_loop;e.loop.start();original=deepcopy(e.runtime_state['snapshot'])
    if fault=='dead_thread':e.loop.thread.alive=False
    elif fault=='tid':e.loop.thread.native_id+=1
    elif fault=='stale':e.state['clock']+=3
    elif fault=='clock_back':e.state['clock']=-1
    elif fault=='epoch':e.runtime_state['snapshot']['record']['start_ticks']+=1
    elif fault=='journal':e.runtime.journal.db.execute('DELETE FROM vm_libvirt_event_loops')
    elif fault=='configuration':e.loop.freshness=10
    else:e.loop._heartbeat(999,e.loop)
    with pytest.raises(RuntimeErrorBase):e.loop.check()
    e.loop.thread.alive=True;e.loop.thread.native_id=700;e.state['clock']=e.loop.last_tick
    e.runtime_state['snapshot']=original
    with pytest.raises(RuntimeErrorBase):e.loop.check()
    with pytest.raises(RuntimeErrorBase,match='cannot be repeated'):e.loop.start()
    assert e.state['starts']==1


@pytest.mark.parametrize('fault',['register','timer','iteration','no_heartbeat','sdk_exception'])
def test_uncertain_start_preserves_intent_without_native_retry(event_loop,fault):
    e=event_loop
    if fault=='register':e.state['register']=-1
    elif fault=='timer':e.state['timer']=-1
    elif fault=='iteration':e.state['iteration']=-1
    elif fault=='no_heartbeat':e.state['no_heartbeat']=True
    else:e.state['error']=OSError('SDK dispatch failed')
    with pytest.raises((RuntimeErrorBase,OSError)):e.loop.start()
    row=e.runtime.journal.db.execute('SELECT payload FROM vm_libvirt_event_loops').fetchone()
    assert row is not None and e.loop.failure
    with pytest.raises(RuntimeErrorBase):e.loop.check()
    with pytest.raises(RuntimeErrorBase,match='cannot be repeated'):e.loop.start()
    assert e.calls.count('register')==1 and e.state['starts']<=1


def test_retirement_seals_witness_but_does_not_stop_sdk_dispatch(event_loop):
    e=event_loop;e.loop.start();before=e.loop.iterations
    result=e.loop.retire()
    assert result['phase']=='retired' and e.loop.thread.is_alive()
    e.loop._iterate()
    assert e.loop.iterations==before+1
    with pytest.raises(RuntimeErrorBase):e.loop.check()
    assert e.state['starts']==1 and e.calls.count('register')==1


def test_supervised_loop_is_qualified_before_sdk_open_and_guards_connection(event_loop,case):
    e=event_loop
    for name in ('virEventRegisterDefaultImpl','virEventAddTimeout','virEventRunDefaultImpl'):
        setattr(case.sdk,name,getattr(e.sdk,name))
    e.loop.sdk=case.sdk
    e.loop.start()
    open_auth=case.sdk.openAuth
    def observed_open(*args):
        assert e.loop.check() and e.calls[0]=='register' and e.loop.iterations>0
        return open_auth(*args)
    case.sdk.openAuth=observed_open
    with case.connect(event_loop=e.loop) as connection:
        assert connection.getURI()=='qemu:///session'
        e.state['clock']+=3
        with pytest.raises(RuntimeErrorBase):connection.getURI()
    assert e.state['starts']==1 and case.calls[-1]==('close',)


def test_dispatch_worker_preserves_sdk_failure_without_restarting(event_loop):
    e=event_loop;e.state['error']=OSError('original SDK failure')
    factory=e.loop.thread_factory
    def worker(**kwargs):
        thread=factory(**kwargs)
        def start():
            e.state['starts']+=1;thread.alive=True
            # Execute the real worker body inline; its first synthetic SDK
            # iteration fails, so no native thread or infinite loop is created.
            thread.target();thread.alive=False
        thread.start=start
        return thread
    e.loop.thread_factory=worker
    with pytest.raises(RuntimeErrorBase,match='original SDK failure'):e.loop.start()
    assert e.loop.ready.is_set() and not e.loop.thread.is_alive()
    assert e.loop.failure=='OSError: original SDK failure'
    with pytest.raises(RuntimeErrorBase):e.loop.start()
    assert e.state['starts']==1
