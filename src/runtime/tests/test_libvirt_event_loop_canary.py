"""Loop-only recipe; fake SDK/thread, original runtime witness on temp files."""
from copy import deepcopy
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from libvirt_event_loop_canary import run
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from test_libvirt_event_loop import event_loop, runtime_process


def scope(e):
    return dict(purpose='isolated-libvirt-loop-canary',runtime_epoch_sha256=fingerprint(e.epoch),
                hypervisor_connections_allowed=False,domain_actions_allowed=False)


def execute(e, *, preflight=None, pause=None):
    return run(e.runtime,e.sdk,preflight=preflight or (lambda:scope(e)),loop_factory=lambda runtime,sdk:e.loop,
               clock=lambda:e.state['clock'],pause=pause or (lambda delay:e.loop._iterate()),timeout=0.03)


def test_loop_only_recipe_requires_parent_exit_before_cleanup_claim(event_loop):
    e=event_loop;result=execute(e)
    assert result['phase']=='awaiting_process_exit' and result['qualified']
    assert result['requires_original_process_exit'] and not result['cleanup_verified'] and not result['gate_allowed']
    assert result['retirement']['phase']=='retired' and e.loop.thread.is_alive()
    assert e.state['starts']==1 and e.calls==['register',('timer',100),'iterate','iterate']
    with pytest.raises(RuntimeErrorBase):e.loop.check()
    row=e.runtime.journal.db.execute('SELECT payload,fingerprint FROM libvirt_event_loop_canaries').fetchone()
    assert json.loads(row['payload'])==result and row['fingerprint']==fingerprint(result)


def test_second_attempt_never_registers_or_starts_another_loop(event_loop):
    e=event_loop;execute(e)
    with pytest.raises(RuntimeErrorBase,match='one-shot'):execute(e)
    assert e.state['starts']==1 and e.calls.count('register')==1


def test_unqualified_process_scope_fails_before_any_loop_action(event_loop):
    e=event_loop;bad=scope(e);bad['hypervisor_connections_allowed']=True
    with pytest.raises(RuntimeErrorBase,match='scope differs'):execute(e,preflight=lambda:bad)
    assert not e.calls and e.state['starts']==0


def test_scope_changed_after_checkpoint_stays_pending_without_loop_start(event_loop):
    e=event_loop;count=[]
    def preflight():
        count.append(True);value=scope(e)
        if len(count)>2:value['purpose']='another-process-role'
        return value
    with pytest.raises(RuntimeErrorBase,match='scope differs'):execute(e,preflight=preflight)
    row=e.runtime.journal.db.execute('SELECT payload FROM libvirt_event_loop_canaries').fetchone()
    assert json.loads(row['payload'])['phase']=='pending' and not e.calls


def test_dispatch_failure_keeps_pending_and_original_receipt(event_loop):
    e=event_loop
    def failure(delay):e.state['error']=OSError('original SDK dispatch failed');e.loop._iterate()
    with pytest.raises(OSError,match='original SDK dispatch'):execute(e,pause=failure)
    row=e.runtime.journal.db.execute('SELECT payload FROM libvirt_event_loop_canaries').fetchone()
    saved=json.loads(row['payload'])
    assert saved['phase']=='pending' and saved['loop_sha256'] is not None
    assert not saved['qualified'] and not saved['cleanup_verified'] and e.state['starts']==1
