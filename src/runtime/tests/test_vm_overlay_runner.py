"""Recover only a unique original arm receipt; no process is spawned."""
from copy import deepcopy
import uuid

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict, canonical, fingerprint
from dnlab_runtime.vm_overlay_runner import OverlayProcessRunner
from dnlab_runtime.vm_overlay_worker import command_plan


@pytest.fixture
def records(tmp_path):
    journal=Journal(tmp_path/'journal')
    profile={key:dict(path='/synthetic/'+key,sha256='e'*64) for key in ('python','worker')}
    runner=OverlayProcessRunner(journal,profile=profile,observer=object())
    identity=dict(device=1,inode=2,uid=1001,gid=1002,mode=0o600)
    request=dict(operation_id='a'*32,nonce='b'*32,spec=dict(id='boot',path='/disk/overlay.qcow2',base_path='/base.raw',
        base_sha256='c'*64,base_format='raw',uid=1001,gid=1002,mode=0o600))
    command=command_plan(request,dict(path='/usr/bin/qemu-img',sha256='d'*64),17,identity)
    def insert(phase='armed',has_reference=True):
        token=uuid.uuid4().hex
        reference=dict(token=token,command_sha256=fingerprint(command),process_record=dict(boot_id='synthetic',pid=123,
            start_ticks=456,uid=0,gid=0,executable_sha256='e'*64,namespace_sha256='f'*64))
        value=dict(token=token,command=deepcopy(command),profile=profile,phase=phase,
                   reference=reference if has_reference else None,outcome=None)
        journal.db.execute('INSERT INTO vm_overlay_workers VALUES(?,?,?)',(token,canonical(value),fingerprint(value)))
        return reference
    try:yield runner,command,insert
    finally:journal.close()


def test_original_reference_reopens_without_launch_or_writes(records):
    runner,command,insert=records;reference=insert();before=runner.journal.db.total_changes
    assert runner.original_reference(command)==reference
    assert runner.journal.db.total_changes==before and runner.live=={}


def test_unknown_launch_cannot_be_adopted(records):
    runner,command,insert=records;insert('launch_requested',False)
    assert runner.original_reference(command) is None


def test_ambiguous_arm_is_never_selected(records):
    runner,command,insert=records;insert();insert()
    with pytest.raises(Conflict,match='ambiguous'):runner.original_reference(command)


def test_original_release_cannot_be_reinterpreted_as_armed(records):
    runner,command,insert=records;insert('release_requested')
    with pytest.raises(Conflict,match='not left armed'):runner.original_reference(command)
