"""Synthetic journal/observers and private temporary output, no host prepare."""
import os

import pytest

from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_prepare import PrepareDelivery
from test_libvirt_postboot_session import assembly,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def delivery(assembly,tmp_path):
    output=tmp_path/'output';output.mkdir(mode=0o700)
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY)
    try:
        with PrepareDelivery(assembly[0],fd) as writer:yield writer,output,assembly
    finally:os.close(fd)


def test_prepare_delivers_original_reference_and_resume_never_creates_directories(delivery):
    writer,output,assembly=delivery;session,_,_,files,_,_,_=assembly
    reference=writer.prepare()
    before=session.journal.db.total_changes
    assert writer.prepare(resume=True)==reference
    assert session.journal.db.total_changes==before and files.calls==[]
    assert sorted(p.name for p in output.iterdir())==['intent.json','prepared-reference.json']
    artifacts={path.name:(path.stat().st_ino,path.read_bytes()) for path in output.iterdir()}
    with pytest.raises(Conflict,match='already contains a reference'):writer.prepare()
    assert session.journal.db.total_changes==before and files.calls==[]
    assert {path.name:(path.stat().st_ino,path.read_bytes()) for path in output.iterdir()}==artifacts


def test_lost_prepare_response_recovers_same_journal_metadata(delivery,monkeypatch):
    writer,_,assembly=delivery;session=assembly[0];prepare=session.prepare
    def lost():
        prepare()
        raise OSError('synthetic lost journal response')
    monkeypatch.setattr(session,'prepare',lost)
    with pytest.raises(OSError,match='lost journal'):writer.prepare()
    original=session.recovery.read(session.recovery_id)
    monkeypatch.setattr(session,'prepare',prepare)
    assert writer.prepare(resume=True)['recovery']==original and assembly[3].calls==[]


@pytest.mark.parametrize('name',['intent.json','prepared-reference.json'])
def test_lost_artifact_response_reuses_original_file(delivery,monkeypatch,name):
    writer,output,assembly=delivery;write=writer._write
    def lost(path,value):
        write(path,value)
        if path==name:raise OSError('synthetic lost artifact response')
    monkeypatch.setattr(writer,'_write',lost)
    with pytest.raises(OSError,match='lost artifact'):writer.prepare()
    before=(output/name).stat().st_ino;raw=(output/name).read_bytes()
    monkeypatch.setattr(writer,'_write',write)
    writer.prepare(resume=True)
    assert (output/name).stat().st_ino==before and (output/name).read_bytes()==raw
    assert assembly[3].calls==[]


def test_reference_fsync_failure_preserves_file_and_resume_confirms_durability(delivery,monkeypatch):
    writer,output,assembly=delivery;fsync=os.fsync;failed=[]
    def sync(fd):
        target=output/'prepared-reference.json'
        if target.exists() and os.fstat(fd).st_ino==target.stat().st_ino and not failed:
            failed.append(True);raise OSError('synthetic reference fsync failure')
        return fsync(fd)
    monkeypatch.setattr(os,'fsync',sync)
    with pytest.raises(OSError,match='reference fsync'):writer.prepare()
    inode=(output/'prepared-reference.json').stat().st_ino
    writer.prepare(resume=True)
    assert (output/'prepared-reference.json').stat().st_ino==inode and assembly[3].calls==[]


@pytest.mark.parametrize('fault',['intent','partial-reference','symlink-reference'])
def test_foreign_or_incomplete_delivery_blocks_without_journal_mutation(delivery,fault):
    writer,output,assembly=delivery;writer.prepare()
    if fault=='intent':(output/'intent.json').write_text('{}\n')
    else:
        path=output/'prepared-reference.json';path.unlink()
        if fault=='partial-reference':path.write_text('{');path.chmod(0o600)
        else:path.symlink_to(output/'intent.json')
    before=assembly[0].journal.db.total_changes
    with pytest.raises((Conflict,OSError)):writer.prepare(resume=True)
    assert assembly[0].journal.db.total_changes==before and assembly[3].calls==[]


def test_prepare_delivery_does_not_resume_an_apply(delivery):
    writer,_,assembly=delivery;reference=writer.prepare()
    assembly[0].apply_original(reference);calls=list(assembly[3].calls)
    with pytest.raises(Conflict,match='recovery started'):writer.prepare(resume=True)
    assert assembly[3].calls==calls
