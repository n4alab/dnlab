"""Real SQLite only in private temporary directories; no installation reads."""
from copy import deepcopy
import hashlib
import os
import sqlite3

import pytest

from dnlab_runtime.libvirt_install import SessionInstaller
from dnlab_runtime.manifest import Conflict
from tools.libvirt_postboot_journal import open_postboot_journal
from test_libvirt_install import install,request_profile
from test_libvirt_postboot_session import assembly,boot_parent,installed_packages


@pytest.fixture
def original(install,tmp_path):
    installer,_,prepared,_=install;installed=installer.apply(prepared['id'])
    directory=tmp_path/'original';directory.mkdir(mode=0o700);path=directory/'journal.sqlite3'
    with sqlite3.connect(path) as copied:installer.journal.db.backup(copied)
    path.chmod(0o600)
    retained=[];checks=[]
    arguments=dict(directory=directory,installation=installed,identity=installer.journal.identity,
        initial_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),retain=retained.append,
        verify=lambda:checks.append(True))
    return arguments,path,retained,checks


def test_initial_open_retains_binding_before_metadata_write_and_resume_reuses_it(original):
    arguments,path,retained,checks=original
    with open_postboot_journal(**arguments) as (journal,binding):
        assert retained==[binding] and checks
        assert SessionInstaller(journal,None,readonly=True).read(arguments['installation']['id'])==arguments['installation']
        with journal.transaction():journal.db.execute('CREATE TABLE synthetic_postboot (value TEXT)')
    changed=hashlib.sha256(path.read_bytes()).hexdigest()
    assert changed!=arguments['initial_sha256']
    with open_postboot_journal(**arguments,original_binding=binding) as (journal,resumed):
        assert resumed==binding and retained==[binding]
        assert journal.db.execute('SELECT count(*) FROM synthetic_postboot').fetchone()[0]==0
    with pytest.raises(Conflict,match='hash differs'):
        with open_postboot_journal(**arguments):pytest.fail('initial hash must not be reused')


def test_missing_journal_is_not_initialized(original):
    arguments,path,retained,_=original;path.unlink()
    with pytest.raises(FileNotFoundError):
        with open_postboot_journal(**arguments):pytest.fail('missing original opened')
    assert not path.exists() and retained==[]


@pytest.mark.parametrize('fault',['identity','source','hash'])
def test_foreign_logical_binding_refused_before_retention_or_database_write(original,fault):
    arguments,path,retained,_=original;raw=path.read_bytes();arguments=deepcopy(arguments)
    if fault=='identity':arguments['identity']='0'*32
    elif fault=='hash':arguments['initial_sha256']='0'*64
    else:arguments['installation']['phase']='foreign'
    with pytest.raises(Conflict):
        with open_postboot_journal(**arguments):pytest.fail('foreign source opened')
    assert path.read_bytes()==raw and retained==[]


def test_same_bytes_replacement_is_not_adopted_on_resume(original):
    arguments,path,_,_=original
    with open_postboot_journal(**arguments) as (_,binding):pass
    replacement=path.with_name('replacement');replacement.write_bytes(path.read_bytes());replacement.chmod(0o600)
    replacement.replace(path);raw=path.read_bytes()
    with pytest.raises(Conflict,match='resume binding differs'):
        with open_postboot_journal(**arguments,original_binding=binding):pytest.fail('replacement opened')
    assert path.read_bytes()==raw


def test_retention_failure_prevents_first_metadata_write_and_can_resume_explicitly(original):
    arguments,path,retained,_=original;raw=path.read_bytes()
    def lost(binding):retained.append(binding);raise OSError('synthetic retention response lost')
    arguments['retain']=lost
    with pytest.raises(OSError,match='retention response'):
        with open_postboot_journal(**arguments):pytest.fail('metadata enabled without durable binding')
    assert path.read_bytes()==raw
    with open_postboot_journal(**arguments,original_binding=retained[0]) as (_,binding):
        assert binding==retained[0]


def test_window_conflict_rolls_back_metadata_transaction(original):
    arguments,_,_,_=original;active=[True]
    def verify():
        if not active[0]:raise Conflict('synthetic window closed')
    arguments['verify']=verify
    with pytest.raises(Conflict,match='window closed'):
        with open_postboot_journal(**arguments) as (journal,_):
            with journal.transaction():
                journal.db.execute('CREATE TABLE forbidden_completion (value TEXT)');active[0]=False
    with sqlite3.connect(arguments['directory']/'journal.sqlite3') as db:
        assert db.execute("SELECT name FROM sqlite_master WHERE name='forbidden_completion'").fetchone() is None


def test_symlink_database_is_not_followed(original):
    arguments,path,retained,_=original;target=path.with_name('saved-original');path.rename(target)
    path.symlink_to(target);raw=target.read_bytes()
    with pytest.raises(OSError):
        with open_postboot_journal(**arguments):pytest.fail('symlink opened')
    assert target.read_bytes()==raw and retained==[]


def test_existing_journal_composes_prepare_delivery_and_explicit_resume(assembly,tmp_path):
    from dnlab_runtime.libvirt_postboot_session import PostBootRecoverySession
    from tools.libvirt_postboot_prepare import PrepareDelivery
    _,arguments,_,files,_,_,_=assembly
    directory=tmp_path/'composed-journal';directory.mkdir(mode=0o700)
    path=directory/'journal.sqlite3'
    with sqlite3.connect(path) as copied:arguments['journal'].db.backup(copied)
    path.chmod(0o600);retained=[]
    opening=dict(directory=directory,installation=arguments['installation'],identity=arguments['journal_identity'],
        initial_sha256=hashlib.sha256(path.read_bytes()).hexdigest(),retain=retained.append,verify=lambda:None)
    output=tmp_path/'delivery';output.mkdir(mode=0o700)
    fd=os.open(output,os.O_RDONLY|os.O_DIRECTORY)
    try:
        def session(journal):
            files.journal=journal
            source=SessionInstaller(journal,None,readonly=True)
            return PostBootRecoverySession(**{**arguments,'journal':journal,'source_reader':source.read})
        with open_postboot_journal(**opening) as (journal,binding):
            with PrepareDelivery(session(journal),fd) as delivery:reference=delivery.prepare()
        with open_postboot_journal(**opening,original_binding=binding) as (journal,_):
            with PrepareDelivery(session(journal),fd) as delivery:
                assert delivery.prepare(resume=True)==reference
            assert SessionInstaller(journal,None,readonly=True).read(arguments['installation']['id'])==arguments['installation']
        assert files.calls==[] and retained==[binding]
    finally:os.close(fd)
