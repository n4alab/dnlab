"""Actual private file exchange; directory/session lineage and services synthetic."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_activation_lineage import ActivationFiles,ActivationLineage
from dnlab_runtime.libvirt_configuration import UNIT
from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.manifest import Conflict
from tools.libvirt_service_units import observe_service_files
from test_libvirt_successor_unit_files import successor,configured,install,request_profile


@pytest.fixture
def activation_files(successor):
    driver,adapter,prepared,root,_,_=successor
    source=driver.apply(prepared['id']);reference=driver.read(prepared['id'])
    persistent_files=InstallationFiles(root,journal=driver.journal,readonly=True)
    view=SimpleNamespace(journal=driver.journal,files=persistent_files,read=lambda:deepcopy(reference['installation']))
    lineage=ActivationLineage(view,driver,reference=reference,effective_source=source)
    files=ActivationFiles(lineage,adapter.files,revision_window=driver.window,preflight=adapter.preflight)
    return lineage,files,source,driver,adapter,root


def test_lineage_and_per_creator_files_do_not_replay_inactive_revision_preflight(activation_files,monkeypatch):
    lineage,files,source,driver,adapter,_=activation_files
    monkeypatch.setattr(driver,'effective',lambda *a:pytest.fail('activation cannot reuse inactive-only effective observer'))
    monkeypatch.setattr(driver.window,'observe',lambda:{})
    assert lineage.read()==source
    assert len(observe_service_files(files,source))==7
    unit=next(item for item in source['items'] if item['spec'].get('path')==UNIT)
    with pytest.raises(Conflict,match='creator'):files.observe(unit,source['id'])


def test_replaced_revised_unit_or_backup_refused(activation_files):
    lineage,files,source,_,_,root=activation_files
    backup=root/lineage.reference['backup'].lstrip('/')
    backup.write_text('foreign backup; preserve')
    with pytest.raises(Conflict):observe_service_files(files,source)
    assert backup.read_text()=='foreign backup; preserve'


def test_complete_activation_preflight_stays_mandatory(activation_files,monkeypatch):
    _,files,source,_,_,_=activation_files
    monkeypatch.setattr(files.adapter,'preflight',lambda value:{})
    with pytest.raises(Conflict,match='preflight'):observe_service_files(files,source)


def test_current_directory_lineage_change_refused_before_files(activation_files):
    lineage,files,source,_,_,_=activation_files
    lineage.view.read=lambda:{'foreign':'directory source'}
    with pytest.raises(Conflict,match='lineage'):observe_service_files(files,source)


def test_effective_source_change_cannot_be_adopted(activation_files):
    lineage,_,_,_,_,_=activation_files
    lineage.source['configuration_revision']['receipt_sha256']='0'*64
    with pytest.raises(Conflict,match='effective activation source'):lineage.read()
