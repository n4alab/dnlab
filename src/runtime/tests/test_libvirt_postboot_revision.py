"""Completed unit revision qualification with synthetic boots and births."""

from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.libvirt_activation_lineage import ActivationLineage
from dnlab_runtime.libvirt_configuration import ConfigurationRevision, UNIT
from dnlab_runtime.libvirt_current_session import CurrentSessionView
from dnlab_runtime.libvirt_postboot import PostBootQualification
from dnlab_runtime.libvirt_postboot_revision import PostBootRevision
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_volatile_recovery import VolatileDirectories
from dnlab_runtime.manifest import Conflict
from test_libvirt_configuration import Replacement
from test_libvirt_current_session import current, recovery, postboot, install, request_profile
from test_libvirt_volatile_recovery import Directories


@pytest.fixture
def after_revision(current):
    view, _, request, _, installer = current
    legacy = request['installation']
    journal = view.journal
    original = installer.read(legacy['id'])
    agreement = dict(operation_id='revision', context=legacy['context'], targets=['file:' + UNIT], nonce='e' * 32)
    window = ProvisioningWindow(agreement, lambda: agreement)
    adapter = Replacement()
    revision = ConfigurationRevision(journal, adapter, window=window)
    prepared = revision.prepare(agreement['operation_id'], legacy)
    effective = revision.apply(prepared['id'])
    reference = revision.read(prepared['id'])
    state = dict(conflict=False, reads=0)

    def locations(request, layout):
        assert layout == 'backed_up'
        state['reads'] += 1
        if state['conflict']:
            raise Conflict('original backup replaced')
        return reference['proof']['source_proof'], dict(identity=reference['proof']['replacement']['identity'])

    swap = SimpleNamespace(journal=journal, window=window, _locations=locations,
                           _read=lambda request: {'phase': 'completed'})
    completed = PostBootRevision(revision, swap, reference)
    boot = deepcopy(legacy['context'])
    boot['boot_id'] = 'boot-after-original-revision'
    prior = view.recovery.qualification
    keys = prior.read('postboot-check')['plan']
    observed = dict(context=boot, prerequisites=deepcopy(effective['prerequisites']),
                    persistent={item['spec']['key']: deepcopy(item['proof']) for item in effective['items']
                                if item['spec']['key'] in keys['persistent']},
                    volatile={key: dict(state='absent') for key in keys['volatile']})
    qualification = PostBootQualification(journal, source_reader=installer.read,
                                         observer=lambda value: deepcopy(observed),
                                         account_history=prior.account_history, completed_revision=completed)
    value = qualification.prepare('postboot-revised', original, boot)
    agreement = dict(operation_id='fresh-directories', context=boot, targets=keys['volatile'], nonce='7' * 32)
    window = ProvisioningWindow(agreement, lambda: agreement)
    recovery = VolatileDirectories(qualification, Directories(journal, observed), window=window)
    return qualification, value, recovery, revision, reference, state, observed, view


def test_revised_unit_and_new_directories_feed_activation_without_revision_replay(after_revision):
    qualification, value, recovery, revision, reference, state, observed, old = after_revision
    qualification.qualify_persistent(value['id'])
    assert state['reads'] >= 2
    prepared = recovery.prepare('fresh-directories', value['id'])
    view = CurrentSessionView(recovery, prepared['id'])
    with pytest.raises(Conflict, match='completed current-boot'):
        view.read()
    recovery.apply(prepared['id'])
    source = view.read()
    assert source['context'] == observed['context']
    assert source['postboot']['creators']['file:' + UNIT] == reference['id']
    for item in recovery.read(prepared['id'])['items']:
        assert source['postboot']['creators'][item['spec']['key']] == prepared['id']
        assert old.read()['postboot']['creators'][item['spec']['key']] != prepared['id']
    lineage = ActivationLineage(view, revision, reference=reference, effective_source=source)
    assert lineage.read() == source
    assert revision.read(reference['id']) == reference
    assert revision.adapter.calls == 1


@pytest.mark.parametrize('fault', ['backup', 'old-unit', 'old-boot'])
def test_requalification_preserves_prepared_state_on_conflict(after_revision, fault):
    qualification, value, recovery, _, reference, state, observed, _ = after_revision
    if fault == 'backup':
        state['conflict'] = True
    elif fault == 'old-unit':
        observed['persistent']['file:' + UNIT] = reference['proof']['source_proof']
    else:
        observed['context'] = reference['installation']['context']
    with pytest.raises(Conflict):
        qualification.qualify_persistent(value['id'])
    assert qualification.read(value['id'])['phase'] == 'prepared'
    assert recovery.files.calls == []


def test_projection_reuse_rechecks_journal_and_returns_independent_values(after_revision, monkeypatch):
    qualification, value, _, revision, reference, _, _, _ = after_revision
    completed = qualification.completed_revision
    original_read = revision.read
    reads = []

    def read(operation):
        reads.append(operation)
        return original_read(operation)

    monkeypatch.setattr(revision, 'read', read)
    source = qualification._revision(value)
    assert reads == [reference['id']]
    source['context']['host_id'] = 'changed-copy'
    assert qualification._revision(value)['context']['host_id'] != 'changed-copy'
    changed = deepcopy(reference)
    changed['window_sha256'] = 'f' * 64
    monkeypatch.setattr(revision, 'read', lambda operation: changed)
    with pytest.raises(Conflict, match='original completed unit revision changed'):
        qualification._revision(value)


def test_cached_projection_does_not_bypass_retirement(after_revision, monkeypatch):
    qualification, value, _, revision, _, _, _, _ = after_revision

    def retired(reference):
        raise Conflict('configuration revision retired')

    monkeypatch.setattr(revision, '_active', retired)
    with pytest.raises(Conflict, match='configuration revision retired'):
        qualification._revision(value)
