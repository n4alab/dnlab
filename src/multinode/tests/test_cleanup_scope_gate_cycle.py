"""A gate scope can be both born and cleaned after its immutable baseline."""
from copy import deepcopy
from pathlib import Path
import sys

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from cleanup_scope_sources import ROOT, QualifiedScopeSources
from tests.test_cleanup_scope_sources import scope
from tests.test_helper_scope_registration import registration, proof_case, helper, dns_world, jump_world, relay


def test_gate_scope_cleanup_projects_to_original_precreation_baseline(scope):
    qualifier, baseline, active, intent, _, calls = scope
    assert qualifier(active) == baseline
    # The same qualified original birth has now completed cleanup. No scope
    # remains, while the transient parent retains its changed timestamps/size.
    cleaned = deepcopy(baseline)
    parent = next(row for row in cleaned['candidates'] if row['source_id'] == ROOT)
    parent['metadata'][5:] = [100, 400, 500]
    intent['action'] = 'removed'
    assert qualifier(cleaned) == baseline
    assert calls[-1][1] == {}


def test_completed_cycle_recovery_reverifies_birth_and_cleanup_without_learning(scope):
    qualifier, baseline, _, intent, context, calls = scope
    intent['action']='removed'
    reopened=QualifiedScopeSources(baseline,context=context,definition_profile_sha256='4'*64,
        transitions=lambda:[deepcopy(intent)],verify=qualifier._verify)
    cleaned=deepcopy(baseline)
    next(row for row in cleaned['candidates'] if row['source_id']==ROOT)['metadata'][5:]=[100,400,500]
    original=deepcopy(baseline)
    assert reopened(cleaned)==baseline
    assert reopened(cleaned)==baseline and len(calls)==2
    assert baseline==original and reopened._baseline=={row['source_id']:row for row in original['candidates']}
    reopened._verify=lambda *args: (_ for _ in ()).throw(ValueError('original durable birth missing'))
    with pytest.raises(ValueError,match='original durable birth missing'):reopened(cleaned)


@pytest.mark.parametrize('fault',['foreign-source','parent-owner','parent-entry','remaining-scope','partial-baseline','receipt'])
def test_completed_cycle_preserves_rejection_of_unqualified_changes(scope,fault):
    qualifier, baseline, _, intent, context, _ = scope
    intent['action']='removed'
    cleaned=deepcopy(baseline);before=deepcopy(baseline)
    parent=next(row for row in cleaned['candidates'] if row['source_id']==ROOT)
    parent['metadata'][5:]=[100,400,500]
    verify=qualifier._verify
    if fault=='foreign-source':next(row for row in cleaned['candidates'] if row['source_id'].startswith('/etc/'))['sha256']='9'*64
    elif fault=='parent-owner':parent['metadata'][3]=1000
    elif fault=='parent-entry':parent['names'].append('foreign.scope')
    elif fault=='remaining-scope':cleaned['candidates'].append(deepcopy(intent['rows'][0]))
    elif fault=='partial-baseline':before['candidates'].append(deepcopy(intent['rows'][1]))
    else:verify=lambda *args:{}
    reopened=QualifiedScopeSources(before,context=context,definition_profile_sha256='4'*64,
        transitions=lambda:[deepcopy(intent)],verify=verify)
    snapshot=deepcopy(cleaned)
    with pytest.raises(ValueError):reopened(cleaned)
    assert cleaned==snapshot


def test_full_cycle_uses_registered_helper_birth_and_original_cleanup_guard(registration):
    value, _, captures, _, cleanup, state = registration
    saved=value.register()
    root={'source_id':ROOT,'kind':'directory','metadata':[1,2,16877,0,0,10,20,30],'names':[]}
    baseline={'complete':True,'candidates':[deepcopy(root)]}
    action=['created']
    def qualifier():
        return QualifiedScopeSources(baseline,context=value.context,
            definition_profile_sha256=value.definitions.sha256,
            transitions=lambda:[value.intent(action[0])],verify=value.proof())
    active=deepcopy(root)
    active['names']=sorted({row['source_id'][len(ROOT)+1:].split('/')[0] for row in saved['rows']})
    active['metadata'][5:]=[100,200,300]
    assert qualifier()({'complete':True,'candidates':[active]+deepcopy(saved['rows'])})==baseline
    cleanup();state['scope']={'rows':[],'bodies':{}};action[0]='removed'
    cleaned=deepcopy(root);cleaned['metadata'][5:]=[100,400,500]
    changes=value.store.db.total_changes
    # Reopen after cleanup: the proof must use the saved birth, not a capture
    # or an in-memory observation of the earlier creation.
    assert qualifier()({'complete':True,'candidates':[cleaned]})==baseline
    assert value._saved()==saved and captures==[1] and value.store.db.total_changes==changes
