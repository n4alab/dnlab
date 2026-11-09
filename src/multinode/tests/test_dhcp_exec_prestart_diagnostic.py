"""Diagnostic: a persisted inactive exec must not bypass service preflight."""
from copy import deepcopy
import json

import pytest

from dnlab_multinode.services import jumphost_host as module
from tests.test_dhcp_exec_journal import World,created


def foreign_service(w):
    return {'container':deepcopy(w.container),'operation_nonce':'f'*32,'host_pid':88,'start':'foreign'}


@pytest.mark.parametrize('boundary',['created-recovery','created-save'])
def test_foreign_service_before_start_rejects_without_another_exec_or_signal(tmp_path,boundary):
    w=created() if boundary=='created-recovery' else World()
    if boundary=='created-recovery':w.service=foreign_service(w)
    else:
        save=w.save
        def arrive():
            save()
            if w.intent['phase']=='created':w.service=foreign_service(w)
        w.save=arrive
    observations=[]
    def qualified_observe():
        observations.append(deepcopy(w.service))
        if w.service is not None and w.service['operation_nonce']!=w.intent['nonce']:
            raise module.JumphostError('foreign daemon blocks a second launch')
        return deepcopy(w.service)
    rejected=False;before=deepcopy(w.service)
    try:
        module.JournaledDHCPExec(w.intent,w.save,w.preflight,qualified_observe,docker=w).run()
    except module.JumphostError:rejected=True
    evidence={'boundary':boundary,'rejected':rejected,'start_calls':w.starts,
        'phase':w.intent['phase'],'observed_foreign_before_start':any(v and v['operation_nonce']=='f'*32 for v in observations),
        'service_after':w.service,'expected_foreign':before if boundary=='created-recovery' else foreign_service(w)}
    (tmp_path/'diagnostic.json').write_text(json.dumps(evidence,indent=2)+'\n')
    assert rejected,evidence
    assert w.starts==0 and w.service==evidence['expected_foreign']


def test_inactive_exec_starts_normally_when_complete_observer_verifies_absence():
    w=created();observations=[]
    def observe():observations.append(deepcopy(w.service));return deepcopy(w.service)
    value=module.JournaledDHCPExec(w.intent,w.save,w.preflight,observe,docker=w).run()
    assert value==w.service and w.starts==1


@pytest.mark.parametrize('boundary',['starting-save','last-preflight'])
def test_foreign_arrival_after_start_intent_or_last_preflight_preserves_exec_for_retry(tmp_path,boundary):
    w=World();save=w.save;preflight=w.preflight;armed=[True]
    def arrive():
        if armed[0]:armed[0]=False;w.service=foreign_service(w)
    def persisted():
        save()
        if boundary=='starting-save' and w.intent['phase']=='starting':arrive()
    def checked():
        result=preflight()
        if boundary=='last-preflight' and w.intent['phase']=='starting':arrive()
        return result
    w.save=persisted;w.preflight=checked
    def observe():
        if w.service is not None and w.service['operation_nonce']!=w.intent['nonce']:
            raise module.JumphostError('foreign daemon')
        return deepcopy(w.service)
    with pytest.raises(module.JumphostError):
        module.JournaledDHCPExec(w.intent,w.save,w.preflight,observe,docker=w).run()
    assert not armed[0] and w.starts==0 and w.intent['phase']=='starting'
    assert w.service==foreign_service(w) and len(w.execs)==1
    identity=w.intent['exec_id'];assert w.saved['exec_id']==identity and w.saved['start_attempted']
    w.reopen();w.service=None
    value=module.JournaledDHCPExec(w.intent,w.save,w.preflight,observe,docker=w).run()
    assert value==w.service and w.starts==1 and w.intent['exec_id']==identity and len(w.execs)==1


@pytest.mark.parametrize('presence',['same-nonce','foreign-nonce','foreign-container','unreadable'])
def test_inactive_exec_never_starts_over_an_existing_or_unqualified_service(presence):
    w=created();before=len(w.calls);identity=w.intent['exec_id']
    w.service={'container':deepcopy(w.container),'operation_nonce':w.intent['nonce'],'host_pid':88,'start':'other'}
    if presence=='foreign-nonce':w.service['operation_nonce']='f'*32
    if presence=='foreign-container':w.service['container']['id']='f'*64
    original=deepcopy(w.service)
    def observe():
        if presence=='unreadable':raise PermissionError('inspection denied')
        return deepcopy(w.service)
    with pytest.raises((module.JumphostError,PermissionError)):
        module.JournaledDHCPExec(w.intent,w.save,w.preflight,observe,docker=w).run()
    assert w.starts==0 and w.service==original and w.intent['exec_id']==identity
    assert all(method=='GET' for method,path,payload in w.calls[before:])
