"""Repeated source/resource contracts with synthetic current-boot proof leaves."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_activation import steps
from dnlab_runtime.libvirt_activation_lineage import ActivationLineage
from dnlab_runtime.libvirt_activation_resources import ActivationResources
from dnlab_runtime.libvirt_activation_services import ActivationServices
from dnlab_runtime.libvirt_configuration import ConfigurationRevision,UNIT
from dnlab_runtime.libvirt_current_session import CurrentAccountObserver
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict,fingerprint
from test_libvirt_configuration import Replacement
from test_libvirt_current_session import current,recovery,postboot,install,session,snapshot,fixture,request_profile


@pytest.fixture
def resource_preflight(current):
    view,_,request,_,_=current;base=request['installation']
    agreement=dict(operation_id='unit-before-activation',context=deepcopy(base['context']),targets=['file:'+UNIT],nonce='8'*32)
    window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    revision=ConfigurationRevision(view.journal,Replacement(),window=window)
    prepared=revision.prepare(agreement['operation_id'],base);source=revision.apply(prepared['id'])
    reference=revision.read(prepared['id']);lineage=ActivationLineage(view,revision,reference=reference,effective_source=source)
    observed=dict(context=deepcopy(source['context']),prerequisites=deepcopy(source['prerequisites']))
    value=dict(id='activation',installation=deepcopy(source),installation_sha256=fingerprint(source),
        items=[dict(spec=spec,phase='prepared',nonce='9'*32,proof=None) for spec in steps(source['profile'])])
    state=dict(activation=value,inventory=deepcopy(observed['prerequisites']['services']),
        receipts={item['spec']['key']:None for item in value['items']})
    services=ActivationServices(source,generation_observer=lambda *a:pytest.fail('no daemon started in this fixture'))
    accounts=CurrentAccountObserver(view,lambda request:deepcopy(request['expected']))
    provider=ActivationResources(lineage,activation_id='activation',snapshot=lambda:deepcopy(observed),accounts=accounts,
        directory_dependency=lambda spec:pytest.fail('no dependency in this fixture'),services=services,
        state_reader=lambda:deepcopy(state))
    return provider,observed,state,view,reference,accounts


def test_current_resources_verified_without_mutations(resource_preflight):
    provider,_,_,view,reference,_=resource_preflight;calls=list(view.files.calls);before=view.journal.db.total_changes
    assert provider(reference)['revision_sha256']==fingerprint(reference)
    assert view.files.calls==calls and view.journal.db.total_changes==before


@pytest.mark.parametrize('fault',['persistent','volatile','account','context','static','process','activation','reference'])
def test_foreign_or_changed_resource_snapshot_is_refused(resource_preflight,fault,monkeypatch):
    provider,observed,state,view,reference,accounts=resource_preflight
    if fault in ('persistent','volatile'):
        key=next(item['spec']['key'] for item in provider.source['items']
            if item['spec']['kind']=='directory' and item['spec']['path'].startswith('/run/')==(fault=='volatile'))
        view.files.resources[key]={'foreign':'preserve'}
    elif fault=='account':monkeypatch.setattr(accounts,'identity',lambda request:None)
    elif fault=='context':observed['context']['boot_id']='foreign'
    elif fault=='static':observed['prerequisites']['packages']='foreign packages'
    elif fault=='process':
        state['inventory']['processes']=[dict(pid=9999,uids=[1001]*4,gids=[1002]*4,groups=[])]
        observed['prerequisites']['services']=deepcopy(state['inventory'])
    elif fault=='activation':state['activation']['id']='foreign-operation'
    else:reference=deepcopy(reference);reference['nonce']='0'*32
    before=view.journal.db.total_changes
    with pytest.raises(Conflict):provider(reference)
    assert view.journal.db.total_changes==before


def test_second_observation_change_is_refused(resource_preflight,monkeypatch):
    provider,observed,_,_,reference,_=resource_preflight;calls=[]
    def changed():
        value=deepcopy(observed)
        if calls:value['prerequisites']['packages']='changed between observations'
        calls.append(True);return value
    monkeypatch.setattr(provider,'snapshot',changed)
    with pytest.raises(Conflict):provider(reference)
