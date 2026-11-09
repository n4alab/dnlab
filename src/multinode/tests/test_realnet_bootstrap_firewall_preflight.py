"""Bootstrap must reject firewall ownership conflicts before allocating resources."""
import copy
import shlex

import pytest

from dnlab_multinode.services.realnet_bootstrap_host import Bootstrap
from dnlab_multinode.services.realnet_cleanup_host import OwnershipError,Worker
from tests.test_realnet_bootstrap_host import request_and_kernel
from tests.test_realnet_cleanup import CONTEXT


@pytest.mark.parametrize('conflict',['changed_target','duplicate'])
def test_bootstrap_firewall_conflict_prevents_allocation(tmp_path,conflict):
    request,kernel=request_and_kernel()
    rules=copy.deepcopy(request['infrastructure']['firewall'])
    if conflict=='changed_target':rules[0][-1]='DROP'
    else:rules.append(copy.deepcopy(rules[0]))
    calls=[]
    def run(argv,**kwargs):
        calls.append(argv)
        if argv==['iptables-save','-t','filter']:
            return '\n'.join(shlex.join(['-A',*rule]) for rule in rules)
        return kernel.run(argv,**kwargs)
    # Confirm that the same proof/current rules are incompatible under the
    # existing ownership contract, rather than asserting a new policy.
    guard=Worker(request['infrastructure'],run=run,host_context=lambda:CONTEXT)
    with pytest.raises(OwnershipError,match='firewall'):guard.preflight()
    calls.clear()
    bootstrap=Bootstrap(request,run=run,host_context=lambda:CONTEXT,directory=tmp_path/'bootstrap')
    try:
        bootstrap.deploy()
    except OwnershipError:
        pass
    assert not kernel.mutations,{'mutations':kernel.mutations,'firewall_inspected':['iptables-save','-t','filter'] in calls}
    assert not bootstrap.directory.exists()


@pytest.mark.parametrize('stage',['active_retry','recover_after_helper','recover_after_veth'])
@pytest.mark.parametrize('conflict',['changed_target','duplicate'])
def test_conflict_on_retry_or_recovery_preserves_pending_resources(tmp_path,stage,conflict):
    request,kernel=request_and_kernel()
    bootstrap=Bootstrap(request,run=kernel.run,host_context=lambda:CONTEXT,directory=tmp_path/'bootstrap')
    if stage=='active_retry':bootstrap.deploy()
    else:
        kernel.fail_after=1 if stage=='recover_after_helper' else 2
        with pytest.raises(RuntimeError,match='crash'):bootstrap.deploy()
        kernel.fail_after=None
    if conflict=='changed_target':kernel.rules[0][-1]='DROP'
    else:kernel.rules.append(copy.deepcopy(kernel.rules[0]))
    resources=copy.deepcopy((kernel.links,kernel.peer,kernel.container,kernel.rules))
    journal=(bootstrap.directory/(request['infrastructure']['scope']+'.json')).read_bytes()
    count=len(kernel.mutations)
    retry=Bootstrap(request,run=kernel.run,host_context=lambda:CONTEXT,directory=bootstrap.directory)
    with pytest.raises(OwnershipError,match='firewall'):retry.deploy()
    assert len(kernel.mutations)==count
    assert (kernel.links,kernel.peer,kernel.container,kernel.rules)==resources
    assert (bootstrap.directory/(request['infrastructure']['scope']+'.json')).read_bytes()==journal
    kernel.rules=copy.deepcopy(request['infrastructure']['firewall'])
    assert retry.deploy()['phase']=='active'


def test_conflict_appearing_during_bootstrap_stops_next_mutation(tmp_path):
    request,kernel=request_and_kernel()
    def run(argv,**kwargs):
        value=kernel.run(argv,**kwargs)
        if argv[:2]==['docker','run']:kernel.rules[0][-1]='DROP'
        return value
    bootstrap=Bootstrap(request,run=run,host_context=lambda:CONTEXT,directory=tmp_path/'bootstrap')
    with pytest.raises(OwnershipError,match='firewall'):bootstrap.deploy()
    assert len(kernel.mutations)==1
    assert kernel.container is not None and 'vh-test' not in kernel.links
    assert bootstrap.directory.exists()
    kernel.rules=copy.deepcopy(request['infrastructure']['firewall'])
    recovered=Bootstrap(request,run=kernel.run,host_context=lambda:CONTEXT,directory=bootstrap.directory)
    assert recovered.deploy()['phase']=='active'


def test_foreign_unlabelled_rule_is_preserved_during_bootstrap_and_retry(tmp_path):
    request,kernel=request_and_kernel()
    foreign=['FORWARD','-i','br-test','-j','ACCEPT']
    kernel.rules.append(foreign)
    saved=copy.deepcopy(kernel.rules)
    bootstrap=Bootstrap(request,run=kernel.run,host_context=lambda:CONTEXT,directory=tmp_path/'bootstrap')
    bootstrap.deploy();bootstrap.deploy()
    assert kernel.rules==saved
