"""Typed references and Docker inspection compatibility with simulated IO."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, validate_request
from dnlab_runtime.workload_identity import WorkloadReference
from test_runtime import runtime, request, stop, run


def test_docker_and_vm_identifiers_remain_explicitly_distinct():
    cid='a'*64
    domain='12345678-1234-4234-8234-123456789abc'
    assert WorkloadReference('docker','container',cid).public()=={'backend':'docker','kind':'container','id':cid}
    assert WorkloadReference('libvirt','vm',domain).public()=={'backend':'libvirt','kind':'vm','id':domain}
    with pytest.raises(RuntimeErrorBase,match='UUID'):WorkloadReference('libvirt','vm',cid)
    with pytest.raises(RuntimeErrorBase,match='backend and kind'):WorkloadReference('docker','vm',domain)


def test_inspection_adds_reference_without_changing_generation_or_lifecycle(runtime):
    engine,journal,docker,_=runtime
    assert run(engine,journal,request())['phase']=='completed'
    before=deepcopy(docker.containers);calls=list(docker.calls)
    view=engine.inspect('demo','R1')
    assert view['workload_ref']=={'backend':'docker','kind':'container','id':view['container_id']}
    assert view['workload_state']==view['container_state']=='running'
    assert view['workload']['container_id']==view['workload_ref']['id']
    assert docker.containers==before and docker.calls==calls
    assert run(engine,journal,stop())['phase']=='completed'
    stopped=engine.inspect('demo','R1')
    assert stopped['workload_ref'] is None and stopped['container_id'] is None
    assert stopped['workload_state']==stopped['container_state']=='absent'
    assert stopped['committed_state']=='stopped' and stopped['workload']['phase']=='cleaned'


def test_typed_reference_does_not_enable_unimplemented_vm_execution():
    value=request();value['spec']['kind']='vm'
    with pytest.raises(RuntimeErrorBase,match='only native linux'):validate_request(value)
