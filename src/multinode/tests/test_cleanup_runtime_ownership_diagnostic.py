"""Regressions for pending lifecycle and unqualified VD cleanup protection."""
import shlex

import pytest

from dnlab_multinode.models.state import DeploymentState,NodeRuntimeState
from dnlab_multinode.services import lab_cleanup as cleanup


class Client:
    def __init__(self,identity):
        self.identity=identity;self.commands=[];self.removed=[]
    def run_no_check(self,command,timeout=30):
        self.commands.append(command)
        if shlex.split(command)==['docker','rm','-f','clab-dnlab-demo-R1-R1']:
            self.removed.append(self.identity)
        return 0,'',''


@pytest.mark.parametrize('runtime_state',['stopping','reconciling','error'])
def test_cleanup_protects_unfinished_lifecycle(runtime_state):
    state=DeploymentState(lab_name='demo',topology_file='/tmp/demo.yml',runtime_mode='per-vd')
    state.node_runtime={'R1':NodeRuntimeState(node='R1',host='master',container='clab-dnlab-demo-R1-R1',state=runtime_state)}
    artifact=cleanup.CleanupArtifact(kind='container',name='clab-dnlab-demo-R1-R1',host='master',lab='demo',state='exited',age_seconds=3600)
    inventory={'master':cleanup.HostCleanupInventory(name='master',host='127.0.0.1',reachable=True,artifacts=[artifact])}
    plans=cleanup.build_cleanup_plan(inventory,{'demo':state},grace_seconds=600)
    assert not state.teardown_requested and plans['demo'].protected
    client=Client('original-runtime-generation')
    cleanup._execute_plans(plans,{'master':client},own_clients=False,states={'demo':state})
    assert client.removed==[] and client.commands==[]


def test_cleanup_preserves_unqualified_replacement():
    state=DeploymentState(lab_name='demo',topology_file='/tmp/demo.yml')
    state.node_runtime={'R1':NodeRuntimeState(node='R1',host='master',container='clab-dnlab-demo-R1-R1',state='error')}
    # Inventory describes the original exited workload. Between plan and execute
    # an unrelated Docker generation has taken the same name and may be running.
    artifact=cleanup.CleanupArtifact(kind='container',name='clab-dnlab-demo-R1-R1',host='master',lab='demo',state='exited',age_seconds=3600)
    inventory={'master':cleanup.HostCleanupInventory(name='master',host='127.0.0.1',reachable=True,artifacts=[artifact])}
    plans=cleanup.build_cleanup_plan(inventory,{'demo':state},grace_seconds=600)
    client=Client('foreign-replacement-generation')
    cleanup._execute_plans(plans,{'master':client},own_clients=False,states={'demo':state})
    assert plans['demo'].protected and client.removed==[] and client.commands==[]
