import pytest

from test_runtime import runtime, request, stop, run
from dnlab_runtime.manifest import Conflict


@pytest.mark.parametrize('action',['inspect','stop','coordinated-stop'])
def test_recreated_container_with_same_labels_is_rejected(runtime,action):
    engine,journal,docker,linux=runtime
    linux.network_identity=lambda:{'boot_id':'fixture','device':4,'inode':100}
    payload=request();payload['spec']['endpoints']=[]
    assert run(engine,journal,payload)['phase']=='completed'
    name=payload['spec']['container_name']
    original=docker.containers[name]['Id']
    # Equivalent external remove/create preserves configuration and labels but
    # produces a different immutable Docker generation.
    replacement='replacement-with-same-labels'
    docker.containers[name]['Id']=replacement
    assert replacement!=original
    targets=[];original_signal=docker.signal
    def signal(identity,value):
        targets.append((identity,value));return original_signal(identity,value)
    docker.signal=signal
    before=list(docker.calls)
    if action=='inspect':
        with pytest.raises(Conflict,match='generation'):
            engine.inspect('demo','R1')
    else:
        result=run(engine,journal,stop(**({'stop_mode':'coordinated'} if action=='coordinated-stop' else {})))
        assert result['phase']=='recovery_required'
        assert 'generation' in result['error']
        if action=='coordinated-stop':assert engine.stops.session(result['id']) is None
    assert docker.calls==before and targets==[]
    assert docker.containers[name]['Id']==replacement and docker.containers[name]['State']['Running']
    assert journal.node('demo','R1')['revision']==1
