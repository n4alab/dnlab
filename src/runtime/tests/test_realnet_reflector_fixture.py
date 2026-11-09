import copy

import pytest

from tools.realnet_reflector_smoke import cleanup_container


class FixtureDocker:
    def __init__(self,running=True):
        self.container={'Id':'a'*64,'Name':'/drsp-rr-test','Image':'sha256:'+'b'*64,
                        'Config':{'Labels':{'io.dnlab.spike':'test'}},'State':{'Running':running}}
        self.calls=[]
        self.keep_running=False

    def inspect(self,identity):return copy.deepcopy(self.container)
    def signal(self,identity,signal):self.calls.append(('signal',identity,signal))
    def request(self,method,path,*,missing_ok):
        self.calls.append(('wait',method,path,missing_ok))
        self.container['State']['Running']=self.keep_running
        return {'StatusCode':137}
    def remove(self,identity):
        self.calls.append(('remove',identity));self.container=None


@pytest.mark.parametrize('running',[True,False])
def test_owned_cleanup_waits_before_ordinary_remove(running):
    api=FixtureDocker(running);original=copy.deepcopy(api.container)
    cleanup_container(api,original)
    assert api.container is None
    assert [call[0] for call in api.calls]==(['signal','wait','remove'] if running else ['remove'])
    if running:
        assert api.calls[0][2]=='SIGKILL'
        assert api.calls[1][2].endswith('/wait?condition=not-running')


def test_absent_cleanup_is_idempotent():
    api=FixtureDocker();original=api.container;api.container=None
    cleanup_container(api,original)
    assert not api.calls


@pytest.mark.parametrize('field',['Id','Name','Image','Labels'])
def test_cleanup_refuses_changed_ownership(field):
    api=FixtureDocker();original=copy.deepcopy(api.container)
    if field=='Labels':api.container['Config']['Labels']={}
    else:api.container[field]='different'
    with pytest.raises(RuntimeError,match='ownership differs'):cleanup_container(api,original)
    assert not api.calls


def test_cleanup_does_not_remove_running_container_after_wait():
    api=FixtureDocker();original=copy.deepcopy(api.container);api.keep_running=True
    with pytest.raises(RuntimeError,match='did not stop'):cleanup_container(api,original)
    assert [call[0] for call in api.calls]==['signal','wait']
