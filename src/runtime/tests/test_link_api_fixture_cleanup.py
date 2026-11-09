"""Absent workers and foreign ownership must not depend on CLI error wording."""
import copy
from pathlib import Path

import pytest

from dnlab_runtime.backend import Docker
from dnlab_runtime.manifest import RuntimeErrorBase

ID='a'*64
IMAGE='sha256:'+'b'*64
LAB='link-api-test'
WORKER={'id':ID,'name':'fixture-worker'}
VALUE={'Id':ID,'Name':'/fixture-worker','Image':IMAGE,
       'Config':{'Labels':{'io.dnlab.spike':LAB}},'State':{'Running':False}}


class API:
    def __init__(self,value):self.value=copy.deepcopy(value);self.actions=[]
    def inspect(self,identity):return copy.deepcopy(self.value)
    def signal(self,identity,signal):
        self.actions.append(('signal',identity,signal));self.value['State']['Running']=False
    def remove(self,identity):self.actions.append(('remove',identity));self.value=None


@pytest.fixture
def cleanup(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).parents[1]/'tools'))
    from link_api_smoke import cleanup_worker
    return cleanup_worker


def test_already_removed_worker_requires_no_mutation(cleanup):
    api=API(None)
    cleanup(api,WORKER,IMAGE,LAB)
    assert not api.actions


@pytest.mark.parametrize('running',[False,True])
def test_owned_worker_removal_waits_for_exit(cleanup,running):
    api=API(VALUE);api.value['State']['Running']=running
    cleanup(api,WORKER,IMAGE,LAB)
    assert api.actions==([('signal',ID,'SIGKILL')] if running else [])+[('remove',ID)]


@pytest.mark.parametrize('field',['Id','Name','Image','label'])
def test_foreign_worker_never_killed_or_removed(cleanup,field):
    api=API(VALUE)
    if field=='label':api.value['Config']['Labels']['io.dnlab.spike']='foreign'
    else:api.value[field]='foreign'
    with pytest.raises(RuntimeError,match='ownership'):cleanup(api,WORKER,IMAGE,LAB)
    assert not api.actions


def test_inspection_error_is_not_absence(cleanup):
    api=API(VALUE)
    def fail(_):raise RuntimeErrorBase('Docker HTTP 500')
    api.inspect=fail
    with pytest.raises(RuntimeErrorBase,match='500'):cleanup(api,WORKER,IMAGE,LAB)
    assert not api.actions


@pytest.mark.parametrize('status',[404,500])
def test_docker_absence_uses_http_status_not_diagnostic_text(monkeypatch,status):
    from dnlab_runtime import backend
    class Response:
        def __init__(self):self.status=status
        def read(self):return b'{"message":"error: no such object"}'
    class Connection:
        def __init__(self,*args):pass
        def request(self,*args,**kwargs):pass
        def getresponse(self):return Response()
        def close(self):pass
    monkeypatch.setattr(backend,'UnixConnection',Connection)
    if status==404:assert Docker().inspect(ID) is None
    else:
        with pytest.raises(RuntimeErrorBase,match='HTTP 500'):Docker().inspect(ID)
