"""Pinned readonly namespace queries using synthetic HTTP and namespace I/O."""
from contextlib import contextmanager
from copy import deepcopy
import io
import json
from pathlib import Path
import sys

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_query import ImageBuildNamespaceQuery, PinnedNetworkNamespace
from dnlab_runtime.vm_template import TemplateError
from test_image_build_observation import observation


@pytest.fixture
def query(observation):
    observer,owner,native,profile=observation
    state=dict(requests=[],closed=0,namespace=[],status=200,body=None,error=False,after=None)
    class Namespace:
        @contextmanager
        def enter(self,capture,context):
            assert capture==native['capture'] and context==profile['context']
            state['namespace'].append('enter')
            try:yield
            finally:state['namespace'].append('restore')
    class Connection:
        sock=None
        def __init__(self,host,port,timeout):assert host=='127.0.0.1' and port==8082 and 0<timeout<=3
        def request(self,method,path,headers):
            assert method=='GET' and state['namespace']==['enter']
            self.path=path;state['requests'].append(path)
        def getresponse(self):
            if state['error']:raise OSError('synthetic HTTP failure')
            values={'/health':{'ok':True},'/jobs':native['jobs'],'/vrnetlab/binding':native['binding']}
            raw=json.dumps(values[self.path]).encode() if state['body'] is None else state['body']
            stream=io.BytesIO(raw);stream.status=state['status']
            if state['after'] and self.path=='/vrnetlab/binding':state['after']()
            return stream
        def close(self):state['closed']+=1
    provider=ImageBuildNamespaceQuery(observer.api,profile,read_context=lambda:deepcopy(native['context']),
        process=observer.process,namespace=Namespace(),connection=Connection)
    return provider,owner,native,state


def test_query_only_three_fixed_gets_in_pinned_namespace_and_restores(query):
    provider,owner,native,state=query
    result=provider(owner,native['capture'])
    assert result==dict(health={'ok':True},jobs=native['jobs'],binding=native['binding'])
    assert state['requests']==['/health','/jobs','/vrnetlab/binding']
    assert state['closed']==3 and state['namespace']==['enter','restore']


@pytest.mark.parametrize('fault',['redirect','duplicate','oversize','nan','http_error'])
def test_query_failures_close_transport_restore_namespace_and_never_retry(query,fault):
    provider,owner,native,state=query
    if fault=='redirect':state['status']=302
    elif fault=='duplicate':state['body']=b'{"ok":true,"ok":false}'
    elif fault=='oversize':state['body']=b'x'*8193
    elif fault=='nan':state['body']=b'{"ok":NaN}'
    else:state['error']=True
    with pytest.raises((TemplateError,OSError)):provider(owner,native['capture'])
    assert state['requests']==['/health'] and state['closed']==1
    assert state['namespace']==['enter','restore']


def test_original_context_change_refuses_before_api_or_namespace_access(query):
    provider,owner,native,state=query;native['context']['boot_id']='different'
    with pytest.raises(TemplateError,match='owner/context'):provider(owner,native['capture'])
    assert not state['requests'] and not state['namespace']


def test_original_generation_change_after_query_is_not_accepted(query):
    provider,owner,native,state=query
    state['after']=lambda:native['inspect']['State'].update(StartedAt='substituted')
    with pytest.raises(TemplateError,match='generation/context'):provider(owner,native['capture'])
    assert state['closed']==3 and state['namespace']==['enter','restore']


@pytest.fixture
def namespace():
    original=dict(device=1,inode=10);target=dict(device=1,inode=20)
    state=dict(current=deepcopy(original),closed=[],switches=[],restore_error=False)
    context=dict(namespaces=dict(net=original));capture=dict(process=dict(pid=44,namespaces=dict(net=target)))
    def open_ns(path,flags):
        assert path in ('/proc/thread-self/ns/net','/proc/44/ns/net')
        return 10 if path=='/proc/thread-self/ns/net' else 20
    def switch(fd,flags):
        assert flags==0;state['switches'].append(fd)
        if fd==10 and state['restore_error']:raise OSError('synthetic restoration failure')
        state['current']=deepcopy(original if fd==10 else target)
    provider=PinnedNetworkNamespace(open_ns=open_ns,identity=lambda fd:dict(device=1,inode=fd),
        current=lambda:deepcopy(state['current']),switch=switch,close=state['closed'].append)
    return provider,capture,context,state


def test_namespace_restores_original_after_query_error_and_closes_both_fds(namespace):
    provider,capture,context,state=namespace
    with pytest.raises(ValueError,match='original query'):
        with provider.enter(capture,context):raise ValueError('original query failure')
    assert state['switches']==[20,10] and state['closed']==[20,10]
    assert state['current']==context['namespaces']['net']


def test_target_namespace_mismatch_refuses_without_switching(namespace):
    provider,capture,context,state=namespace;capture['process']['namespaces']['net']['inode']=30
    with pytest.raises(TemplateError,match='namespace FD'):
        with provider.enter(capture,context):pytest.fail('foreign namespace entered')
    assert not state['switches'] and state['closed']==[20,10]


def test_failed_restoration_preserves_original_query_error_and_diagnostic(namespace):
    provider,capture,context,state=namespace;state['restore_error']=True
    with pytest.raises(ValueError,match='original query') as error:
        with provider.enter(capture,context):raise ValueError('original query failure')
    assert 'restoration failed' in error.value.__notes__[0]
    assert state['closed']==[20,10]
