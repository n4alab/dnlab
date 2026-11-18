"""Native action adapters with synthetic HTTP/pidfd providers, no service I/O."""
from contextlib import contextmanager
from copy import deepcopy
import io
import json
import os
from pathlib import Path
import select
import signal
import sys
from urllib.parse import parse_qs, urlsplit

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_control import ImageBuildEngine, OriginalImageBuildTerm, shutdown_log_proof
from dnlab_runtime.vm_template import TemplateError


@pytest.fixture
def engine():
    state=dict(status=200,body=b'{"Warnings":null}',requests=[],closed=0)
    class Connection:
        def __init__(self,path,timeout):assert path=='/synthetic/docker.sock' and timeout==10
        def request(self,method,path,body,headers):state['requests'].append((method,path,body,headers))
        def getresponse(self):
            stream=io.BytesIO(state['body']);stream.status=state['status'];return stream
        def close(self):state['closed']+=1
    return ImageBuildEngine('a'*64,socket_path='/synthetic/docker.sock',connection=Connection),state


def test_policy_and_start_use_only_original_id_and_exact_acknowledgements(engine):
    adapter,state=engine;policy=dict(Name='no',MaximumRetryCount=0)
    adapter.update_policy(policy)
    state.update(status=204,body=b'');adapter.start()
    assert [(row[0],row[1]) for row in state['requests']]==[
        ('POST','/containers/'+'a'*64+'/update'),('POST','/containers/'+'a'*64+'/start')]
    assert json.loads(state['requests'][0][2])==dict(RestartPolicy=policy)
    assert state['requests'][1][2] is None and state['closed']==2


@pytest.mark.parametrize('status,body',[(304,b''),(500,b''),(204,b'unexpected')])
def test_start_refuses_already_running_failed_or_nonempty_ack_without_retry(engine,status,body):
    adapter,state=engine;state.update(status=status,body=body)
    with pytest.raises(TemplateError):adapter.start()
    assert len(state['requests'])==1 and state['closed']==1


@pytest.mark.parametrize('body',[b'{"Warnings":["changed"]}',b'{"Warnings":null,"other":1}',b'x'*65537])
def test_update_refuses_warnings_unexpected_fields_and_oversize_response(engine,body):
    adapter,state=engine;state['body']=body
    with pytest.raises(TemplateError):adapter.update_policy(dict(Name='no',MaximumRetryCount=0))
    assert len(state['requests'])==1 and state['closed']==1


def frame(data,stream=2):return bytes([stream,0,0,0])+len(data).to_bytes(4,'big')+data


def log_lines():
    messages=['Started server process [1]','Application startup complete.','Shutting down',
              'Waiting for application shutdown.','Application shutdown complete.','Finished server process [1]']
    return [f'2026-11-18T09:00:0{index}.123456789Z INFO:     {message}\n'.encode()
            for index,message in enumerate(messages)]


def test_shutdown_logs_require_exact_generation_sequence_across_frames(engine):
    adapter,state=engine;lines=b''.join(log_lines())
    state['body']=frame(lines[:37])+frame(b'unrelated stdout',1)+frame(lines[37:])
    proof=adapter.shutdown_logs('2026-11-18T09:00:00Z',1)
    assert proof['ordinary_shutdown_log_verified'] is True and proof['namespace_pid']==1
    method,path,body,_=state['requests'][0]
    assert method=='GET' and path.startswith('/containers/'+'a'*64+'/logs?') and 'follow' not in path
    assert body is None and state['closed']==1
    assert parse_qs(urlsplit(path).query)['since']==['1794992400']
    assert not {'drain_verified','pidfd_exit_verified'} & set(proof)


@pytest.mark.parametrize('fault',['missing','duplicate','foreign','older','reordered','stdout','truncated','plain'])
def test_incomplete_ambiguous_or_other_generation_logs_cannot_prove_shutdown(fault):
    lines=log_lines()
    if fault=='missing':lines.pop(3)
    elif fault=='duplicate':lines.append(lines[-1])
    elif fault=='foreign':lines[-1]=lines[-1].replace(b'[1]',b'[22]')
    elif fault=='older':lines[0]=lines[0].replace(b'2026-11-18',b'2026-11-17')
    elif fault=='reordered':lines[2],lines[3]=lines[3],lines[2]
    raw=frame(b''.join(lines),1 if fault=='stdout' else 2)
    if fault=='truncated':raw=raw[:-1]
    elif fault=='plain':raw=b''.join(lines)
    with pytest.raises(TemplateError):shutdown_log_proof(raw,'2026-11-18T09:00:00Z',1)


def test_integer_since_earlier_same_second_logs_are_excluded_at_exact_generation_boundary():
    previous=b'2026-11-18T09:00:00.000000001Z INFO:     Finished server process [22]\n'
    raw=frame(previous+b''.join(log_lines()))
    proof=shutdown_log_proof(raw,'2026-11-18T09:00:00.100000000Z',1)
    assert proof['ordinary_shutdown_log_verified'] is True and proof['namespace_pid']==1


@pytest.fixture
def term():
    capture=dict(process=dict(pid=123,start_ticks='456'),sources={},executable=dict(sha256='b'*64))
    state=dict(view=deepcopy(capture['process']),capture=deepcopy(capture),namespace_pid=1,
               events=[],exit_events=select.POLLIN,signals=[],fds=[])
    class Process:
        @contextmanager
        def capture(self,pid,cid,copies):
            assert pid==123 and cid=='a'*64 and copies=={}
            yield deepcopy(state['capture'])
        def _view(self,pid):assert pid==123;return deepcopy(state['view'])
    def pidfd(pid,flags):
        assert (pid,flags)==(123,0)
        fd=os.open('/dev/null',os.O_RDONLY);state['fds'].append(fd);return fd
    class Poll:
        def register(self,fd,events):assert events==select.POLLIN;self.fd=fd
        def poll(self,milliseconds):
            assert milliseconds in (0,1000)
            return [(self.fd,event) for event in state['events']]
    def send(fd,number,info,flags):
        state['signals'].append((fd,number,info,flags))
        state['events']=[] if state['exit_events'] is None else [state['exit_events']]
    adapter=OriginalImageBuildTerm(process=Process(),pidfd_open=pidfd,poll_factory=Poll,
        send_signal=send,namespace_pid=lambda pid:state['namespace_pid'])
    yield adapter,capture,state
    for fd in state['fds']:
        with pytest.raises(OSError):os.fstat(fd)


def test_pinned_original_gets_one_term_and_exit_proof_but_no_drain_claim(term):
    adapter,capture,state=term
    with adapter.pin(capture,'a'*64,{}) as original:
        proof=original.term(preflight=lambda:True,timeout=1)
        assert proof==dict(pidfd_exit_verified=True,term_count=1,force_used=False,namespace_pid=1)
        assert state['signals']==[(state['fds'][0],signal.SIGTERM,None,0)]
        with pytest.raises(TemplateError,match='unused'):original.term(preflight=lambda:True,timeout=1)
    with pytest.raises(TemplateError,match='unused'):original.term(preflight=lambda:True,timeout=1)


@pytest.mark.parametrize('fault',['process','namespace','refuse'])
def test_full_preflight_change_blocks_signal(term,fault):
    adapter,capture,state=term
    with adapter.pin(capture,'a'*64,{}) as original:
        def preflight():
            if fault=='process':state['view']['start_ticks']='789'
            elif fault=='namespace':state['namespace_pid']=2
            return fault!='refuse'
        with pytest.raises(TemplateError):original.term(preflight=preflight,timeout=1)
    assert state['signals']==[]


@pytest.mark.parametrize('events',[None,select.POLLERR,select.POLLNVAL,select.POLLIN|select.POLLERR])
def test_exit_timeout_and_error_leave_single_term_uncertain(term,events):
    adapter,capture,state=term;state['exit_events']=events
    with adapter.pin(capture,'a'*64,{}) as original:
        with pytest.raises(TemplateError,match='uncertain'):original.term(preflight=lambda:True,timeout=1)
        with pytest.raises(TemplateError,match='unused'):original.term(preflight=lambda:True,timeout=1)
    assert len(state['signals'])==1


def test_exit_before_pin_prevents_signal_and_closes_descriptor(term):
    adapter,capture,state=term;state['events']=[select.POLLIN]
    with pytest.raises(TemplateError,match='unavailable'):
        with adapter.pin(capture,'a'*64,{}):pytest.fail('unavailable process yielded')
    assert not state['signals']
