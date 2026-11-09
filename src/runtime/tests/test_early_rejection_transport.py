"""Original-connection error recovery and bounded, mutation-free body draining."""
from email.message import Message
import io
import json
from unittest.mock import Mock

import pytest
from dnlab_runtime import transport
from dnlab_runtime.manifest import RuntimeErrorBase


class Response:
    def __init__(self,status=409,body=None,headers=None):
        self.status=status
        self.body=json.dumps({'error':'runtime journal identity differs'}).encode() if body is None else body
        self.headers={'Content-Length':str(len(self.body)),'Content-Type':'application/json'} if headers is None else headers
        self.read_sizes=[]
    def getheader(self,name,default=None):return self.headers.get(name,default)
    def read(self,size=None):
        self.read_sizes.append(size)
        return self.body if size is None else self.body[:size]


class Connection:
    def __init__(self,response=None,send_error=None,receive_error=None):
        self.response=response or Response();self.send_error=send_error;self.receive_error=receive_error
        self.sent=[];self.received=0;self.closed=0
    def request(self,*args):
        self.sent.append(args)
        if self.send_error:raise self.send_error
    def getresponse(self):
        self.received+=1
        if self.receive_error:raise self.receive_error
        return self.response
    def close(self):self.closed+=1


def client(monkeypatch,connection):
    created=[]
    monkeypatch.setattr(transport,'UnixConnection',lambda path:created.append(path) or connection)
    return transport.Client('/fixture.sock',expected_journal_id='a'*32),created


def test_early_send_failure_preserves_complete_error_from_original_connection(monkeypatch):
    connection=Connection(send_error=BrokenPipeError('send failed'));api,created=client(monkeypatch,connection)
    with pytest.raises(RuntimeErrorBase,match='journal identity') as error:
        api.request('POST','/v1/operations',{'value':'private-marker'})
    assert not isinstance(error.value,transport.DeliveryUncertain)
    assert len(created)==len(connection.sent)==connection.received==connection.closed==1
    assert connection.response.read_sizes==[len(connection.response.body)]


@pytest.mark.parametrize('outcome',['no-response','reset','incomplete','malformed-json','missing-length','oversized','non-json','non-error-object','empty-error','success-after-send-error'])
def test_uncertain_delivery_is_typed_and_never_retransmitted_or_reported_success(monkeypatch,outcome):
    connection=Connection(send_error=BrokenPipeError('send failed'))
    if outcome=='no-response':connection.receive_error=transport.http.client.ResponseNotReady()
    if outcome=='reset':connection.receive_error=ConnectionResetError()
    if outcome=='incomplete':connection.response.headers['Content-Length']=str(len(connection.response.body)+1)
    if outcome=='malformed-json':connection.response=Response(body=b'not-json')
    if outcome=='missing-length':connection.response.headers.pop('Content-Length')
    if outcome=='oversized':connection.response.headers['Content-Length']=str(transport.MAX_BODY+1)
    if outcome=='non-json':connection.response.headers['Content-Type']='text/html'
    if outcome=='non-error-object':connection.response=Response(body=b'[]')
    if outcome=='empty-error':connection.response=Response(body=b'{"error":""}')
    if outcome=='success-after-send-error':connection.response=Response(status=202,body=b'{"id":"committed"}')
    api,created=client(monkeypatch,connection)
    with pytest.raises(transport.DeliveryUncertain,match='original request; no automatic retry') as error:
        api.request('POST','/v1/operations',{'value':'private-marker'})
    assert 'private-marker' not in str(error.value)
    assert len(created)==len(connection.sent)==connection.received==connection.closed==1
    if outcome in ('missing-length','oversized','non-json','success-after-send-error'):
        assert not connection.response.read_sizes


def test_successful_original_send_keeps_existing_response_and_journal_binding(monkeypatch):
    connection=Connection(response=Response(status=202,body=b'{"id":"accepted"}'));api,created=client(monkeypatch,connection)
    assert api.request('POST','/v1/operations',{'value':1})=={'id':'accepted'}
    assert connection.sent[0][3]['X-Dnlab-Journal']=='a'*32
    assert len(created)==len(connection.sent)==connection.closed==1


def test_lost_response_after_successful_send_is_uncertain_without_resubmit(monkeypatch):
    connection=Connection(receive_error=ConnectionResetError());api,created=client(monkeypatch,connection)
    with pytest.raises(transport.DeliveryUncertain):api.request('POST','/v1/operations',{'value':1})
    assert len(created)==len(connection.sent)==connection.closed==1


def handler(headers,body):
    value=object.__new__(transport.Handler);value.headers=Message()
    for name,content in headers:value.headers[name]=content
    value.rfile=io.BytesIO(body);value.connection=Mock()
    return value


def test_rejected_bounded_body_is_discarded_without_json_decode_or_overread(monkeypatch):
    raw=b'\xff\0not JSON'*20000;next_request=b'NEXT REQUEST'
    value=handler([('Content-Length',str(len(raw)))],raw+next_request)
    monkeypatch.setattr(transport.json,'loads',Mock(side_effect=AssertionError('rejected body parsed')))
    value._discard_rejected_body()
    assert value.rfile.tell()==len(raw) and value.rfile.read()==next_request
    value.connection.settimeout.assert_called_with(10)


@pytest.mark.parametrize('headers',[
    [],[('Content-Length','-1')],[('Content-Length','invalid')],
    [('Content-Length',str(transport.MAX_BODY+1))],
    [('Content-Length','9'*5000)],
    [('Content-Length','1'),('Content-Length','1')],
    [('Content-Length','8'),('Transfer-Encoding','chunked')],
])
def test_unknown_or_unbounded_rejected_framing_is_never_drained(headers):
    value=handler(headers,b'unread data');value._discard_rejected_body()
    assert value.rfile.tell()==0


def test_rejected_body_drain_has_an_absolute_deadline(monkeypatch):
    value=handler([('Content-Length','100')],b'x'*100)
    class Slow:
        def __init__(self):self.reads=0
        def read1(self,size):self.reads+=1;return b'x'
    value.rfile=Slow();times=iter([0,1,11])
    monkeypatch.setattr(transport.time,'monotonic',lambda:next(times))
    value._discard_rejected_body()
    assert value.rfile.reads==1
    assert value.connection.settimeout.call_args_list[-1].args==(10,)


def test_rejected_drain_io_error_keeps_rejection_path(monkeypatch):
    value=handler([('Content-Length','100')],b'')
    value.rfile=Mock();value.rfile.read1.side_effect=TimeoutError()
    value._discard_rejected_body()
    value.connection.settimeout.assert_called_with(10)


def test_valid_leading_zero_content_length_remains_bounded():
    value=handler([('Content-Length','000001')],b'XY')
    value._discard_rejected_body()
    assert value.rfile.tell()==1 and value.rfile.read()==b'Y'
