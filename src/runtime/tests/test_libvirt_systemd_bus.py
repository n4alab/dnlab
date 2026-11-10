"""ABI function doubles only: no CDLL, real handles, sockets or bus access."""
import ctypes as C
import errno

import pytest

from dnlab_runtime.libvirt_activation_bus import serve
from dnlab_runtime.manifest import Conflict
from tools.libvirt_systemd_bus import SdBusABI,SystemdStartBus
from test_libvirt_activation_bus import worker
from test_libvirt_activation_acknowledgements import acknowledgements
from test_libvirt_service_observer import service,install,request_profile


@pytest.fixture
def adapter(worker):
    receipts,command,connection,_,state,_,source,sink,_,_,_=worker
    abi_state=dict(calls=[],error=None,unrefs=[],sender=b':1.42',unique=b':1.43',ready=1,timeout=None)
    class Call:
        def __init__(self,name):self.name=name
        def __call__(self,*args):
            name=self.name;abi_state['calls'].append((name,args))
            if abi_state['error']==name:return -errno.ETIMEDOUT
            if name in ('sd_bus_is_open','sd_bus_is_ready'):return abi_state['ready']
            if name=='sd_bus_get_unique_name':args[1]._obj.value=abi_state['unique'];return 0
            if name=='sd_bus_message_new_method_call':args[1]._obj.value=0x200;return 0
            if name=='sd_bus_message_append_basic':return 0
            if name=='sd_bus_call':
                abi_state['timeout']=args[2];args[4]._obj.value=0x300;return 0
            if name in ('sd_bus_message_get_cookie','sd_bus_message_get_reply_cookie'):args[1]._obj.value=17;return 0
            if name=='sd_bus_message_get_sender':return abi_state['sender']
            if name=='sd_bus_message_get_signature':return b'o'
            if name=='sd_bus_message_read_basic':args[2]._obj.value=b'/org/freedesktop/systemd1/job/91';return 1
            if name=='sd_bus_message_unref':abi_state['unrefs'].append(args[0].value);return None
            pytest.fail('unexpected ABI function '+name)
    class Library:
        def __init__(self):self.functions={}
        def __getattr__(self,name):
            if name not in self.functions:self.functions[name]=Call(name)
            return self.functions[name]
    library=Library();abi=SdBusABI(library)
    bus=SystemdStartBus(abi,C.c_void_p(0x100),connection,transport=command['transport'],
        qualify=lambda conn,cmd:state['valid'] and conn==connection and cmd==command)
    return bus,abi_state,worker,library


def test_constructing_adapter_does_not_load_or_call_library(adapter):
    _,state,_,library=adapter
    assert state['calls']==[]
    assert library.sd_bus_call.argtypes==[C.c_void_p,C.c_void_p,C.c_uint64,C.c_void_p,C.POINTER(C.c_void_p)]
    assert library.sd_bus_message_get_sender.restype is C.c_char_p


def test_worker_calls_pinned_owner_once_and_commits_job_before_ack(adapter):
    bus,state,worker,_=adapter
    receipts,command,_,_,_,_,source,sink,_,_,_=worker
    result=serve(source,sink,bus=bus)
    assert receipts._read(command)['result']==result
    calls=[args for name,args in state['calls'] if name=='sd_bus_call']
    assert len(calls)==1 and state['timeout']==5_000_000
    message=next(args for name,args in state['calls'] if name=='sd_bus_message_new_method_call')
    assert message[2:]==(b':1.42',b'/org/freedesktop/systemd1',b'org.freedesktop.systemd1.Manager',b'StartUnit')
    assert [args[2].value for name,args in state['calls'] if name=='sd_bus_message_append_basic']==[v.encode('ascii') for v in command['body']]
    assert state['unrefs']==[0x300,0x200]


@pytest.mark.parametrize('function,freed,calls',[
    ('sd_bus_message_new_method_call',[],0),
    ('sd_bus_message_append_basic',[0x200],0),
    ('sd_bus_call',[0x200],1),
    ('sd_bus_message_get_reply_cookie',[0x300,0x200],1),
    ('sd_bus_message_read_basic',[0x300,0x200],1),
])
def test_abi_failure_keeps_receipt_pending_and_frees_only_owned_messages(adapter,function,freed,calls):
    bus,state,worker,_=adapter
    receipts,command,_,_,_,_,source,sink,_,_,_=worker;state['error']=function
    with pytest.raises(OSError) as error:serve(source,sink,bus=bus)
    assert error.value.errno==errno.ETIMEDOUT
    assert state['unrefs']==freed
    assert len([name for name,_ in state['calls'] if name=='sd_bus_call'])==calls
    assert receipts._read(command)['phase']=='prepared'


def test_foreign_reply_sender_is_not_accepted_after_call(adapter):
    bus,state,worker,_=adapter
    receipts,command,_,_,_,_,source,sink,_,_,_=worker;state['sender']=b':1.99'
    with pytest.raises(Conflict,match='method reply'):serve(source,sink,bus=bus)
    assert state['unrefs']==[0x300,0x200] and receipts._read(command)['phase']=='prepared'


def test_changed_unique_connection_blocks_before_message_creation(adapter):
    bus,state,worker,_=adapter
    _,_,_,_,_,_,source,sink,_,_,_=worker;state['unique']=b':1.99'
    with pytest.raises(Conflict,match='connection or transport'):serve(source,sink,bus=bus)
    assert not any(name=='sd_bus_message_new_method_call' for name,_ in state['calls'])


def test_unbounded_timeout_refused_before_method_call(adapter):
    bus,state,worker,_=adapter;_,command,connection,_,_,_,_,_,_,_,_=worker
    with pytest.raises(Conflict,match='bounded'):bus.start_unit(connection,command,timeout=0)
    assert not any(name=='sd_bus_call' for name,_ in state['calls'])
