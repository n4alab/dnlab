"""Narrow sd-bus StartUnit transport over an already qualified connection.

No CDLL load, bus open, reconnect, subprocess or library lookup is provided.
The owner must qualify the supplied library and handle and retain their lifetime.
Owned message references are always released; the borrowed bus stays untouched.
"""
from copy import deepcopy
import ctypes as C
import os

from dnlab_runtime.libvirt_activation_bus import connection_proof,reply_proof,validate
from dnlab_runtime.manifest import Conflict


def require(condition,message):
    if not condition:raise Conflict(message)


def success(result,operation):
    if result<0:raise OSError(-result,operation+': '+os.strerror(-result))
    return result


class SdBusABI:
    """Bind non-variadic v257 sd-bus signatures; construction makes no calls."""
    def __init__(self,library):
        self.library=library
        pointer=C.c_void_p;out=C.POINTER(pointer);string=C.c_char_p
        signatures={
            'sd_bus_is_open':([pointer],C.c_int),
            'sd_bus_is_ready':([pointer],C.c_int),
            'sd_bus_get_unique_name':([pointer,C.POINTER(string)],C.c_int),
            'sd_bus_message_new_method_call':([pointer,out,string,string,string,string],C.c_int),
            'sd_bus_message_append_basic':([pointer,C.c_char,pointer],C.c_int),
            'sd_bus_call':([pointer,pointer,C.c_uint64,pointer,out],C.c_int),
            'sd_bus_message_get_cookie':([pointer,C.POINTER(C.c_uint64)],C.c_int),
            'sd_bus_message_get_reply_cookie':([pointer,C.POINTER(C.c_uint64)],C.c_int),
            'sd_bus_message_get_sender':([pointer],string),
            'sd_bus_message_get_signature':([pointer,C.c_int],string),
            'sd_bus_message_read_basic':([pointer,C.c_char,pointer],C.c_int),
            'sd_bus_message_unref':([pointer],pointer),
        }
        for name,(args,result) in signatures.items():
            call=getattr(library,name);call.argtypes=args;call.restype=result

    def connected(self,handle,unique_name):
        require(isinstance(handle,C.c_void_p) and handle.value is not None and handle.value>3,
            'explicit borrowed sd-bus handle required')
        library=self.library
        if success(library.sd_bus_is_open(handle),'sd_bus_is_open')!=1:return False
        if success(library.sd_bus_is_ready(handle),'sd_bus_is_ready')!=1:return False
        name=C.c_char_p()
        success(library.sd_bus_get_unique_name(handle,C.byref(name)),'sd_bus_get_unique_name')
        return name.value==unique_name.encode('ascii')

    def call_start(self,handle,command,manager_owner,timeout):
        validate(command)
        require(type(timeout) is int and 0<timeout<=5,'bounded original bus call timeout required')
        return self._call(handle, manager_owner, command['path'], command['interface'],
                          command['member'], command['body'], 'o', timeout * 1_000_000)

    def _call(self, handle, destination, path, interface, method, arguments, output, timeout_usec):
        library=self.library;message=C.c_void_p();reply=C.c_void_p()
        try:
            success(library.sd_bus_message_new_method_call(
                handle, C.byref(message), destination.encode('ascii'), path.encode('ascii'),
                interface.encode('ascii'), method.encode('ascii')), 'sd_bus_message_new_method_call')
            require(message.value is not None,'original bus message missing')
            for value in arguments:
                success(library.sd_bus_message_append_basic(message,b's',C.c_char_p(value.encode('ascii'))),'sd_bus_message_append_basic')
            # A timeout/error is uncertain delivery. There is deliberately no loop.
            success(library.sd_bus_call(handle,message,timeout_usec,None,C.byref(reply)),'sd_bus_call')
            require(reply.value is not None,'original bus method reply missing')
            sent=C.c_uint64();received=C.c_uint64()
            success(library.sd_bus_message_get_cookie(message,C.byref(sent)),'sd_bus_message_get_cookie')
            success(library.sd_bus_message_get_reply_cookie(reply,C.byref(received)),'sd_bus_message_get_reply_cookie')
            sender=library.sd_bus_message_get_sender(reply)
            signature=library.sd_bus_message_get_signature(reply,1)
            require(isinstance(sender,bytes) and signature==output.encode('ascii'),
                    'original bus reply sender/signature missing')
            body = C.c_uint32() if output == 'u' else C.c_char_p()
            require(success(library.sd_bus_message_read_basic(reply,signature,C.byref(body)),
                            'sd_bus_message_read_basic') > 0 and body.value is not None,
                    'original bus reply body missing')
            return dict(call_serial=sent.value,reply_serial=received.value,sender=sender.decode('ascii'),
                signature=output,body=[body.value if output == 'u' else body.value.decode('ascii')])
        finally:
            if reply.value is not None:library.sd_bus_message_unref(reply)
            if message.value is not None:library.sd_bus_message_unref(message)


class SystemdStartBus:
    """Original connection only; qualification callback must bind library/context.

    Native manager/process/connection provenance and library loading remain the
    owner's responsibility. This adapter neither discovers nor repairs them.
    """
    def __init__(self,abi,handle,reference,*,transport,qualify):
        connection_proof(reference)
        require(callable(qualify),'explicit original bus qualification required')
        self.abi,self.handle,self.reference=abi,handle,deepcopy(reference)
        self.transport,self.qualify=deepcopy(transport),qualify

    def verify(self,connection,command):
        validate(command);connection_proof(connection)
        require(connection==self.reference and command['transport']==self.transport,'original bus transport or connection differs')
        return (self.qualify(deepcopy(connection),deepcopy(command)) is True
            and self.abi.connected(self.handle,self.reference['unique_name']) is True)

    def start_unit(self,connection,command,*,timeout):
        require(self.verify(connection,command),'original bus connection not qualified')
        result=self.abi.call_start(self.handle,command,self.reference['manager_owner'],timeout)
        reply_proof(result,self.reference)
        require(self.verify(connection,command),'original bus changed after StartUnit; delivery uncertain')
        return result
