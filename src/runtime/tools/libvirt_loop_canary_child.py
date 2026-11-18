"""Gated child composition for the loop-only canary; no import-time actions.

The launcher supplies qualified sources, SDK loader, interpreter profile and
private journal. SDK loading and runtime capture happen only after the original
parent's release. This module never connects to libvirt or launches a process.
"""
from copy import deepcopy
import json
import os
import select
import time

from dnlab_runtime.manifest import canonical, fingerprint
from dnlab_runtime.vm_runtime_process import RuntimeProcess
from dnlab_runtime.vm_template import fields, require
from libvirt_event_loop_canary import run as run_loop


class ChildFrames:
    """Bounded unbuffered pipe protocol, retaining bytes after each newline."""
    def __init__(self, input_fd, output_fd, *, timeout=10, limit=65536,
                 read=os.read, write=os.write, wait=select.select, clock=time.monotonic):
        require(type(input_fd) is int and input_fd>=0 and type(output_fd) is int
                and output_fd>=0 and input_fd!=output_fd
                and type(timeout) in (int,float) and 0<timeout<=10
                and type(limit) is int and 1024<=limit<=65536,
                'distinct original pipe descriptors and bounded frames required')
        self.input_fd,self.output_fd=input_fd,output_fd
        self.timeout,self.limit=timeout,limit
        self.read,self.write,self.wait,self.clock=read,write,wait,clock
        self.pending=b''

    @staticmethod
    def _object(pairs):
        value={}
        for key,item in pairs:
            require(key not in value, 'duplicate child frame field')
            value[key]=item
        return value

    @staticmethod
    def _constant(value):
        raise ValueError('nonfinite child frame value refused')

    def receive(self):
        deadline=self.clock()+self.timeout
        while True:
            if b'\n' in self.pending:
                line,self.pending=self.pending.split(b'\n',1)
                require(0<len(line)<=self.limit, 'bounded complete child frame required')
                value=json.loads(line,object_pairs_hook=self._object,parse_constant=self._constant)
                require(type(value) is dict, 'child frame object required')
                return value
            require(len(self.pending)<=self.limit, 'child frame exceeds bound')
            remaining=deadline-self.clock()
            require(remaining>0, 'original child input deadline exceeded')
            readable,_,_=self.wait([self.input_fd],[],[],remaining)
            require(self.input_fd in readable, 'original child input deadline exceeded')
            block=self.read(self.input_fd,min(4096,self.limit+1-len(self.pending)))
            if not block:
                require(not self.pending, 'truncated child frame at EOF')
                return None
            self.pending+=block

    def send(self,value):
        require(type(value) is dict, 'child frame object required')
        packet=(canonical(value)+'\n').encode()
        require(len(packet)<=self.limit+1, 'child output frame exceeds bound')
        deadline=self.clock()+self.timeout
        while packet:
            remaining=deadline-self.clock()
            require(remaining>0, 'original child output deadline exceeded')
            _,writable,_=self.wait([],[self.output_fd],[],remaining)
            require(self.output_fd in writable, 'original child output deadline exceeded')
            # Small writes avoid relying on pipe capacity for a complete report.
            count=self.write(self.output_fd,packet[:512])
            require(type(count) is int and 0<count<=min(512,len(packet)), 'original child write incomplete')
            packet=packet[count:]


def run_child(request, profile, journal, *, verify_sources, load_sdk, read_frame,
              write_frame, runtime_factory=RuntimeProcess, runner=run_loop):
    """Compose an original RuntimeProcess and loop after the release boundary.

    The SDK provider must independently qualify its files/import paths. Closing
    the runtime witness is not an exit proof: the parent retains that duty.
    """
    fields(request,('nonce','command'),'loop child request')
    expected=deepcopy(profile);request_sha256=fingerprint(request)
    require(all(callable(fn) for fn in (verify_sources,load_sdk,read_frame,write_frame,runtime_factory,runner)),
            'qualified original child providers required')
    def sources():
        value=verify_sources()
        require(profile==expected and value==expected['sources_sha256'], 'original child sources/profile differ')
        return value
    sources()
    write_frame(dict(ready=request['nonce'],request_sha256=request_sha256))
    require(read_frame()==dict(release=request['nonce'],request_sha256=request_sha256),
            'original parent release required before child runtime or SDK')
    sources()
    runtime=runtime_factory(journal,expected,verify_sources=sources)
    try:
        epoch=runtime.start()
        require(epoch['profile']==expected, 'original child runtime profile differs')
        sources();sdk=load_sdk();sources()
        require(runtime.check()==epoch, 'original child runtime changed during SDK load')
        scope=dict(purpose='isolated-libvirt-loop-canary',runtime_epoch_sha256=fingerprint(epoch),
                   hypervisor_connections_allowed=False,domain_actions_allowed=False)
        def preflight():
            sources()
            require(runtime.check()==epoch, 'original child runtime changed during canary')
            return deepcopy(scope)
        result=runner(runtime,sdk,preflight=preflight)
        sources()
        require(runtime.check()==epoch, 'original child runtime changed before report')
        write_frame(dict(result=result,epoch=epoch,request_sha256=request_sha256))
        require(read_frame() is None, 'original parent EOF required after child report')
        return 0
    finally:
        runtime.close()
