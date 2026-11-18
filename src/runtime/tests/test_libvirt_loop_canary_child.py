"""Child composition and bounded pipe framing with synthetic providers only."""
from copy import deepcopy
import json
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from libvirt_loop_canary_child import ChildFrames, run_child
from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.journal import Journal
from dnlab_runtime.vm_runtime_process import RuntimeProcess


@pytest.fixture
def child():
    request=dict(nonce='a'*32,command={})
    profile=dict(sources_sha256='b'*64)
    epoch=dict(profile=deepcopy(profile),snapshot=dict(record=dict(pid=123)))
    state=dict(events=[],frames=[],sources=profile['sources_sha256'],closed=False)
    sdk=object();journal=object()
    class Runtime:
        def __init__(self,current,expected,*,verify_sources):
            assert current is journal and expected==profile
            state['events'].append('runtime');self.journal=current
        def start(self):state['events'].append('start');return deepcopy(epoch)
        def check(self):return deepcopy(epoch)
        def close(self):state['closed']=True
    frames=iter([dict(release=request['nonce'],request_sha256=fingerprint(request)),None])
    def receive():state['events'].append('read');return next(frames)
    def load():state['events'].append('sdk');return sdk
    def runner(runtime,current,*,preflight):
        assert current is sdk
        state['events'].append('loop')
        assert preflight()==dict(purpose='isolated-libvirt-loop-canary',
            runtime_epoch_sha256=fingerprint(epoch),hypervisor_connections_allowed=False,domain_actions_allowed=False)
        return dict(phase='awaiting_process_exit')
    kwargs=dict(verify_sources=lambda:state['sources'],load_sdk=load,read_frame=receive,
        write_frame=state['frames'].append,runtime_factory=Runtime,runner=runner)
    return SimpleNamespace(request=request,profile=profile,epoch=epoch,state=state,journal=journal,kwargs=kwargs)


def test_child_release_precedes_runtime_capture_sdk_import_and_dispatch(child):
    e=child
    assert run_child(e.request,e.profile,e.journal,**e.kwargs)==0
    assert e.state['events']==['read','runtime','start','sdk','loop','read']
    assert e.state['closed'] and len(e.state['frames'])==2
    assert e.state['frames'][0]==dict(ready=e.request['nonce'],request_sha256=fingerprint(e.request))
    assert e.state['frames'][1]['epoch']==e.epoch


@pytest.mark.parametrize('release',[None,{},dict(release='foreign')])
def test_no_release_never_captures_runtime_or_loads_sdk(child,release):
    e=child;e.kwargs['read_frame']=lambda:release
    with pytest.raises(RuntimeErrorBase,match='parent release'):
        run_child(e.request,e.profile,e.journal,**e.kwargs)
    assert e.state['events']==[] and not e.state['closed'] and len(e.state['frames'])==1


def test_source_change_at_release_is_refused_before_capture(child):
    e=child
    def release():
        e.state['sources']='c'*64
        return dict(release=e.request['nonce'],request_sha256=fingerprint(e.request))
    e.kwargs['read_frame']=release
    with pytest.raises(RuntimeErrorBase,match='sources/profile differ'):
        run_child(e.request,e.profile,e.journal,**e.kwargs)
    assert e.state['events']==[] and not e.state['closed']


def test_sdk_failure_closes_witness_without_claiming_process_exit(child):
    e=child
    def fail():raise ValueError('original SDK import failed')
    e.kwargs['load_sdk']=fail
    with pytest.raises(ValueError,match='SDK import failed'):
        run_child(e.request,e.profile,e.journal,**e.kwargs)
    assert e.state['closed'] and len(e.state['frames'])==1 and 'loop' not in e.state['events']


def test_source_change_in_sdk_loader_prevents_dispatch(child):
    e=child
    def change():e.state['sources']='c'*64;return object()
    e.kwargs['load_sdk']=change
    with pytest.raises(RuntimeErrorBase,match='sources/profile differ'):
        run_child(e.request,e.profile,e.journal,**e.kwargs)
    assert e.state['closed'] and 'loop' not in e.state['events'] and len(e.state['frames'])==1


def test_extra_parent_frame_is_refused_after_report(child):
    e=child;calls=[]
    def receive():
        calls.append(True)
        return dict(release=e.request['nonce'],request_sha256=fingerprint(e.request))
    e.kwargs['read_frame']=receive
    with pytest.raises(RuntimeErrorBase,match='parent EOF'):
        run_child(e.request,e.profile,e.journal,**e.kwargs)
    assert len(calls)==2 and e.state['closed'] and len(e.state['frames'])==2


def codec(blocks):
    chunks=list(blocks);written=[]
    def read(fd,count):
        assert fd==3
        if not chunks:return b''
        chunk=chunks[0][:count];chunks[0]=chunks[0][count:]
        if not chunks[0]:chunks.pop(0)
        return chunk
    def write(fd,data):assert fd==4;written.append(data[:3]);return len(data[:3])
    frames=ChildFrames(3,4,read=read,write=write,wait=lambda readers,writers,errors,timeout:(readers,writers,[]))
    return frames,written


def test_pipe_frames_retain_coalesced_tail_and_accept_clean_eof():
    frames,_=codec([b'{"release":"original"}\n{"next":1}\n'])
    assert frames.receive()==dict(release='original')
    assert frames.receive()==dict(next=1)
    assert frames.receive() is None


@pytest.mark.parametrize('raw',[b'{"a":1,"a":2}\n',b'{"a":NaN}\n',b'[]\n',b'{}',b'\n',b'x'*65537])
def test_pipe_refuses_ambiguous_nonfinite_partial_or_oversized_frames(raw):
    frames,_=codec([raw])
    with pytest.raises((RuntimeErrorBase,ValueError)):frames.receive()


def test_pipe_reassembles_short_writes_and_enforces_output_bound():
    frames,written=codec([])
    frames.send(dict(nonce='a'*32))
    assert json.loads(b''.join(written))==dict(nonce='a'*32)
    with pytest.raises(RuntimeErrorBase,match='output frame exceeds'):frames.send(dict(value='a'*65536))


def test_pipe_deadlines_refuse_without_retry_or_extra_io():
    frames,_=codec([]);frames.wait=lambda *args:([],[],[])
    with pytest.raises(RuntimeErrorBase,match='input deadline'):frames.receive()
    with pytest.raises(RuntimeErrorBase,match='output deadline'):frames.send({})


def test_child_persists_real_runtime_epoch_and_closes_only_its_witness(tmp_path):
    import os
    journal=Journal(tmp_path/'journal')
    spaces={name:dict(device=4,inode=index+100) for index,name in enumerate(('pid','mnt','net','user'))}
    profile=dict(host_id='master',executable_sha256='a'*64,cmdline_sha256='b'*64,
                 namespaces=spaces,sources_sha256='c'*64)
    snapshot=dict(record=dict(boot_id='12345678-1234-4234-8234-123456789abc',pid=123,
        start_ticks=456,uid=0,gid=0,executable_sha256='a'*64,namespace_sha256=fingerprint(spaces)),
        namespaces=spaces,proc_identity=[4,800],cmdline_sha256='b'*64)
    request=dict(nonce='d'*32,command={});written=[];captured=[]
    class Poll:
        def register(self,fd,events):pass
        def poll(self,timeout):return []
    def factory(current,expected,*,verify_sources):
        runtime=RuntimeProcess(current,expected,verify_sources=verify_sources,
            reader=SimpleNamespace(read_process=lambda pid:deepcopy(snapshot)),
            pidfd_open=lambda pid,flags:os.open('/dev/null',os.O_RDONLY),
            poll_factory=Poll,process_id=lambda:123,thread_namespaces=lambda:deepcopy(spaces))
        captured.append(runtime)
        return runtime
    frames=iter([dict(release=request['nonce'],request_sha256=fingerprint(request)),None])
    def runner(runtime,sdk,*,preflight):
        epoch=runtime.check()
        assert preflight()['runtime_epoch_sha256']==fingerprint(epoch)
        return dict(phase='awaiting_process_exit',epoch_sha256=fingerprint(epoch),
                    qualified=True,cleanup_verified=False,requires_original_process_exit=True,gate_allowed=False)
    try:
        assert run_child(request,profile,journal,verify_sources=lambda:profile['sources_sha256'],
            load_sdk=object,read_frame=lambda:next(frames),write_frame=written.append,
            runtime_factory=factory,runner=runner)==0
        saved=journal.db.execute('SELECT payload FROM vm_runtime_epochs').fetchone()[0]
        assert json.loads(saved)==written[1]['epoch'] and captured[0].fd is None
        assert written[1]['result']['cleanup_verified'] is False
        assert written[1]['epoch']['snapshot']==snapshot
    finally:
        for runtime in captured:runtime.close()
        journal.close()
