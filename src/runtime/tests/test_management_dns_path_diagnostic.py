"""The diagnostic observes the original exec once without changing its result."""
from contextlib import contextmanager
import importlib.util
import json
import os
from pathlib import Path
import socket
from types import SimpleNamespace
import pytest

TOOLS=Path(__file__).resolve().parents[1]/'tools'
spec=importlib.util.spec_from_file_location('path_capture',TOOLS/'management_dns_path_capture.py')
m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m)


def test_filter_keeps_only_original_ip_or_arp():
    frame=bytearray(42);frame[12:14]=b'\x08\x00';frame[26:30]=socket.inet_aton('198.19.234.252');frame[30:34]=socket.inet_aton('198.19.100.2')
    assert m.relevant(frame,{'198.19.100.2'})
    assert not m.relevant(frame,{'192.0.2.1'})
    frame[12:14]=b'\x08\x06';frame[28:32]=socket.inet_aton('198.19.234.252')
    assert m.relevant(frame,{'198.19.234.252'})
    assert not m.relevant(b'',{'198.19.234.252'})


def test_frame_and_scan_budgets_are_finite():
    class Sock:
        def recvmsg(self,*args):return b'frame',[],0,('probe0',0,4)
        def close(self):self.closed=True
    capture=m.Capture([]);sock=Sock();row={'scanned':0,'matched':0,'frames':[]}
    capture.sockets=[(sock,row)];old=m.relevant
    try:
        m.relevant=lambda *_:True
        for _ in range(10):capture.drain()
    finally:m.relevant=old
    assert row['scanned']==capture.MAX_SCANNED and row['matched']==capture.MAX_SCANNED
    assert len(row['frames'])==capture.MAX_FRAMES and row['scan_limit']
    capture.close();assert sock.closed and not capture.sockets


def test_open_restores_namespace_and_closes_failed_socket(monkeypatch):
    calls=[]
    class Sock:
        def setsockopt(self,*args):pass
        def bind(self,*args):raise RuntimeError('bind failed')
        def close(self):calls.append('close-socket')
    monkeypatch.setattr(m.os,'open',lambda *_:99)
    monkeypatch.setattr(m.os,'close',lambda fd:calls.append(('close',fd)))
    monkeypatch.setattr(m.os,'setns',lambda fd,_:calls.append(('setns',fd)))
    monkeypatch.setattr(m.socket,'if_nametoindex',lambda _:5)
    monkeypatch.setattr(m.socket,'socket',lambda *_:Sock())
    with pytest.raises(RuntimeError,match='bind failed'):m.Capture([]).open(10,'probe0','client')
    assert calls==[('setns',10),('setns',99),('close',99),'close-socket']


@pytest.mark.parametrize('failed',[False,True])
def test_original_run_once_result_failure_and_observer_restored(tmp_path,monkeypatch,failed):
    calls=[]
    class Cap:
        def __init__(self,*args):self.points=[]
        def open(self,fd,name,label):self.points.append({'label':label});calls.append(('open',label))
        def drain(self):calls.append('drain')
        def close(self):calls.append('closed')
    record={'container_id':'id','nonce':'nonce','namespace':{},'started_at':'now',
            'config':{'attachment':{'segment':'blue','interface':'jmblue'},'ip':'198.19.100.3'}}
    class Worker:
        def __init__(self,*args,**kwargs):pass
        def read(self):return record
        def infrastructure(self,*args):pass
        def verify_extensions(self,*args):pass
        def verify_attachment(self,*args):pass
        def container(self,*args):return {'Id':'id','State':{'Running':True,'Pid':os.getpid(),'StartedAt':'now'}}
        def open_ns(self,pid):return os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY)
        @contextmanager
        def namespace(self,*args):yield 11
        def find(self,*args):return {'ifindex':1}
        def packet_endpoint(self,*args):pass
    class Execution:
        def __init__(self):
            self.w=Worker();self.r=record;self.w.request={'lab':'lab','segment':'blue','packet_profile':{'addresses':{'4':'198.19.234.252'},'resolvers':{'4':'198.19.100.2'},'server_ip':'198.19.234.254'}}
        def identity(self):return {'id':'original'}
        def original(self):calls.append('guard')
        def observe_exit(self,**kwargs):calls.append('observe')
        def run(self):
            calls.append('run');self.observe_exit()
            if failed:raise ValueError('original DNS timeout')
            return 'original-result'
    original_observe=Execution.observe_exit
    monkeypatch.setattr(m,'Capture',Cap);monkeypatch.setattr(m,'snapshot',lambda fd:[])
    m.install(Execution,Worker,Worker,tmp_path)
    if failed:
        with pytest.raises(ValueError,match='original DNS timeout'):Execution().run()
    else:assert Execution().run()=='original-result'
    report=json.loads((tmp_path/'dns-path.json').read_text())
    assert calls.count('run')==1 and calls.count('observe')==1
    assert Execution.observe_exit is original_observe and calls[-1]=='closed'
    assert report['phase']=='observed' and report['post_identity']=='verified'
    assert [v['label'] for v in report['points']]==['client','jumphost-management','jumphost-wan','dns']
    assert (tmp_path/'dns-path.json').stat().st_mode&0o777==0o600
    assert bool(report.get('original_error'))==failed


def test_instrumentation_compiles_without_changing_original_client():
    import sys
    sys.path.insert(0,str(TOOLS));sys.path.insert(0,str(TOOLS.parents[1]/'multinode'))
    from management_dns_path_host import instrument
    from dnlab_multinode.services.management_probe_runtime import program,packet_program
    source=program();result=instrument(source,'/tmp/drsp-diagnostic')
    compile(result,'diagnostic-worker','exec')
    assert source.split("if __name__=='__main__':main()")[0] in result
    assert 'PACKET_SOURCE='+repr(packet_program()) in result
    assert "_fixture_capture['install']" in result


def test_host_instruments_only_one_dns_packet_call(tmp_path,monkeypatch):
    import sys
    sys.path.insert(0,str(TOOLS))
    from management_dns_path_host import DNSPathHost
    import management_dns_path_host as host_module
    calls=[]
    monkeypatch.setattr(host_module,'instrument',lambda source,root:source+' instrumented')
    monkeypatch.setattr(host_module.DiagnosticHost,'run_input',lambda self,command,payload,**kw:calls.append(json.loads(payload)))
    host=DNSPathHost(tmp_path)
    for action,mode in [('inspect','dns-client'),('packets','dhcp'),('packets','dns-client'),('packets','dns-client')]:
        host.run_input('original',json.dumps({'source':'original','request':{'action':action,'request':{'packet_profile':{'mode':mode}}}}))
    assert [v['source'] for v in calls]==['original','original','original instrumented','original']


def test_dns_namespace_needs_no_journal_namespace_and_never_saves():
    record={'container_id':'original-id','nonce':'original-nonce'};before=json.dumps(record)
    class Worker:
        def container(self,r):return {'Id':r['container_id'],'State':{'Running':True,'Pid':os.getpid(),'StartedAt':'original-start'}}
        def open_ns(self,pid):return os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY)
        def save(self,*args):raise AssertionError('readonly diagnostic wrote journal')
    with m.dns_namespace(Worker(),record) as (fd,proof):
        assert os.fstat(fd).st_ino==proof['namespace']['inode']
        assert proof['container_id']=='original-id' and proof['pid']==os.getpid()
        assert proof['started_at']=='original-start' and proof['process_start']
    with pytest.raises(OSError):os.fstat(fd)
    assert json.dumps(record)==before


@pytest.mark.parametrize('change',['container','pid','started','namespace'])
def test_dns_namespace_refuses_changed_identity_and_closes_fd(monkeypatch,change):
    record={'container_id':'original-id','nonce':'original-nonce'};calls=[]
    class Worker:
        def container(self,r):
            return {'Id':('replacement' if change=='container' and calls else 'original-id'),
                    'State':{'Running':True,'Pid':(0 if change=='pid' and calls else os.getpid()),
                             'StartedAt':('changed' if change=='started' and calls else 'original')}}
        def open_ns(self,pid):
            fd=os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY);calls.append(fd);return fd
    if change=='namespace':
        original=m.os.fstat
        monkeypatch.setattr(m.os,'fstat',lambda fd:SimpleNamespace(st_dev=original(fd).st_dev,st_ino=original(fd).st_ino+1))
    with pytest.raises(RuntimeError):
        with m.dns_namespace(Worker(),record):raise AssertionError('changed identity accepted')
    assert len(calls)==1
    with pytest.raises(OSError):os.fstat(calls[0])


def test_dns_namespace_checks_after_observation_and_closes_fd():
    changed=False;record={'container_id':'original-id','nonce':'nonce'}
    class Worker:
        def container(self,r):return {'Id':'original-id','State':{'Running':True,'Pid':os.getpid(),'StartedAt':'new' if changed else 'old'}}
        def open_ns(self,pid):return os.open('/proc/'+str(pid)+'/ns/net',os.O_RDONLY)
    with pytest.raises(RuntimeError,match='process or namespace changed'):
        with m.dns_namespace(Worker(),record) as (fd,proof):changed=True
    with pytest.raises(OSError):os.fstat(fd)


def test_cleanup_finishes_live_attempt_before_replaying_cleaned_predecessors(tmp_path):
    import sys
    sys.path.insert(0,str(TOOLS))
    from management_service_diagnostics import probe_cleanup_order
    for name,phase in [('a-old','cleaned'),('z-live','cleanup_pending'),('b-old','cleaned')]:
        (tmp_path/(name+'.json')).write_text(json.dumps({'phase':phase}))
    pending={'z-live'};seen=[]
    for path in probe_cleanup_order(tmp_path):
        name=path.stem
        if name!='z-live' and pending:raise AssertionError('old cleanup hit original live-attempt preflight')
        pending.discard(name);seen.append(name)
    assert seen==['z-live','a-old','b-old'] and not pending
    assert json.loads((tmp_path/'z-live.json').read_text())['phase']=='cleanup_pending'


def test_cleanup_order_keeps_bad_journal_for_original_error_handling(tmp_path):
    import sys
    sys.path.insert(0,str(TOOLS))
    from management_service_diagnostics import probe_cleanup_order
    (tmp_path/'bad.json').write_text('{incomplete')
    (tmp_path/'old.json').write_text('{"phase":"cleaned"}')
    assert [p.name for p in probe_cleanup_order(tmp_path)]==['bad.json','old.json']
    assert (tmp_path/'bad.json').read_text()=='{incomplete'
