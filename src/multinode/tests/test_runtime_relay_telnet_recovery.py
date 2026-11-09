"""Execute the actual in-VD recovery program against simulated proc/pidfds."""
import builtins
import io
import os
import signal
from types import SimpleNamespace
import pytest
from tests.runtime_relay_import import load_runtime_relay_module
relay = load_runtime_relay_module()


def program(monkeypatch, args, *, disappeared=False, supported=True, exited=True, reused=False):
    closed=[];sent=[]
    fake_os=SimpleNamespace(listdir=lambda path:list(args), path=os.path,
                            close=closed.append)
    if supported: fake_os.pidfd_open=lambda pid:100+pid
    def send(fd,sig):
        if reused: raise ProcessLookupError()
        sent.append((fd,sig))
    fake_signal=SimpleNamespace(SIGTERM=signal.SIGTERM, pidfd_send_signal=send)
    def open_proc(path,mode):
        pid=path.split('/')[2]
        if disappeared: raise FileNotFoundError()
        return io.BytesIO(b'\0'.join(args[pid])+b'\0')
    poll=SimpleNamespace(register=lambda *a:None,poll=lambda delay:[(1,1)] if exited else [])
    modules={'os':fake_os,'signal':fake_signal,'select':SimpleNamespace(poll=lambda:poll,POLLIN=1),'sys':SimpleNamespace(argv=['cleanup','5000'])}
    def imports(name,*a,**kw): return modules[name]
    scope = dict(vars(builtins), __import__=imports, open=open_proc)
    try: exec(relay._TELNET_CLEANUP, {'__builtins__':scope})
    finally:
        assert sorted(closed)==sorted(100+int(v) for v in args) if supported else not closed
    return sent


def test_exact_selection_and_pidfds_closed(monkeypatch):
    args={
        '1':[b'/usr/bin/telnet',b'127.0.0.1',b'5000'],
        '2':[b'inetutils-telnet',b'127.0.0.1',b'5000'],
        '3':[b'telnet',b'127.0.0.1',b'5001'],
        '4':[b'telnet',b'192.0.2.1',b'5000'],
        '5':[b'sh',b'-c',b'telnet 127.0.0.1 5000'],
        '6':[b'telnet',b'127.0.0.1',b'5000',b'extra'],
    }
    assert program(monkeypatch,args)==[(101,signal.SIGTERM),(102,signal.SIGTERM)]


@pytest.mark.parametrize('disappeared,exited',[(True,True),(False,True)])
def test_exit_is_qualified(monkeypatch,disappeared,exited):
    result=program(monkeypatch,{'1':[b'telnet',b'127.0.0.1',b'5000']},disappeared=disappeared,exited=exited)
    assert result==([] if disappeared else [(101,signal.SIGTERM)])


@pytest.mark.parametrize('disappeared',[True,False])
def test_incomplete_observation_or_term_timeout_rejected(monkeypatch,disappeared):
    with pytest.raises(RuntimeError):program(monkeypatch,{'1':[b'telnet',b'127.0.0.1',b'5000']},disappeared=disappeared,exited=False)


def test_missing_pidfd_fails_without_signal(monkeypatch):
    with pytest.raises(RuntimeError, match='pidfd support'):
        program(monkeypatch,{},supported=False)


def test_recovery_precedes_upstream_open(monkeypatch):
    broker=relay._ConsoleBroker('fixture');calls=[]
    monkeypatch.setattr(relay,'_cleanup_container_telnet',lambda *a:calls.append('recover'))
    monkeypatch.setattr(broker,'_open_upstream',lambda *a:calls.append('open'))
    broker._start_upstream(['fixture'],'5000')
    assert calls==['recover','open']


def test_recovery_error_prevents_new_upstream(monkeypatch):
    broker=relay._ConsoleBroker('fixture')
    monkeypatch.setattr(relay,'_cleanup_container_telnet',lambda *a:(_ for _ in ()).throw(RuntimeError('failed')))
    monkeypatch.setattr(broker,'_open_upstream',lambda *a:pytest.fail('must not open'))
    with pytest.raises(RuntimeError):broker._start_upstream(['fixture'],'5000')
    assert broker._cleanup_error=='RuntimeError'


def test_pid_reuse_never_falls_back_to_numeric_pid_signal(monkeypatch):
    assert program(monkeypatch,{'1':[b'telnet',b'127.0.0.1',b'5000']},reused=True)==[]
