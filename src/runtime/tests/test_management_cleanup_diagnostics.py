"""The fixture retains exact primitive evidence without relaxing failures."""
import importlib
import json
from pathlib import Path
import subprocess
import sys

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase


@pytest.fixture
def diagnostic_module(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'tools'))
    return importlib.import_module('management_link_authority_smoke')


def test_failed_primitive_retains_command_result_before_raising(diagnostic_module,tmp_path,monkeypatch):
    trace=diagnostic_module.DiagnosticLinux(tmp_path/'events.jsonl');trace.phase='after-stop-before-endpoint-delete-c'
    argv=['ip','link','delete','drsp-owned']
    def result(actual,**kwargs):
        assert actual==argv and kwargs['pass_fds']==(17,) and kwargs['timeout']==30
        return subprocess.CompletedProcess(actual,1,'partial output','Cannot find device "drsp-owned"\n')
    monkeypatch.setattr(diagnostic_module.subprocess,'run',result)
    with pytest.raises(RuntimeErrorBase,match='host primitive ip failed with exit code 1'):
        trace.run(argv,pass_fds=(17,))
    events=[json.loads(line) for line in trace.path.read_text().splitlines()]
    assert events[-1]['exit_code']==1 and events[-1]['stderr']=='Cannot find device "drsp-owned"\n'
    assert events[-1]['stdout']=='partial output' and events[-1]['argv']==argv
    assert events[-1]['phase']==trace.phase and events[-1]['command_id']==events[0]['command_id']
    assert trace.path.stat().st_mode & 0o777==0o600


def test_diagnostics_preserve_successful_output(diagnostic_module,tmp_path,monkeypatch):
    trace=diagnostic_module.DiagnosticLinux(tmp_path/'events.jsonl');trace.phase='snapshot'
    monkeypatch.setattr(diagnostic_module.subprocess,'run',lambda argv,**kwargs:subprocess.CompletedProcess(argv,0,'[]\n',''))
    assert trace.run(['ip','-j','link','show'])=='[]\n'
    event=json.loads(trace.path.read_text().splitlines()[-1]);assert event['exit_code']==0 and event['stdout']=='[]\n'


def test_timeout_evidence_does_not_swallow_original_exception(diagnostic_module,tmp_path,monkeypatch):
    trace=diagnostic_module.DiagnosticLinux(tmp_path/'events.jsonl');trace.phase='cleanup'
    timeout=subprocess.TimeoutExpired(['ip','link','show'],30)
    def fail(*args,**kwargs):raise timeout
    monkeypatch.setattr(diagnostic_module.subprocess,'run',fail)
    with pytest.raises(subprocess.TimeoutExpired) as actual:trace.run(['ip','link','show'])
    assert actual.value is timeout
    event=json.loads(trace.path.read_text().splitlines()[-1]);assert event['event']=='command-exception' and event['exception']=='TimeoutExpired'


def test_endpoint_disappearing_after_owned_read_completes_cleanup():
    """Model observed asynchronous removal; this does not prove the old host cause."""
    from dnlab_runtime.backend import Backend,Linux
    request={'lab_id':'lab','node_id':'vd'}
    spec={'endpoints':[{'host_interface':'drsp-owned','node_interface':'eth1'}]}
    class DisappearingLinux(Linux):
        present=True
        deletes=0
        def link(self,name,pid=None):
            assert name=='drsp-owned'
            return {'ifname':name,'ifindex':17,'ifalias':Backend.alias(request,spec)} if self.present else None
        def delete_link(self,expected):
            assert expected['ifindex']==17
            self.deletes+=1
            self.present=False  # The container namespace teardown wins the race.
            raise RuntimeErrorBase('host primitive ip failed with exit code 1')
    linux=DisappearingLinux();backend=Backend(linux=linux)
    backend.delete_endpoints(request,spec)
    assert linux.link('drsp-owned') is None
    backend.delete_endpoints(request,spec)
    assert linux.deletes==1


@pytest.mark.parametrize('state',['owned-present','foreign-replacement','verification-error'])
def test_failed_delete_preserves_errors_and_never_retries_present_or_unknown_port(state):
    from dnlab_runtime.backend import Backend,Linux
    request={'lab_id':'lab','node_id':'vd'}
    spec={'endpoints':[{'host_interface':'drsp-owned','node_interface':'eth1'}]}
    delete_error=RuntimeErrorBase('host primitive ip failed with exit code 1')
    verify_error=RuntimeErrorBase('kernel inventory unavailable')
    owned={'ifname':'drsp-owned','ifindex':17,'ifalias':Backend.alias(request,spec)}
    foreign={'ifname':'drsp-owned','ifindex':18,'ifalias':'foreign'}
    class FailingLinux(Linux):
        deletes=0
        def link(self,name,pid=None):
            if not self.deletes:return owned
            if state=='verification-error':raise verify_error
            return foreign if state=='foreign-replacement' else owned
        def delete_link(self,expected):
            self.deletes+=1
            raise delete_error
    linux=FailingLinux()
    with pytest.raises(RuntimeErrorBase) as actual:Backend(linux=linux).delete_endpoints(request,spec)
    assert actual.value is (verify_error if state=='verification-error' else delete_error)
    assert linux.deletes==1


def test_foreign_endpoint_is_refused_before_delete():
    from dnlab_runtime.backend import Backend,Linux
    from dnlab_runtime.manifest import Conflict
    class ForeignLinux(Linux):
        def link(self,name,pid=None):return {'ifname':name,'ifindex':18,'ifalias':'foreign'}
        def command(self,*args,**kwargs):pytest.fail('foreign interface must not be mutated')
    with pytest.raises(Conflict,match='foreign'):
        Backend(linux=ForeignLinux()).delete_endpoints({'lab_id':'lab','node_id':'vd'},
            {'endpoints':[{'host_interface':'drsp-owned','node_interface':'eth1'}]})


def test_replacement_after_absence_check_is_not_reported_cleaned():
    from dnlab_runtime.backend import Backend,Linux
    from dnlab_runtime.manifest import Conflict
    request={'lab_id':'lab','node_id':'vd'}
    spec={'endpoints':[{'host_interface':'drsp-owned','node_interface':'eth1'}]}
    class ReplacedLinux(Linux):
        reads=0;deletes=0
        def link(self,name,pid=None):
            self.reads+=1
            if self.reads==1:return {'ifname':name,'ifindex':17,'ifalias':Backend.alias(request,spec)}
            if self.reads==2:return None
            return {'ifname':name,'ifindex':18,'ifalias':'foreign'}
        def delete_link(self,expected):
            self.deletes+=1
            raise RuntimeErrorBase('host primitive ip failed with exit code 1')
    linux=ReplacedLinux()
    with pytest.raises(Conflict,match='still exists'):Backend(linux=linux).delete_endpoints(request,spec)
    assert linux.deletes==1


def test_timed_out_delete_completes_only_after_absence_is_verified():
    from dnlab_runtime.backend import Backend,Linux
    request={'lab_id':'lab','node_id':'vd'}
    spec={'endpoints':[{'host_interface':'drsp-owned','node_interface':'eth1'}]}
    class TimedOutLinux(Linux):
        deletes=0
        def link(self,name,pid=None):
            return None if self.deletes else {'ifname':name,'ifindex':17,'ifalias':Backend.alias(request,spec)}
        def delete_link(self,expected):
            self.deletes+=1;raise subprocess.TimeoutExpired(['kernel-endpoint-delete'],30)
    linux=TimedOutLinux();Backend(linux=linux).delete_endpoints(request,spec)
    assert linux.deletes==1


def test_name_replacement_before_delete_preserves_foreign_endpoint():
    """Actual backend control flow, with an external replacement between syscalls."""
    from dnlab_runtime.backend import Backend,Linux
    request={'lab_id':'lab','node_id':'vd'}
    spec={'endpoints':[{'host_interface':'drsp-owned','node_interface':'eth1'}]}
    owned={'ifname':'drsp-owned','ifindex':17,'ifalias':Backend.alias(request,spec),'address':'02:00:00:00:00:17'}
    foreign={'ifname':'drsp-owned','ifindex':18,'ifalias':'foreign-owner','address':'02:00:00:00:00:18'}
    class ReplacingLinux(Linux):
        live=owned;reads=0;deleted=[]
        def link(self,name,pid=None):
            if name!='drsp-owned':return None
            self.reads+=1
            if self.reads==1:
                self.live=foreign  # The qualified object vanishes; another object takes its name.
                return owned.copy()
            return self.live
        def delete_link(self,expected):
            assert expected['ifindex']==17
            if self.live and self.live['ifindex']==expected['ifindex']:
                self.deleted.append(self.live.copy());self.live=None
    linux=ReplacingLinux()
    from dnlab_runtime.manifest import Conflict
    with pytest.raises(Conflict,match='still exists'):Backend(linux=linux).delete_endpoints(request,spec)
    assert linux.deleted==[] and linux.live==foreign
    with pytest.raises(Conflict,match='foreign'):Backend(linux=linux).delete_endpoints(request,spec)
    assert linux.live==foreign


def test_namespace_or_identity_conflict_is_never_hidden_by_later_absence():
    from dnlab_runtime.backend import Backend,Linux
    from dnlab_runtime.manifest import Conflict
    request={'lab_id':'lab','node_id':'vd'};spec={'endpoints':[{'host_interface':'drsp-owned','node_interface':'eth1'}]}
    class WrongNamespace(Linux):
        attempted=False
        def link(self,name,pid=None):
            return None if self.attempted else {'ifname':name,'ifindex':17,'ifalias':Backend.alias(request,spec)}
        def delete_link(self,expected):
            self.attempted=True;raise Conflict('endpoint namespace identity changed')
    with pytest.raises(Conflict,match='namespace'):
        Backend(linux=WrongNamespace()).delete_endpoints(request,spec)
