"""Lost-ack injection preserves the original operation and underlying failures."""
import importlib.util
from pathlib import Path
import pytest

spec=importlib.util.spec_from_file_location('probe_recovery',Path(__file__).resolve().parents[1]/'tools/management_probe_recovery.py')
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)


def test_boundary_drops_only_after_original_result_and_never_retries_itself():
    calls=[];birth={'container_id':'fixture'};request={'host':'master','segment':'blue','request_id':'id'}
    def invoke(client,request,action,**kwargs):calls.append((action,kwargs));return {'resource_proof':birth}
    boundary=module.ProbeBoundary(invoke)
    for action in ('packets','cleanup'):
        with pytest.raises(module.LostProbeAcknowledgment):boundary(None,request,action,expected_birth=birth)
    assert [a for a,k in calls]==['packets','cleanup'] and not boundary.pending
    assert len(boundary.losses)==2 and all(v['returned'] for v in boundary.losses)
    assert boundary(None,request,'verify-cleaned',expected_birth=birth)=={'resource_proof':birth}


def test_underlying_failure_is_not_reclassified_as_injected_loss():
    def failed(*args,**kwargs):raise OSError('real transport failure')
    boundary=module.ProbeBoundary(failed)
    with pytest.raises(OSError,match='real transport'):
        boundary(None,{'host':'master','segment':'blue','request_id':'id'},'packets',expected_birth={})
    assert not boundary.losses and boundary.pending==['packets','cleanup']


@pytest.mark.parametrize('path,killed',[('/exec/'+'a'*64+'/start',True),('/containers/fixture/exec',False)])
def test_fixture_sigkill_targets_only_its_own_worker_after_exec_start(path,killed):
    import subprocess,sys
    source="import os\nclass DockerExecHTTP:\n def call(self,*args,**kwargs):return {}\ndef main():\n DockerExecHTTP().call('POST',"+repr(path)+")\n print('returned')\nif __name__=='__main__':main()\n"
    result=subprocess.run([sys.executable,'-I','-c',module.crash_after_exec_start(source)],text=True,capture_output=True)
    assert result.returncode==(-9 if killed else 0),result.stderr
    assert result.stdout==('' if killed else 'returned\n')


def test_only_verified_fixture_worker_crash_is_classified_as_expected():
    original=module.ProbeWorkerCrashed('verified own worker')
    try:raise RuntimeError('transport wrapper') from original
    except RuntimeError as error:assert module.caused_by_worker_crash(error)
    assert not module.caused_by_worker_crash(OSError('other failure'))
