"""Standalone guard delivery must not depend on the source fitting in argv."""
import json
import os
import shlex

from dnlab_multinode.services import jumphost


def test_guard_source_delivery_uses_bounded_process_arguments():
    captured={}
    class Transport:
        def run_input(self,command,payload,timeout):
            captured.update(command=command,payload=payload,timeout=timeout)
            return json.dumps({'phase':'absent'})
    assert jumphost._guard(Transport(),'transport-diagnostic','read')=={'phase':'absent'}
    sizes=[len(value.encode())+1 for value in shlex.split(captured['command'])]
    # On Linux an individual exec argument is bounded to 32 kernel pages,
    # independently of the larger aggregate ARG_MAX environment budget.
    limit=os.sysconf('SC_PAGESIZE')*32
    assert max(sizes)<limit, f'worker transport argument {max(sizes)} bytes exceeds {limit}-byte limit'


class LocalTransport:
    """Run exactly the argv/stdin pair used by SSH, without Docker or root work."""
    def run_input(self,command,payload,timeout):
        import subprocess
        result=subprocess.run(shlex.split(command),input=payload,text=True,capture_output=True,timeout=timeout,check=True)
        return result.stdout


def test_actual_large_worker_source_executes_over_stdin_without_host_operations(monkeypatch):
    from pathlib import Path
    original=Path.read_text
    source=original(Path(jumphost.__file__).with_name('jumphost_host.py'))
    # Replace only the root entrypoint with a harmless request echo. Compile and
    # execute all production class/function definitions in the real interpreter.
    source=source.replace("if __name__ == '__main__': main()", "if __name__ == '__main__': print(canonical({'phase':'observed','request':json.load(sys.stdin)}))")
    assert len(source.encode())>os.sysconf('SC_PAGESIZE')*32
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**kw:source)
    value={'secret':"unicode-à\nquote' $() `literal`",'nested':{'values':[1,True,None]}}
    result=jumphost._guard(LocalTransport(),'lab-unicode-à','read',value)
    assert result['phase']=='observed'
    assert result['request']['config']==value and result['request']['lab']=='lab-unicode-à'
    assert 'source' not in result['request']


def test_request_is_data_and_does_not_execute_as_python(monkeypatch):
    from pathlib import Path
    source="import json,sys\nprint(json.dumps({'phase':'observed','value':json.load(sys.stdin)['config']}))\n"
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**kw:source)
    value={'text':"'); raise RuntimeError('injected'); #\n"}
    assert jumphost._guard(LocalTransport(),'lab','read',value)['value']==value


def test_worker_failure_retains_public_error_without_payload_exposure(monkeypatch):
    from pathlib import Path
    import pytest
    monkeypatch.setattr(Path,'read_text',lambda self,*a,**kw:"raise RuntimeError('worker failed')")
    with pytest.raises(RuntimeError,match='root-local journal retained') as error:
        jumphost._guard(LocalTransport(),'lab','read',{'secret':'private-marker'})
    assert 'private-marker' not in str(error.value)
