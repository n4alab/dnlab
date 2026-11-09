"""DNS embeds the shared worker too; transport must remain bounded in argv."""
import json
import os
import shlex

from dnlab_multinode.services import dns


def test_dns_worker_source_delivery_uses_bounded_process_arguments():
    captured={}
    class Transport:
        def run_input(self,command,payload,timeout):
            captured.update(command=command,payload=payload,timeout=timeout)
            return json.dumps({'phase':'absent'})
    assert dns._guard(Transport(),'transport-diagnostic','read')=={'phase':'absent'}
    sizes=[len(value.encode())+1 for value in shlex.split(captured['command'])]
    limit=os.sysconf('SC_PAGESIZE')*32
    assert max(sizes)<limit, f'DNS worker argument {max(sizes)} bytes exceeds {limit}-byte limit'


class LocalTransport:
    def run_input(self,command,payload,timeout):
        import subprocess
        result=subprocess.run(shlex.split(command),input=payload,text=True,capture_output=True,timeout=timeout,check=True)
        return result.stdout


def test_full_composed_dns_source_executes_with_original_request_via_stdin(monkeypatch):
    from pathlib import Path
    original=Path.read_text
    def source(path,*args,**kwargs):
        value=original(path,*args,**kwargs)
        if path.name=='dns_host.py':
            value=value.replace("if __name__ == '__main__': main()", "if __name__ == '__main__': print(canonical({'phase':'observed','request':json.load(sys.stdin)}))")
        return value
    monkeypatch.setattr(Path,'read_text',source)
    value={'generation':'a'*32,'marker':"privato-à ' $() `literal`\n"}
    hosts='192.0.2.11 fixture.test\n# unicode-à\n'
    result=dns._guard(LocalTransport(),'lab-à','read',value,hosts)
    assert result['request']=={'lab':'lab-à','action':'read','config':value,'content':hosts,'directory':dns.PATHS.dns_journal_dir}


def test_config_hosts_and_source_remain_out_of_command_arguments():
    captured={}
    class Transport:
        def run_input(self,command,payload,timeout):
            captured.update(command=command,payload=json.loads(payload),timeout=timeout)
            return '{"phase":"absent"}'
    dns._guard(Transport(),'lab','read',{'password':'private-marker'},'192.0.2.11 fixture-private.test\n')
    assert 'private-marker' not in captured['command'] and 'fixture-private.test' not in captured['command']
    assert len(captured['payload']['source'].encode())>os.sysconf('SC_PAGESIZE')*32
    assert captured['payload']['request']['config']['password']=='private-marker'
    assert captured['timeout']==60


def test_payload_python_text_stays_data(monkeypatch):
    from pathlib import Path
    original=Path.read_text
    def source(path,*args,**kwargs):
        if path.name=='dns_host.py':
            return "import json,sys\nprint(json.dumps({'phase':'observed','request':json.load(sys.stdin)}))\n"
        return original(path,*args,**kwargs)
    monkeypatch.setattr(Path,'read_text',source)
    value={"text":"'); raise RuntimeError('injected'); #\n"}
    assert dns._guard(LocalTransport(),'lab','read',value)['request']['config']==value


def test_worker_errors_keep_existing_public_error_without_exposing_request(monkeypatch):
    from pathlib import Path
    import pytest
    original=Path.read_text
    monkeypatch.setattr(Path,'read_text',lambda path,*a,**kw:"raise RuntimeError('worker failed')" if path.name=='dns_host.py' else original(path,*a,**kw))
    with pytest.raises(RuntimeError,match='journal retained') as error:
        dns._guard(LocalTransport(),'lab','read',{'password':'private-marker'})
    assert 'private-marker' not in str(error.value)
