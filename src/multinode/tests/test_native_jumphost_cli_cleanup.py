"""Census persisted CLI evidence before any dependent teardown, no real Docker."""
from copy import deepcopy

import pytest

from tests.test_native_jumphost_stage import stage, inventory, configure, native
from tests.test_jumphost_cli_assets import assets, complete
from tests.test_jumphost_cli_execution import World
from tests.test_native_jumphost_stage_recovery_diagnostic import reopen
import native_jumphost_stage as module


@pytest.fixture
def qualified_cli(stage,assets,monkeypatch):
    value,docker,control,relay=stage;value.prepare()
    _,provider,container=assets
    provider.owner['container_id']=control['record']['container_id']
    nonce=value.cli_slot('cli-before-connect')
    command,marker=module.console_command(nonce)
    asset=module.Assets(value.root/'cli-before-connect-assets.json',provider,nonce,'connect','R1',
                        command,marker)
    profile=asset.prepare()
    world=World();world.owner=deepcopy(provider.owner);world.nonce=nonce
    world.config={'User':'labuser','Cmd':['python3','-I','-c',module.build(profile),nonce],
                  **{key:False for key in ('AttachStdin','AttachStdout','AttachStderr','Tty','Privileged')}}
    request=world.request
    def run(method,path,payload=None):
        result=request(method,path,payload)
        if method=='POST' and path.endswith('/start'):complete(asset,container)
        return result
    world.request=run
    actor=module.Execution(value.root/'cli-before-connect-exec.json',world,world.owner,world.config,nonce,
                           asset.observe,asset.result)
    actor.run()
    host_api=module.Docker()
    class ReadonlyAPI:
        def request(self,method,path,payload=None):
            assert method=='GET','cleanup sent a remote mutation'
            return world.request(method,path,payload)
        def inspect(self,cid):return host_api.inspect(cid)
    monkeypatch.setattr(module,'Docker',ReadonlyAPI)
    monkeypatch.setattr(module,'JumphostWorker',lambda *args,**kwargs:object())
    monkeypatch.setattr(module,'JumphostRoot',lambda worker:provider)
    return value,docker,control,relay,world,asset


def test_reopened_preflight_is_readonly_and_cleanup_retries_without_new_clients(qualified_cli):
    value,docker,control,relay,world,asset=qualified_cli
    current=reopen(value);current.prepare()
    before={p:p.read_bytes() for p in value.root.rglob('*') if p.is_file()}
    calls=deepcopy(docker.calls)
    proof=current.preflight_cli()
    assert [r['id'] for r in proof]==['d'*64]
    assert all(p.read_bytes()==raw for p,raw in before.items())
    assert docker.calls==calls and len(world.calls)==2
    result=current.cleanup()
    assert result['verified'] and result['cli_exec_ids']==['d'*64]
    calls=deepcopy(docker.calls)
    assert current.cleanup()['verified'] and docker.calls==calls and len(world.calls)==2


@pytest.mark.parametrize('failure',['running','capture-missing','asset-missing','exec-missing',
                                    'all-missing','owner','command','nonce','changed-result'])
def test_conflicting_or_partial_cli_proofs_preserve_all_dependencies(qualified_cli,failure):
    value,docker,control,relay,world,asset=qualified_cli
    path=value.root/'cli-before-connect-exec.json'
    if failure=='running':world.exec.update(Running=True,Pid=42,ExitCode=None)
    elif failure=='capture-missing':asset.path.with_suffix('.output.json').unlink()
    elif failure=='asset-missing':asset.path.unlink()
    elif failure=='exec-missing':path.unlink()
    elif failure=='all-missing':
        for file in value.root.glob('cli-*'):file.unlink()
    elif failure=='owner':asset.root.owner['container_id']='f'*64
    elif failure=='command':world.exec['ProcessConfig']['arguments']=['replacement']
    elif failure=='nonce':
        data=module.read_intent(path,limit=1048576);data['nonce']='f'*32;module.private_json(path,data)
    else:
        data=module.read_intent(path,limit=1048576);data['result']['output_hex']='00';module.private_json(path,data)
    current=reopen(value);current.prepare();calls=deepcopy(docker.calls)
    before={p:p.read_bytes() for p in value.root.glob('cli-*')}
    with pytest.raises(RuntimeError,match='CLI journal recovery pending'):current.cleanup()
    assert docker.calls==calls and relay['record']['phase']=='active' and len(world.calls)==2
    assert all(p.read_bytes()==raw for p,raw in before.items())


def test_unbound_cli_journal_is_not_adopted(stage):
    value,docker,control,relay=stage;value.prepare()
    module.private_json(value.root/'cli-foreign-exec.json',{'phase':'completed'})
    calls=deepcopy(docker.calls)
    current=reopen(value);current.prepare()
    with pytest.raises(RuntimeError,match='CLI journal recovery pending'):current.cleanup()
    assert docker.calls==calls and relay['record']['phase']=='active'


def test_journal_changed_during_readonly_observation_blocks_all_teardown(qualified_cli,monkeypatch):
    value,docker,control,relay,world,asset=qualified_cli
    current=reopen(value);current.prepare();verify=module.Execution.verify_completed
    def change_after_observation(actor):
        result=verify(actor)
        changed=module.read_intent(actor.path,limit=1048576)
        changed['phase']='starting'
        module.private_json(actor.path,changed)
        return result
    monkeypatch.setattr(module.Execution,'verify_completed',change_after_observation)
    calls=deepcopy(docker.calls)
    with pytest.raises(RuntimeError,match='CLI journal recovery pending'):current.cleanup()
    assert docker.calls==calls and relay['record']['phase']=='active' and len(world.calls)==2
