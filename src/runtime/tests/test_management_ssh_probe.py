"""SSH fixture owns a key, pins the helper and closes every client."""
from contextlib import contextmanager
import importlib.util
import json
from pathlib import Path
import sys
from unittest.mock import Mock
import pytest

TOOLS=Path(__file__).resolve().parents[1]/'tools'
sys.path[:0]=[str(TOOLS),str(TOOLS.parents[1]/'multinode')]
import management_ssh_probe as module


def test_key_is_unique_private_and_parses_without_subprocess(tmp_path):
    key=module.prepare_key(tmp_path)
    assert Path(key['path']).stat().st_mode&0o777==0o600
    parsed=module.paramiko.Ed25519Key.from_private_key_file(key['path'])
    assert key['public']==parsed.get_name()+' '+parsed.get_base64()
    with pytest.raises(FileExistsError):module.prepare_key(tmp_path)


@pytest.mark.parametrize('failure',[None,'authentication','output','thread'])
def test_authentication_pins_key_and_closes_client_on_all_outcomes(tmp_path,failure):
    key=module.prepare_key(tmp_path);host_key=module.paramiko.Ed25519Key.from_private_key_file(key['path'])
    client=Mock();transport=client.get_transport.return_value
    transport.is_authenticated.return_value=True;transport.is_alive.return_value=failure=='thread'
    transport.get_remote_server_key.return_value=host_key
    stdin,stdout,stderr=Mock(),Mock(),Mock();client.exec_command.return_value=(stdin,stdout,stderr)
    stdout.read.return_value=b'wrong\n' if failure=='output' else b'labuser\n';stderr.read.return_value=b''
    stdout.channel.exit_status_ready.return_value=True;stdout.channel.recv_exit_status.return_value=0
    if failure=='authentication':client.connect.side_effect=module.paramiko.AuthenticationException('denied')
    call=lambda:module.authenticate({'bind_ip':'127.0.0.1','port':32001},key['path'],host_key,factory=lambda:client)
    if failure:
        with pytest.raises(Exception):call()
    else:assert call()['authenticated_user']=='labuser'
    client.get_host_keys.return_value.add.assert_called_once_with('[127.0.0.1]:32001','ssh-ed25519',host_key)
    assert isinstance(client.set_missing_host_key_policy.call_args.args[0],module.paramiko.RejectPolicy)
    kwargs=client.connect.call_args.kwargs
    assert kwargs['allow_agent'] is kwargs['look_for_keys'] is False and kwargs['password'] is None
    assert kwargs['timeout']==kwargs['banner_timeout']==kwargs['auth_timeout']==5
    client.close.assert_called_once();transport.join.assert_called_once_with(timeout=3)


@pytest.mark.parametrize('change',[None,'before','after'])
def test_probe_persists_intent_and_rejects_generation_changes(tmp_path,monkeypatch,change):
    worker=Mock();config={'nonce':'original-config'};record={'phase':'active','config':config}
    worker.read.return_value=record
    @contextmanager
    def namespace(r):yield 11
    worker.namespace=namespace
    host_key=Mock();host_key.asbytes.return_value=b'original-server-key'
    observations=[{'container_id':'original','pid':1} for _ in range(3)]
    if change:observations[1 if change=='before' else 2]={'container_id':'replacement','pid':2}
    monkeypatch.setattr(module,'public_key',Mock(side_effect=[(host_key,p) for p in observations]))
    calls=[]
    def auth(*args):
        row=json.loads((tmp_path/'ssh-authentication.json').read_text())
        assert row['phase']=='connecting' and row['attempts']==1
        calls.append(args);return {'authenticated_user':'labuser'}
    call=lambda:module.probe(tmp_path,'lab',config,{'path':'private-key','fingerprint':'public-fingerprint'},worker=worker,auth=auth)
    if change:
        with pytest.raises(RuntimeError,match='proof changed'):call()
    else:assert call()['phase']=='completed'
    assert len(calls)==(0 if change=='before' else 1)
    row=json.loads((tmp_path/'ssh-authentication.json').read_text())
    assert row['phase']==('failed' if change else 'completed')
