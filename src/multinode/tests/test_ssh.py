from dnlab_multinode.services.ssh import SSHClient


class RecordingSSHClient(SSHClient):
    def __init__(self):
        super().__init__("127.0.0.1", "root", "/tmp/key", name="test")
        self.commands = []

    def run(self, command: str, timeout: int = 30, check: bool = True) -> str:
        self.commands.append((command, timeout, check))
        return ""


def test_existing_containerlab_commands_quote_topology_paths():
    client = RecordingSSHClient()
    topology = "/tmp/lab with spaces/demo.clab.yml"

    client.deploy_clab(topology, reconfigure=True)
    client.destroy_clab(topology)

    commands = [command for command, _timeout, _check in client.commands]
    quoted_topology = "'/tmp/lab with spaces/demo.clab.yml'"
    assert commands == [
        f"containerlab deploy -t {quoted_topology} --reconfigure",
        f"containerlab destroy -t {quoted_topology} --cleanup --keep-mgmt-net",
    ]


def test_cancel_active_commands_closes_tracked_channels():
    client = SSHClient("127.0.0.1", "root", "/tmp/key", name="test")

    class Channel:
        def __init__(self):
            self.closed = False

        def close(self):
            self.closed = True

    channel = Channel()
    client._track_channel(channel)

    client.cancel_active_commands()

    assert channel.closed is True


def stdin_client(*,rc=0,write_error=None):
    from types import SimpleNamespace
    client=SSHClient('127.0.0.1','root','/tmp/key',name='fixture');commands=[];writes=[]
    class Channel:
        out=[b'{"ok":true}'];err=[b'fixture-sensitive-value'];closed=False
        def recv_ready(self):return bool(self.out)
        def recv_stderr_ready(self):return bool(self.err)
        def recv(self,size):return self.out.pop(0)
        def recv_stderr(self,size):return self.err.pop(0)
        def exit_status_ready(self):return True
        def recv_exit_status(self):
            assert not self.out and not self.err
            return rc
        def shutdown_write(self):writes.append('EOF')
        def close(self):self.closed=True
    channel=Channel()
    class Input:
        def write(self,data):
            assert channel in client._active_channels
            if write_error:raise write_error
            writes.append(data)
        def flush(self):pass
    def execute(command,timeout):
        commands.append(command);return Input(),SimpleNamespace(channel=channel),SimpleNamespace()
    client._client=SimpleNamespace(exec_command=execute)
    return client,channel,commands,writes


def test_runtime_stdin_is_not_in_command_and_both_streams_are_drained(caplog):
    client,channel,commands,writes=stdin_client()
    assert client.run_input('dnlab-runtime submit','fixture-sensitive-value')=='{"ok":true}'
    assert commands==['dnlab-runtime submit'] and writes==[b'fixture-sensitive-value','EOF']
    assert channel.closed and not client._active_channels
    assert 'fixture-sensitive-value' not in caplog.text


def test_runtime_failure_redacts_stderr_and_releases_channel(caplog):
    import pytest
    from dnlab_multinode.services.ssh import SSHError
    client,channel,commands,_=stdin_client(rc=1)
    with pytest.raises(SSHError) as result:client.run_input('dnlab-runtime submit','fixture-sensitive-value')
    assert 'fixture-sensitive-value' not in str(result.value) and 'fixture-sensitive-value' not in caplog.text
    assert result.value.returncode==1 and channel.closed and not client._active_channels


def test_runtime_input_failure_is_redacted_and_untracked():
    import pytest
    from dnlab_multinode.services.ssh import SSHError
    client,channel,_,_=stdin_client(write_error=ValueError('fixture-sensitive-value'))
    with pytest.raises(SSHError) as result:client.run_input('dnlab-runtime submit','fixture-sensitive-value')
    assert 'fixture-sensitive-value' not in str(result.value) and channel.closed and not client._active_channels
