import importlib
from pathlib import Path

import pytest


@pytest.fixture
def fixture(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]/'tools'))
    return importlib.import_module('ssh_loopback_fixture')


def test_only_exact_runtime_prefix_and_supported_commands_are_executable(fixture):
    prefix=['docker','exec','-i','owned-runtime','dnlab-runtime','--socket','/tmp/fixture.sock']
    import shlex
    for suffix in (['inspect','lab','node'],['capabilities'],['plan'],['submit'],['cancel-request'],['request-status','lab','node','request'],['status','a'*32],['reconcile','a'*32,'--force']):
        assert fixture.allowed(shlex.join(prefix+suffix),prefix)==prefix+suffix
    for command in (shlex.join(prefix+['inspect','../lab','node']),shlex.join(prefix+['inspect','lab','node','extra']),'sh -c id',shlex.join(prefix+['submit'])+'; touch /tmp/forbidden',
                    shlex.join(prefix+['cancel','bad-id']),shlex.join(prefix+['status','a'*32,'--force']),
                    shlex.join(['docker','exec','-i','foreign-runtime',*prefix[4:],'capabilities'])):
        assert fixture.allowed(command,prefix) is None
