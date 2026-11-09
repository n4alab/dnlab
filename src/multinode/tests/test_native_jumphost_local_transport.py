"""Exercise the stage's actual local adapter instead of a fake runtime client."""
from pathlib import Path
import sys
from types import SimpleNamespace

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'runtime/tools'))
from native_jumphost_stage import LocalClient
import management_barrier_smoke as transport


@pytest.mark.parametrize('payload', [None, '{"original":"request"}'])
def test_runtime_commands_use_checkout_module_and_original_stdin(monkeypatch, payload):
    calls = []
    host = SimpleNamespace(run_input=lambda *a, **k: pytest.fail('wrong helper transport'))

    def execute(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout='{"qualified":true}', stderr='')

    monkeypatch.setattr(transport.subprocess, 'run', execute)
    client = LocalClient(host)
    command = "dnlab-runtime --socket '/private/path with spaces/runtime.sock' capabilities"
    result = client.run(command) if payload is None else client.run_input(command, payload)
    argv, kwargs = calls[0]
    assert result == '{"qualified":true}' and len(calls) == 1
    assert argv == [sys.executable, '-m', 'dnlab_runtime.cli', '--socket',
                    '/private/path with spaces/runtime.sock', 'capabilities']
    assert kwargs['input'] == payload and kwargs['timeout'] == 20
    assert kwargs['env']['PYTHONPATH'] == str(transport.SOURCE)


def test_helper_commands_keep_diagnostic_transport_and_timeout():
    calls = []
    host = SimpleNamespace(run_input=lambda *a, **k: calls.append((a, k)) or 'helper')
    client = LocalClient(host)
    assert client.run_input('python3 -I -c guard', 'original', timeout=91) == 'helper'
    assert calls == [(('python3 -I -c guard', 'original'), {'timeout': 91})]


def test_actual_checkout_cli_runs_without_installed_binary():
    host = SimpleNamespace(run_input=lambda *a, **k: pytest.fail('wrong helper transport'))
    output = LocalClient(host).run('dnlab-runtime --help')
    assert 'usage:' in output and '--socket' in output
