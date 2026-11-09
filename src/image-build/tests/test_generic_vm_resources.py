"""Generic resource contract and final QEMU command against pinned vrnetlab.

The optional upstream source is verified by hash and runs without QEMU, network
or vendor images. CI without that explicit fixture skips only integration cases.
"""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shlex
import sys
import types

import pytest

RECIPE = Path(__file__).parents[1] / 'recipes/generic_vm'
PIN = '3e8578d2e946d38a3176480e80f8510bdb2ee53a'
SOURCE_SHA256 = 'a3597267e29694eb1e6c7479f01d833d83640265cc501dad180f6a1edabd83f7'
PROFILE = {'vcpu': 2, 'ram_mb': 4096, 'data_ports': 2, 'nic_model': 'virtio', 'firmware': 'bios'}
VARIABLES = ('VCPU', 'RAM', 'QEMU_SMP', 'QEMU_MEMORY')


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def launcher(monkeypatch, base):
    for name in VARIABLES + ('CLAB_INTFS', 'QEMU_ADDITIONAL_ARGS'):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setitem(sys.modules, 'vrnetlab', base)
    original = Path.read_text
    def read(path, *args, **kwargs):
        if str(path) == '/opt/generic/spec.json': return json.dumps(PROFILE)
        return original(path, *args, **kwargs)
    monkeypatch.setattr(Path, 'read_text', read)
    return load('generic_resources_launcher', RECIPE / 'launch.py')


@pytest.fixture
def unit(monkeypatch):
    class Forbidden:
        def __init__(self, *args, **kwargs): raise AssertionError('invalid input reached VM allocation')
    return launcher(monkeypatch, types.SimpleNamespace(VM=Forbidden, VR=Forbidden))


@pytest.mark.parametrize('variable', VARIABLES)
@pytest.mark.parametrize('value', ['', '0', '-1', '1.5', 'hello', '+8', ' 8', '8 ', '８', pytest.param('9' * 5000, id='oversized-integer')])
def test_invalid_present_value_fails_before_vm_constructor(unit, monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=variable): unit.GenericVM()


@pytest.mark.parametrize('variable,value', [('VCPU', '65'), ('QEMU_SMP', '65'), ('RAM', '255'),
                                          ('QEMU_MEMORY', '255'), ('RAM', '1048577'), ('QEMU_MEMORY', '1048577')])
def test_resource_bounds_fail_before_vm_constructor(unit, monkeypatch, variable, value):
    monkeypatch.setenv(variable, value)
    with pytest.raises(ValueError, match=variable): unit.GenericVM()


def test_invalid_primary_does_not_fall_back_or_partially_normalize(unit, monkeypatch):
    monkeypatch.setenv('VCPU', '8'); monkeypatch.setenv('RAM', '')
    monkeypatch.setenv('QEMU_SMP', '2'); monkeypatch.setenv('QEMU_MEMORY', '4096')
    with pytest.raises(ValueError, match='RAM'): unit.GenericVM()
    assert os.environ['QEMU_SMP'] == '2' and os.environ['QEMU_MEMORY'] == '4096'
    monkeypatch.setenv('VCPU', '')
    with pytest.raises(ValueError, match='VCPU'): unit.GenericVM()


@pytest.fixture
def pinned(monkeypatch, tmp_path):
    source = os.environ.get('DNLAB_TEST_VRNETLAB_SOURCE')
    if not source: pytest.skip('set DNLAB_TEST_VRNETLAB_SOURCE to qualify the pinned upstream VM implementation')
    raw = Path(source).read_bytes()
    assert hashlib.sha256(raw).hexdigest() == SOURCE_SHA256, 'upstream source is not the recipe pin'
    assert PIN in (RECIPE / 'Dockerfile').read_text()
    target = tmp_path / 'vrnetlab.py'; target.write_bytes(raw)
    load('generic_overlay_patch', RECIPE / 'patch_vrnetlab.py').patch(target)
    telnet = types.SimpleNamespace(Telnet=lambda *args: types.SimpleNamespace(close=lambda: None))
    monkeypatch.setitem(sys.modules, 'telnetlib', telnet)
    upstream = load('generic_resources_upstream', target)
    # Mock external I/O only: the pinned VM constructor, resource properties
    # and start()/Popen command construction execute unchanged.
    upstream.os = types.SimpleNamespace(environ=os.environ, getenv=os.getenv,
        path=types.SimpleNamespace(exists=lambda path: path == '/persist/overlay.qcow2'))
    upstream.run_command = lambda *args, **kwargs: pytest.fail('no overlay mutation permitted')
    monkeypatch.setattr(upstream.VM, 'gen_mgmt', lambda self: [])
    monkeypatch.setattr(upstream.VM, 'gen_nics', lambda self: [])
    commands = []
    def popen(command, **kwargs):
        commands.append(shlex.split(command))
        return types.SimpleNamespace(communicate=lambda **options: ('', ''))
    upstream.subprocess = types.SimpleNamespace(Popen=popen, PIPE=-1)
    return launcher(monkeypatch, upstream), commands


@pytest.mark.parametrize('env,cpu,ram,cpu_source,ram_source', [
    ({}, 2, 4096, 'SPEC.vcpu', 'SPEC.ram_mb'),
    ({'VCPU': '8', 'RAM': '16384'}, 8, 16384, 'VCPU', 'RAM'),
    ({'VCPU': '4', 'RAM': '8192'}, 4, 8192, 'VCPU', 'RAM'),
    ({'VCPU': '8'}, 8, 4096, 'VCPU', 'SPEC.ram_mb'),
    ({'RAM': '8192'}, 2, 8192, 'SPEC.vcpu', 'RAM'),
    ({'QEMU_SMP': '6', 'QEMU_MEMORY': '12288'}, 6, 12288, 'QEMU_SMP', 'QEMU_MEMORY'),
    ({'VCPU': '8', 'QEMU_MEMORY': '8192'}, 8, 8192, 'VCPU', 'QEMU_MEMORY'),
    ({'QEMU_SMP': '6', 'RAM': '8192'}, 6, 8192, 'QEMU_SMP', 'RAM'),
    ({'VCPU': '8', 'RAM': '16384', 'QEMU_SMP': '2', 'QEMU_MEMORY': '4096'}, 8, 16384, 'VCPU', 'RAM'),
    ({'VCPU': '8', 'RAM': '16384', 'QEMU_SMP': 'bad', 'QEMU_MEMORY': '4G'}, 8, 16384, 'VCPU', 'RAM'),
    ({'VCPU': '1', 'RAM': '256'}, 1, 256, 'VCPU', 'RAM'),
    ({'VCPU': '64', 'RAM': '1048576'}, 64, 1048576, 'VCPU', 'RAM'),
])
def test_final_qemu_command_uses_resolved_resources(pinned, monkeypatch, caplog, env, cpu, ram, cpu_source, ram_source):
    module, commands = pinned
    for key, value in env.items(): monkeypatch.setenv(key, value)
    monkeypatch.setenv('UNRELATED_SECRET', 'do-not-dump-environment')
    caplog.set_level('INFO')
    vm = module.GenericVM()
    assert vm.ram == ram and vm.smp == str(cpu)
    assert os.environ['QEMU_SMP'] == str(cpu) and os.environ['QEMU_MEMORY'] == str(ram)
    vm.start()
    assert len(commands) == 1
    command = commands[0]
    assert command[command.index('-smp') + 1] == str(cpu)
    assert command[command.index('-m') + 1] == str(ram)
    assert command.count('-smp') == command.count('-m') == 1
    assert 'if=ide,file=/persist/overlay.qcow2' in command
    assert f'source={cpu_source}' in caplog.text and f'source={ram_source}' in caplog.text
    assert 'do-not-dump-environment' not in caplog.text
