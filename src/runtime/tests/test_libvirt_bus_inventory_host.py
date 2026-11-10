"""Run the host wrapper only with a temporary root and synthetic context/socket."""
from copy import deepcopy
import json
import stat

import pytest

from tools import libvirt_bus_inventory_host as host
from test_libvirt_bus_prerequisites import inventory


@pytest.fixture
def recipe(tmp_path):
    folder=tmp_path/'recipe'
    host.prepare_recipe(folder,dict(nonce='1'*32,host_id='synthetic',scope='bus-library-socket-readonly-v1'))
    output=tmp_path/'reports';output.mkdir(mode=0o700)
    return folder,output


def test_full_wrapper_collects_fixture_only_and_preserves_private_output(recipe,inventory):
    folder,parent=recipe;fd,expected,_,_,_,_=inventory
    result,output=host.run(folder,root_fd=fd,read_context=lambda:deepcopy(expected),output_parent=parent)
    assert result['status']=='collected' and result['qualified'] is False
    assert stat.S_IMODE(output.stat().st_mode)==0o700
    assert all(stat.S_IMODE(path.stat().st_mode)==0o600 for path in output.iterdir())
    assert json.loads((output/'result.json').read_text())==result
    before={path.name:path.read_bytes() for path in output.iterdir()}
    with pytest.raises(FileExistsError):host.run(folder,root_fd=fd,read_context=lambda:pytest.fail('no second collection'),output_parent=parent)
    assert {path.name:path.read_bytes() for path in output.iterdir()}==before


def test_context_difference_retains_original_and_observed_diagnostics(recipe,inventory):
    folder,parent=recipe;fd,expected,_,_,_,_=inventory;calls=[]
    def context():
        calls.append(True)
        return deepcopy(expected) if len(calls)==1 else dict(expected,boot_id='changed')
    result,output=host.run(folder,root_fd=fd,read_context=context,output_parent=parent)
    assert result['status']=='failed' and 'context differs' in result['error']
    assert json.loads((output/'initial-context.json').read_text())==expected
    assert json.loads((output/'pass1-context-before.json').read_text())['matches'] is False


def test_request_tampering_refused_before_output_or_fixture_access(recipe,inventory):
    folder,parent=recipe;fd,_,_,_,_,_=inventory
    request=json.loads((folder/'request.json').read_text());request['nonce']='2'*32
    (folder/'request.json').write_text(json.dumps(request))
    with pytest.raises(ValueError,match='recipe differs'):
        host.run(folder,root_fd=fd,read_context=lambda:pytest.fail('no context read'),output_parent=parent)
    assert list(parent.iterdir())==[]


def test_changed_source_inventory_refused_before_collection(recipe,inventory,monkeypatch):
    folder,parent=recipe;fd,_,_,_,_,_=inventory
    monkeypatch.setattr(host,'inventory',lambda:{'tools/foreign.py':'0'*64})
    with pytest.raises(ValueError,match='recipe differs'):
        host.run(folder,root_fd=fd,read_context=lambda:pytest.fail('no context read'),output_parent=parent)
    assert list(parent.iterdir())==[]


def test_symlink_output_parent_not_followed(recipe,inventory,tmp_path):
    folder,parent=recipe;fd,_,_,_,_,_=inventory
    alias=tmp_path/'reports-link';alias.symlink_to(parent)
    with pytest.raises(OSError):
        host.run(folder,root_fd=fd,read_context=lambda:pytest.fail('no context read'),output_parent=alias)
    assert list(parent.iterdir())==[]


def test_native_flag_required_before_recipe_or_root_access(tmp_path):
    with pytest.raises(SystemExit) as result:host.main(['--recipe',str(tmp_path/'absent')])
    assert result.value.code==2
