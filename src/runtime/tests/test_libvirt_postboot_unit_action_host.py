"""Host action routing: real temporary journal/bindings, simulated unit actions."""
from copy import deepcopy
import hashlib
import json
from pathlib import Path

import pytest

from tools import libvirt_postboot_unit_action_host as entry
from tools import libvirt_postboot_unit_prepare_host as prepare_entry
from tools.libvirt_postboot_unit_revision import PostBootUnitRevision
from test_libvirt_postboot_unit_prepare_host import host_recipe
from test_libvirt_postboot_unit_prepare import unit_prepare,directories,wiring,boot_parent,installed_packages,install,request_profile


@pytest.fixture
def action_recipe(host_recipe,monkeypatch):
    recipe,prepared_output,parent,files,commands,_=host_recipe
    assert prepare_entry.run(recipe)==0
    reference=json.loads((prepared_output/'unit-reference.json').read_text())
    (recipe/'unit-reference.json').write_text(json.dumps(reference))
    monkeypatch.setattr(entry,'OUTPUT_PARENT',prepare_entry.OUTPUT_PARENT)
    actions=[]
    def apply(self):actions.append(('apply',deepcopy(self.reference)))
    def recover(self):actions.append(('recover',deepcopy(self.reference)))
    def effective(self):
        source=deepcopy(self.view.read())
        source['configuration_revision']={'operation_id':self.reference['id']}
        return source
    monkeypatch.setattr(PostBootUnitRevision,'apply_original',apply)
    monkeypatch.setattr(PostBootUnitRevision,'recover_original',recover)
    monkeypatch.setattr(PostBootUnitRevision,'effective',effective)
    def freeze():
        receipt=json.loads((recipe/'receipt.json').read_text())
        receipt['entry_sha256']=hashlib.sha256(Path(entry.__file__).read_bytes()).hexdigest()
        receipt['input_sha256']={name:hashlib.sha256((recipe/name).read_bytes()).hexdigest() for name in entry.INPUTS}
        (recipe/'receipt.json').write_text(json.dumps(receipt))
    freeze();commands.clear()
    output=entry.OUTPUT_PARENT/'libvirt-current-unit-apply-999999999999'
    return recipe,output,parent,files,commands,actions,freeze,reference


def test_explicit_exclusive_action_flags_before_access(monkeypatch,tmp_path):
    original_run=entry.run
    monkeypatch.setattr(entry,'run',lambda *a,**kw:pytest.fail('action without explicit flag'))
    for flags in ([],['--apply-host','--recover-host']):
        with pytest.raises(SystemExit) as error:entry.main(['--recipe',str(tmp_path),*flags])
        assert error.value.code==2
    monkeypatch.setattr(entry,'run',original_run)
    with pytest.raises(ValueError,match='explicit unit action'):entry.run(tmp_path,action='prepare')


def test_apply_and_explicit_replay_keep_original_reference(action_recipe):
    recipe,output,parent,files,commands,actions,_,reference=action_recipe;calls=list(files.calls)
    assert entry.run(recipe,action='apply')==0
    saved=(output/'effective.json').read_bytes()
    assert entry.run(recipe,action='apply',resume_output=output)==0
    assert (output/'effective.json').read_bytes()==saved
    assert actions==[('apply',reference),('apply',reference)] and len(commands)==2
    assert files.calls==calls and list(parent.iterdir())==[]
    assert json.loads(saved)['daemon_ready'] is False


def test_lost_response_never_recovers_implicitly(action_recipe,monkeypatch):
    recipe,output,parent,files,_,actions,_,reference=action_recipe;calls=list(files.calls)
    def lost(self):actions.append(('apply',deepcopy(self.reference)));raise OSError('synthetic lost unit action response')
    monkeypatch.setattr(PostBootUnitRevision,'apply_original',lost)
    assert entry.run(recipe,action='apply')==1
    assert actions==[('apply',reference)] and not (output/'effective.json').exists()
    result=json.loads(next(output.glob('result-*.json')).read_text())
    assert result['error']['message']=='synthetic lost unit action response'
    assert entry.run(recipe,action='recover')==0
    recovered=output.with_name(output.name.replace('-apply-','-recover-'))
    assert (recovered/'effective.json').exists() and actions==[('apply',reference),('recover',reference)]
    assert files.calls==calls and list(parent.iterdir())==[]


def test_foreign_original_revision_rejected_before_action(action_recipe):
    recipe,output,parent,files,_,actions,freeze,_=action_recipe;calls=list(files.calls)
    reference=json.loads((recipe/'unit-reference.json').read_text());reference['nonce']='0'*32
    (recipe/'unit-reference.json').write_text(json.dumps(reference));freeze()
    assert entry.run(recipe,action='apply')==1
    assert actions==[] and files.calls==calls and list(parent.iterdir())==[]
    assert not (output/'effective.json').exists()


def test_context_refusal_saved_before_query_or_action(action_recipe,monkeypatch):
    from tools import libvirt_configuration_prepare
    recipe,output,parent,files,commands,actions,_,_=action_recipe;calls=list(files.calls)
    monkeypatch.setattr(libvirt_configuration_prepare,'context',lambda value:{'foreign':'context'})
    assert entry.run(recipe,action='apply')==1
    assert commands==[] and actions==[] and files.calls==calls and list(parent.iterdir())==[]
    result=json.loads(next(output.glob('result-*.json')).read_text())
    assert result['contexts'][0]['observed']=={'foreign':'context'}
