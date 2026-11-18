"""Scoped local Git data and lock checks on temporary files; no Git execution."""
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sys
import tarfile

import pytest

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'tools'))
from image_build_binding import ImageBuildBinding, capture_binding, remote_url, REMOTES
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import TemplateError
from test_image_build_control import engine


@pytest.fixture
def binding(tmp_path):
    checkout=tmp_path/'vrnetlab';checkout.mkdir();git=checkout/'.git';git.mkdir()
    (git/'HEAD').write_text('b'*40+'\n')
    (git/'config').write_text('[remote "dnlab"]\n url = '+REMOTES[0]+'\n[branch "dnlab"]\n vscode-merge-base = opaque value\n')
    context=dict(host_id='master',boot_id='synthetic');current=deepcopy(context)
    actor=dict(container_id='1'*64,image_id='sha256:'+'2'*64,config_sha256='3'*64,artifact_sha256='4'*64,
               process_sha256='5'*64,context_sha256=fingerprint(context))
    expected=dict(state='aligned',repository=REMOTES[0],branch='dnlab',requested_commit='b'*40,current_commit='b'*40,detail=None)
    raw=json.dumps(dict(schema_version=1,repository=REMOTES[0],branch='dnlab',commit='b'*40)).encode()
    state=dict(raw=raw)
    def capture():
        return capture_binding(checkout=str(checkout),binding=expected,original_actor=actor,
            lock_sha256=hashlib.sha256(raw).hexdigest(),context=context,read_context=lambda:deepcopy(current),
            read_lock=lambda digest:state['raw'])
    def make(receipt):return ImageBuildBinding(receipt,expected_sha256=fingerprint(receipt),
        read_context=lambda:deepcopy(current),read_lock=lambda digest:state['raw'])
    return checkout,git,dict(actor=actor),state,current,capture,make


def test_original_detached_checkout_and_lock_are_readonly_and_reopenable(binding):
    checkout,git,value,_,_,capture,make=binding
    before={p.name:p.read_bytes() for p in git.iterdir()}
    receipt=capture();provider=make(receipt)
    assert provider(value)==make(receipt)(value)==receipt['profile']['binding']
    assert before=={p.name:p.read_bytes() for p in git.iterdir()}


@pytest.mark.parametrize('remote',REMOTES)
def test_only_requested_local_remote_is_parsed_other_keys_remain_opaque(binding,remote):
    _,git,value,_,_,capture,make=binding
    (git/'config').write_text('[include]\n path = /never/follow/config\n[remote "dnlab"]\n url = '+remote+
                             '\n fetch = opaque\n[branch "dnlab"]\n vscode-merge-base = other opaque value\n')
    receipt=capture();assert make(receipt)(value)==receipt['profile']['binding']
    assert receipt['evidence']['remote']==remote


@pytest.mark.parametrize('packed',[False,True])
def test_original_symbolic_branch_supports_loose_or_packed_ref(binding,packed):
    _,git,value,_,_,capture,make=binding
    (git/'HEAD').write_text('ref: refs/heads/dnlab\n')
    if packed:(git/'packed-refs').write_text('# pack-refs\n'+'b'*40+' refs/heads/dnlab\n')
    else:
        (git/'refs'/'heads').mkdir(parents=True)
        (git/'refs'/'heads'/'dnlab').write_text('b'*40+'\n')
    receipt=capture();assert make(receipt)(value)==receipt['profile']['binding']


@pytest.mark.parametrize('fault',['head','config','lock','context','directory'])
def test_changed_binding_preserves_original_receipt_without_adoption(binding,fault):
    checkout,git,value,state,current,capture,make=binding;receipt=capture();original=deepcopy(receipt)
    if fault=='head':(git/'HEAD').write_text('c'*40+'\n')
    elif fault=='config':(git/'config').write_text('[remote "dnlab"]\n url = https://example.invalid/other.git\n')
    elif fault=='lock':state['raw']=state['raw']+b'\n'
    elif fault=='context':current['boot_id']='other'
    else:
        git.rename(checkout/'old-git');git.mkdir()
        for p in (checkout/'old-git').iterdir():(git/p.name).write_bytes(p.read_bytes())
    with pytest.raises((TemplateError,OSError)):make(receipt)(value)
    assert receipt==original


def test_config_symlink_is_refused_without_following(binding):
    _,git,_,_,_,capture,_=binding
    original=git/'saved';(git/'config').rename(original);(git/'config').symlink_to(original)
    with pytest.raises(TemplateError,match='regular job ledger'):capture()


@pytest.mark.parametrize('raw',[b'[remote "dnlab"]\nurl = x\n',
    ('[remote "dnlab"]\nurl = '+REMOTES[0]+'\nurl = '+REMOTES[0]+'\n').encode()])
def test_missing_qualified_or_duplicate_remote_is_refused(raw):
    with pytest.raises(TemplateError,match='local dnlab remote'):remote_url(raw)


@pytest.mark.parametrize('fault',[None,'symlink','wrong_hash','extra'])
def test_runtime_lock_archive_is_read_without_extraction(engine,fault):
    adapter,state=engine;raw=b'{"schema_version":1}'
    output=io.BytesIO()
    with tarfile.open(fileobj=output,mode='w:') as archive:
        item=tarfile.TarInfo('vrnetlab.lock.json');item.mode=0o644
        if fault=='symlink':item.type=tarfile.SYMTYPE;item.linkname='/never/follow/lock'
        else:item.size=len(raw)
        archive.addfile(item,None if fault=='symlink' else io.BytesIO(raw))
        if fault=='extra':archive.addfile(tarfile.TarInfo('unexpected'))
    state['body']=output.getvalue();digest=hashlib.sha256(raw).hexdigest()
    if fault=='wrong_hash':digest='0'*64
    if fault:
        with pytest.raises(TemplateError):adapter.lock_asset(digest)
    else:assert adapter.lock_asset(digest)==raw
    assert state['requests'][0][0]=='GET' and '/archive?' in state['requests'][0][1]
    assert state['closed']==1
