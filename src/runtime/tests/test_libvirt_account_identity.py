"""Temporary account files and injected NSS only; never inspect host accounts."""
from copy import deepcopy
import json

import pytest

from dnlab_runtime.journal import Journal
from dnlab_runtime.libvirt_account_identity import LocalAccountIdentity
from dnlab_runtime.libvirt_provisioning import InstallationAccounts,account_marker
from dnlab_runtime.manifest import Conflict


@pytest.fixture
def identity(tmp_path):
    root=tmp_path/'root';(root/'etc').mkdir(parents=True)
    def write(name,data):
        path=root/'etc'/name;path.write_text(data);path.chmod(0o640 if name=='shadow' else 0o644)
        return path
    write('passwd','root:x:0:0:root:/root:/bin/sh\n')
    write('group','root:x:0:\n')
    request=dict(intent_id='install',nonce='a'*32,spec_sha256='b'*64,kind='account',expected=dict(
        name='dnlab-libvirt',uid=1001,gid=1002,home='/var/lib/dnlab-libvirt',shell='/usr/sbin/nologin',locked=True,
        comment=account_marker('install','a'*32)))
    state=dict(overrides={},queries=[])
    def nss(database,key):
        state['queries'].append((database,key))
        if (database,key) in state['overrides']:return deepcopy(state['overrides'][database,key])
        rows=[line.split(':') for line in (root/'etc'/database).read_text().splitlines()]
        matches=[row for row in rows if (int(row[2])==key if type(key) is int else row[0]==key)]
        if not matches:return None
        row=matches[0];value=dict(name=row[0],gid=int(row[3] if database=='passwd' else row[2]))
        if database=='passwd':value['uid']=int(row[2])
        return value
    def create():
        e=request['expected']
        write('passwd','root:x:0:0:root:/root:/bin/sh\n'+f"{e['name']}:x:{e['uid']}:{e['gid']}:{e['comment']}:{e['home']}:{e['shell']}\n")
        write('group','root:x:0:\ndnlab-libvirt:x:1002:\n')
        write('shadow','root:NEVER-EMIT-SECRET:1:0:99999:7:::\ndnlab-libvirt:!:1:0:99999:7:::\n')
    return LocalAccountIdentity(root,nss_query=nss),request,root,write,create,state


def test_absent_identity_does_not_read_shadow(identity,monkeypatch):
    reader,request,root,_,_,state=identity;read=reader._read;paths=[]
    def recording(fd,path):paths.append(path);return read(fd,path)
    monkeypatch.setattr(reader,'_read',recording)
    assert reader(request) is None and 'etc/shadow' not in paths and not (root/'etc/shadow').exists()
    assert state['queries'].count(('passwd','root'))==2
    assert state['queries'].count(('passwd',1001))==2


def test_matching_account_returns_only_expected_identity_and_preserves_files(identity):
    reader,request,root,_,create,_=identity;create()
    before={p.name:p.read_bytes() for p in (root/'etc').iterdir()}
    result=reader(request)
    assert result==request['expected'] and 'NEVER-EMIT-SECRET' not in json.dumps(result)
    assert before=={p.name:p.read_bytes() for p in (root/'etc').iterdir()}


def test_matching_group_does_not_open_shadow(identity,monkeypatch):
    reader,request,_,write,_,_=identity
    request.update(kind='group',expected=dict(name='dnlab-libvirt',gid=1002))
    write('group','root:x:0:\ndnlab-libvirt:x:1002:\n')
    read=reader._read
    def no_shadow(fd,path):assert path!='etc/shadow';return read(fd,path)
    monkeypatch.setattr(reader,'_read',no_shadow)
    assert reader(request)==request['expected']


@pytest.mark.parametrize('database,key,value',[
    ('passwd','dnlab-libvirt',dict(name='dnlab-libvirt',uid=1001,gid=1002)),
    ('passwd',1001,dict(name='foreign',uid=1001,gid=1002)),
    ('passwd','root',None),
])
def test_nss_only_collision_or_missing_control_refuses_without_shadow(identity,database,key,value):
    reader,request,root,_,_,state=identity
    state['overrides'][database,key]=value
    with pytest.raises(Conflict):reader(request)
    assert not (root/'etc/shadow').exists()


@pytest.mark.parametrize('fault',['uid','gid','marker','home','shell','password_field','duplicate_uid','duplicate_name'])
def test_local_account_conflicts_are_refused_before_shadow(identity,fault,monkeypatch):
    reader,request,root,write,create,_=identity;create();path=root/'etc/passwd';data=path.read_text()
    if fault=='uid':data=data.replace(':1001:1002:',':2001:1002:')
    elif fault=='gid':data=data.replace(':1001:1002:',':1001:2002:')
    elif fault=='marker':data=data.replace(request['expected']['comment'],'foreign-marker')
    elif fault=='home':data=data.replace('/var/lib/dnlab-libvirt','/foreign')
    elif fault=='shell':data=data.replace('/usr/sbin/nologin','/bin/sh')
    elif fault=='password_field':data=data.replace('dnlab-libvirt:x:','dnlab-libvirt:foreign:')
    elif fault=='duplicate_uid':data+='foreign:x:1001:1002::/foreign:/bin/sh\n'
    else:data+=data.splitlines()[1]+'\n'
    write('passwd',data)
    read=reader._read
    def no_shadow(fd,name):assert name!='etc/shadow';return read(fd,name)
    monkeypatch.setattr(reader,'_read',no_shadow)
    with pytest.raises(Conflict):reader(request)


@pytest.mark.parametrize('fault',['unlocked','different_lock','duplicate','malformed','missing','symlink','writable'])
def test_shadow_lock_conflicts_never_return_a_qualified_identity(identity,fault):
    reader,request,root,write,create,_=identity;create();path=root/'etc/shadow'
    if fault=='unlocked':write('shadow',path.read_text().replace('dnlab-libvirt:!:','dnlab-libvirt:HASH:'))
    elif fault=='different_lock':write('shadow',path.read_text().replace('dnlab-libvirt:!:','dnlab-libvirt:!!:'))
    elif fault=='duplicate':write('shadow',path.read_text()+path.read_text().splitlines()[1]+'\n')
    elif fault=='malformed':write('shadow','dnlab-libvirt:!\n')
    elif fault=='missing':path.unlink()
    elif fault=='symlink':
        original=root/'original-shadow';path.rename(original);path.symlink_to(original)
    else:path.chmod(0o660)
    with pytest.raises((Conflict,OSError)):reader(request)


def test_nss_target_disagreement_refuses_before_shadow(identity,monkeypatch):
    reader,request,_,_,create,state=identity;create()
    state['overrides']['passwd',1001]=dict(name='foreign',uid=1001,gid=1002)
    read=reader._read
    def no_shadow(fd,path):assert path!='etc/shadow';return read(fd,path)
    monkeypatch.setattr(reader,'_read',no_shadow)
    with pytest.raises(Conflict,match='NSS target'):reader(request)


def test_change_between_observations_preserves_unqualified_state(identity,monkeypatch):
    reader,request,root,write,create,_=identity;create();observe=reader._observe;calls=[]
    def changed(fd,value):
        result=observe(fd,value)
        if not calls:
            calls.append(True);write('passwd',(root/'etc/passwd').read_text()+'other:x:2000:2000::/x:/bin/sh\n')
        return result
    monkeypatch.setattr(reader,'_observe',changed)
    with pytest.raises(Conflict,match='changed during'):reader(request)


def test_matching_rows_do_not_authorize_adoption_without_original_birth(identity,tmp_path):
    reader,request,_,_,create,_=identity;create()
    class Helper:
        inspect=staticmethod(reader)
    journal=Journal(tmp_path/'journal')
    try:
        accounts=InstallationAccounts(journal,Helper())
        # Use the exact request generated by the installation contract.
        spec=dict(kind='account',name='dnlab-libvirt',uid=1001,gid=1002,home='/var/lib/dnlab-libvirt',interactive_login=False)
        with pytest.raises(Conflict,match='already occupied'):
            accounts.observe(dict(spec=spec,nonce=request['nonce']),'install')
        assert journal.db.execute('SELECT count(*) FROM libvirt_install_account_births').fetchone()[0]==0
    finally:journal.close()
