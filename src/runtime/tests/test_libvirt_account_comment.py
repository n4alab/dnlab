"""Generated account comments must fit one passwd GECOS field; no account command."""
from dnlab_runtime.libvirt_install import targets
from dnlab_runtime.libvirt_service_profile import render_profile
from dnlab_runtime.libvirt_provisioning import account_request
from test_libvirt_service_profile import request_profile


def test_generated_account_comment_does_not_contain_passwd_delimiters(request_profile):
    spec=next(item for item in targets(render_profile(**request_profile)) if item['kind']=='account')
    request=account_request(dict(spec=spec,nonce='a'*32),'install-1')
    comment=request['expected']['comment']
    assert not any(char in comment for char in (':','\n','\r'))


def test_marker_is_versioned_stable_and_binds_both_original_identities():
    import re
    from dnlab_runtime.libvirt_provisioning import account_marker
    from dnlab_runtime.manifest import fingerprint
    marker=account_marker('install-1','a'*32)
    assert marker=='dnlab-v1-'+fingerprint(dict(version=1,intent_id='install-1',nonce='a'*32))
    assert re.fullmatch(r'dnlab-v1-[0-9a-f]{64}',marker)
    assert marker==account_marker('install-1','a'*32)
    assert len({marker,account_marker('install-2','a'*32),account_marker('install-1','b'*32)})==3


def test_raw_delimiters_in_identity_cannot_enter_the_comment():
    from dnlab_runtime.libvirt_provisioning import account_marker
    assert not any(c in account_marker('intent:with\nseparator','a'*32) for c in ':\n\r')


import pytest


@pytest.mark.parametrize('phase',['create_requested','created'])
def test_incompatible_saved_request_is_refused_without_rewrite(request_profile,tmp_path,phase):
    from copy import deepcopy
    from dnlab_runtime.journal import Journal
    from dnlab_runtime.libvirt_provisioning import InstallationAccounts,ProvisioningWindow
    from dnlab_runtime.manifest import Conflict,canonical,fingerprint
    spec=next(item for item in targets(render_profile(**request_profile)) if item['kind']=='account')
    item=dict(spec=spec,nonce='a'*32)
    original=account_request(item,'install-1')
    original['expected']['comment']='dnlab:install-1:'+item['nonce']
    saved=dict(request=original,phase=phase,window_sha256='b'*64,completion=None)
    class Helper:
        def inspect(self,*args):pytest.fail('old request must fail before account inspection')
        def create(self,*args):pytest.fail('old request must not create')
        def completion(self,*args):pytest.fail('old request must not be adopted')
    journal=Journal(tmp_path/'journal')
    try:
        adapter=InstallationAccounts(journal,Helper())
        journal.db.execute('INSERT INTO libvirt_install_account_births VALUES(?,?,?,?)',
            ('install-1',item['nonce'],canonical(saved),fingerprint(saved)))
        receipt=dict(operation_id='install-1',context={'boot':'synthetic'},targets=[spec['key']],nonce='f'*32)
        window=ProvisioningWindow(receipt,lambda:deepcopy(receipt))
        before=tuple(journal.db.execute('SELECT * FROM libvirt_install_account_births').fetchone())
        changes=journal.db.total_changes
        for action in (lambda:adapter.observe(item,'install-1'),
                       lambda:adapter.create(item,'install-1',window=window),
                       lambda:adapter.recover(item,'install-1',window=window)):
            with pytest.raises(Conflict,match='original account provisioning intent differs'):action()
        assert journal.db.total_changes==changes
        assert tuple(journal.db.execute('SELECT * FROM libvirt_install_account_births').fetchone())==before
    finally:journal.close()
