"""Successor revision through real private files; host/session leaves simulated."""
from copy import deepcopy

import pytest

from dnlab_runtime.libvirt_configuration import ConfigurationRevision,UNIT
from dnlab_runtime.libvirt_configuration_adapter import ConfigurationFileAdapter
from dnlab_runtime.libvirt_configuration_retirement import ConfigurationRetirement
from dnlab_runtime.libvirt_configuration_swap import EXCHANGE,NOREPLACE
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import Conflict,fingerprint
from tools.libvirt_postboot_unit_revision import PreparedUnitFiles
from test_libvirt_configuration_adapter import configured,install,request_profile


@pytest.fixture
def successor(configured):
    old,adapter,reference,root=configured
    source=deepcopy(reference['installation']);source['context']['boot_id']='99999999-9999-4999-8999-999999999999'
    source['postboot']={'synthetic_completed_directory_lineage':True}
    agreement=dict(operation_id='retire-unit',context=deepcopy(source['context']),targets=['file:'+UNIT],nonce='4'*32)
    window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    def observe(value,current):
        assert adapter.files.observe(value['plan']['source_item'],source['id'])==value['plan']['source_item']['proof']
        assert not (root/value['staging'].lstrip('/')).exists() and not (root/value['backup'].lstrip('/')).exists()
        return dict(context=deepcopy(current['context']),current_source_sha256=fingerprint(current),
            original_unit=deepcopy(value['plan']['source_item']['proof']),staging=dict(path=value['staging'],state='absent'),
            backup=dict(path=value['backup'],state='absent'),services_inactive=True)
    retirement=ConfigurationRetirement(old,source_reader=lambda:deepcopy(source),observer=observe,window=window)
    retirement.retire('retire-unit',reference)
    agreement=dict(operation_id='successor-unit',context=deepcopy(source['context']),targets=['file:'+UNIT],nonce='5'*32)
    window=ProvisioningWindow(agreement,lambda:deepcopy(agreement))
    replacement=ConfigurationFileAdapter(adapter.files,window=window,preflight=adapter.preflight)
    driver=ConfigurationRevision(old.journal,replacement,window=window,generation_source=lambda:deepcopy(source))
    prepared=driver.prepare('successor-unit',source)
    files=PreparedUnitFiles(root,journal=driver.journal,reference=prepared)
    replacement=ConfigurationFileAdapter(files,window=window,preflight=adapter.preflight);driver.adapter=replacement
    return driver,replacement,prepared,root,old,reference


def test_successor_scoped_exchange_preserves_history_and_backup(successor):
    driver,adapter,prepared,root,old,reference=successor;original=(root/UNIT.lstrip('/')).read_bytes()
    effective=driver.apply(prepared['id'])
    assert effective['configuration_revision']['operation_id']==prepared['id']
    assert prepared['predecessor']['revision_id']==reference['id']
    assert old.read(reference['id'])==reference
    assert (root/prepared['backup'].lstrip('/')).read_bytes()==original
    assert 'Requisite=' in (root/UNIT.lstrip('/')).read_text()
    assert driver.apply(prepared['id'])==effective
    with pytest.raises(Conflict,match='retired'):old.apply(reference['id'])


@pytest.mark.parametrize('boundary',[EXCHANGE,NOREPLACE])
def test_successor_lost_rename_reply_recovers_without_repeated_exchange(successor,monkeypatch,boundary):
    driver,adapter,prepared,_,old,reference=successor;rename=adapter.swap._rename;calls=[]
    def lost(*args):
        calls.append(args[-1]);rename(*args)
        if args[-1]==boundary:raise OSError('synthetic successor rename reply lost')
    monkeypatch.setattr(adapter.swap,'_rename',lost)
    with pytest.raises(OSError,match='successor rename'):driver.apply(prepared['id'])
    assert driver.recover(prepared['id'])==driver.effective(prepared['id'])
    assert calls==[EXCHANGE,NOREPLACE] and old.read(reference['id'])==reference
