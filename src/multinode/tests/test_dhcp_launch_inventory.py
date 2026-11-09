"""A pending launch observes every daemon, including renamed executables."""
from copy import deepcopy
import pytest
from dnlab_multinode.services import jumphost_host as module
from tests.test_dhcp_shutdown_status import world


@pytest.mark.parametrize('case',['old-zombie','old-gone','new-daemon','renamed-hash','renamed-inode','other-namespace'])
def test_complete_inventory_distinguishes_original_exit_and_new_live_candidates(world,monkeypatch,case):
    w=world;w.service.pid_namespace=deepcopy(w.expected['pid_namespace'])
    if case=='old-gone':w.state['gone']=True
    if case in ('new-daemon','renamed-hash','renamed-inode','other-namespace'):w.state['foreign']=True
    if case=='renamed-hash':
        w.processes[90007]['comm']='renamed';monkeypatch.setattr(module,'hash_descriptor',lambda fd:w.expected['binary_sha256'])
    if case=='renamed-inode':
        w.processes[90007]['comm']='renamed';w.infos[w.otherexe]=deepcopy(w.expected['binary'])
    if case=='other-namespace':w.state['foreign_namespace']=True
    result=w.service.launch_inventory(w.expected)
    assert result==([{'host_pid':999,'pid':99,'start':'9999'}] if case in ('new-daemon','renamed-hash','renamed-inode') else [])
    w.signal.assert_not_called()


@pytest.mark.parametrize('conflict',['container','binary','host-pid-reuse','local-pid-reuse','permission'])
def test_inventory_errors_or_reused_original_identity_never_qualify_absence(world,conflict):
    w=world;w.service.pid_namespace=deepcopy(w.expected['pid_namespace'])
    if conflict=='container':w.service.container_proof['id']='f'*64
    if conflict=='binary':w.infos[w.binary]=dict(w.infos[w.binary],inode=999)
    if conflict=='host-pid-reuse':w.processes[w.original]['start']='replaced'
    if conflict=='local-pid-reuse':w.state['foreign']=True;w.processes[90007]['local']=w.expected['pid']
    if conflict=='permission':w.state.update(foreign=True,permission=True)
    with pytest.raises((module.JumphostError,PermissionError)):w.service.launch_inventory(w.expected)
    w.signal.assert_not_called();w.service.observe.assert_not_called()
