"""Service signal authorization requires a complete original host proof."""
import copy
import os
import pytest
from dnlab_multinode.services.jumphost_host import dhcp_validate_identity, hash_descriptor, JumphostError


def proof():
    namespace={'device':4,'inode':12}
    binary={'device':9,'inode':22,'uid':0,'gid':0,'mode':0o755,'regular':True}
    return {'container':{'id':'a'*64,'image':'sha256:'+'b'*64,'pid_namespace':namespace,
                         'net_namespace':dict(namespace,inode=13),'mount_namespace':dict(namespace,inode=14),
                         'started_at':'original','host':{'boot':'first'}},
            'pid_namespace':namespace,'net_namespace':dict(namespace,inode=13),'mount_namespace':dict(namespace,inode=14),
            'host_pid':123,'pid':36,'start':'2345','uids':[65534]*4,'gids':[30]*4,
            'pid_file':{'device':9,'inode':42,'uid':65534,'gid':65534,'mode':0o644,'regular':True},
            'binary':binary,'mapped_binary':copy.deepcopy(binary),'binary_sha256':'c'*64,
            'profile':{'uid':65534,'gid':None,'user':'nobody','group':None},
            'command':['dnsmasq','--conf-file=/etc/dnsmasq.d/dnlab-mgmt.conf']}


def test_nonroot_pidfile_with_separate_process_group_is_qualified():
    value=proof();assert dhcp_validate_identity(value)==value
    assert dhcp_validate_identity(copy.deepcopy(value),value)==value


@pytest.mark.parametrize('change',['file-owner','file-write','file-type','process-uid','mixed-uid','mixed-gid',
                                  'configured-group','pidns','netns','mntns','binary-inode','binary-owner','binary-write','command'])
def test_unqualified_service_refused_before_signal(change):
    value=proof()
    if change=='file-owner':value['pid_file']['uid']=0
    if change=='file-write':value['pid_file']['mode']=0o666
    if change=='file-type':value['pid_file']['regular']=False
    if change=='process-uid':value['uids']=[0]*4
    if change=='mixed-uid':value['uids'][1]=0
    if change=='mixed-gid':value['gids'][1]=0
    if change=='configured-group':value['profile']['gid']=65534
    if change in ('pidns','netns','mntns'):
        key={'pidns':'pid_namespace','netns':'net_namespace','mntns':'mount_namespace'}[change]
        value[key]=dict(value[key],inode=999)
    if change=='binary-inode':value['mapped_binary']['inode']=999
    if change=='binary-owner':value['binary']['uid']=65534;value['mapped_binary']['uid']=65534
    if change=='binary-write':value['binary']['mode']=0o777;value['mapped_binary']['mode']=0o777
    if change=='command':value['command']=['sleep','infinity']
    with pytest.raises(JumphostError):dhcp_validate_identity(value)


@pytest.mark.parametrize('field',['host_pid','pid','start','binary_sha256'])
def test_reused_or_replaced_process_refused_on_recovery(field):
    old=proof();value=copy.deepcopy(old);value[field]=999 if isinstance(value[field],int) else 'replacement'
    with pytest.raises(JumphostError,match='generation differs'):dhcp_validate_identity(value,old)


def test_recreated_container_refused_even_with_same_service_pid():
    old=proof();value=copy.deepcopy(old);value['container']['id']='f'*64
    with pytest.raises(JumphostError,match='generation differs'):dhcp_validate_identity(value,old)


def test_binary_hash_uses_pinned_descriptor_without_relying_on_offset(tmp_path):
    import hashlib
    path=tmp_path/'binary';path.write_bytes(b'original binary')
    fd=os.open(path,os.O_RDONLY)
    try:
        os.read(fd,3);path.rename(tmp_path/'old');path.write_bytes(b'replacement')
        assert hash_descriptor(fd)==hashlib.sha256(b'original binary').hexdigest()
    finally:os.close(fd)
