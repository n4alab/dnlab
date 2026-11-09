"""Wire and ownership boundaries for index-bound endpoint deletion."""
import errno
import json
import struct
import subprocess

import pytest

from dnlab_runtime import kernel_endpoint as kernel


@pytest.fixture
def model(monkeypatch):
    scope={'boot_id':'fixture','device':1,'inode':2}
    link={'ifname':'drsp-owned','ifindex':17,'ifalias':'owned','address':'02:00:00:00:00:17',
          'link_index':19,'linkinfo':{'info_kind':'veth'}}
    class Netlink:
        sent=[];error=0
        def __enter__(self):return self
        def __exit__(self,*args):pass
        def settimeout(self,value):assert value==10
        def bind(self,address):assert address==(0,0)
        def getsockname(self):return (1234,0)
        def sendto(self,data,address):self.sent.append(data);assert address==(0,0)
        def recvfrom(self,size):
            header=struct.unpack_from('=IHHII',self.sent[-1])
            return struct.pack('=IHHIIi',20,2,0,header[3],1234,-self.error),(0,0)
    netlink=Netlink();inventory=[link]
    monkeypatch.setattr(kernel.socket,'socket',lambda *args:netlink)
    monkeypatch.setattr(kernel,'context',lambda:dict(scope))
    monkeypatch.setattr(kernel.subprocess,'run',lambda *args,**kwargs:subprocess.CompletedProcess(args,0,json.dumps(inventory),''))
    return {'context':dict(scope),'link':kernel.signature(link)},netlink,inventory,scope


def test_delete_targets_index_without_name_attributes(model):
    config,netlink,_,_=model
    assert kernel.delete(config)=={'status':'deleted','ifindex':17}
    assert len(netlink.sent)==1 and len(netlink.sent[0])==32
    assert struct.unpack_from('=IHHII',netlink.sent[0])[:3]==(32,17,5)
    assert struct.unpack_from('=i',netlink.sent[0],20)[0]==17
    assert b'drsp-owned' not in netlink.sent[0]


def test_missing_index_preserves_same_name_replacement_without_mutation(model):
    config,netlink,inventory,_=model
    inventory[0]={**inventory[0],'ifindex':18,'ifalias':'foreign'}
    assert kernel.delete(config)['status']=='absent' and not netlink.sent


@pytest.mark.parametrize('field,value',[('ifname','renamed'),('address','02:00:00:00:00:18'),('ifalias','foreign'),('link_index',20)])
def test_changed_identity_at_original_index_refused_before_send(model,field,value):
    config,netlink,inventory,_=model;inventory[0][field]=value
    with pytest.raises(kernel.IdentityConflict):kernel.delete(config)
    assert not netlink.sent


def test_namespace_change_before_mutation_refused(model):
    config,netlink,_,scope=model;scope['inode']=3
    with pytest.raises(kernel.IdentityConflict,match='namespace'):kernel.delete(config)
    assert not netlink.sent


def test_missing_original_after_inventory_does_not_delete_new_index(model):
    config,netlink,_,_=model;netlink.error=errno.ENODEV
    assert kernel.delete(config)['status']=='absent'
    assert len(netlink.sent)==1 and struct.unpack_from('=i',netlink.sent[0],20)[0]==17


def test_kernel_error_is_not_reported_success(model):
    config,netlink,_,_=model;netlink.error=errno.EPERM
    with pytest.raises(OSError) as error:kernel.delete(config)
    assert error.value.errno==errno.EPERM and len(netlink.sent)==1


@pytest.mark.parametrize('sender,seq,pid,kind,length',[((5,0),1,1234,2,20),((0,0),2,1234,2,20),
    ((0,0),1,5678,2,20),((0,0),1,1234,16,20),((0,0),1,1234,2,100)])
def test_invalid_ack_cannot_confirm_delete(sender,seq,pid,kind,length):
    packet=struct.pack('=IHHIIi',length,kind,0,seq,pid,0)
    with pytest.raises(RuntimeError):kernel.acknowledgement(packet,sender,1,1234)


def test_local_named_peer_is_normalized_like_backend_link(model):
    config,netlink,inventory,_=model
    inventory[0].pop('link_index');inventory[0]['link']='peer0'
    inventory.append({'ifname':'peer0','ifindex':19,'link_index':17})
    assert kernel.delete(config)['status']=='deleted' and len(netlink.sent)==1
