"""Standalone namespace-local, index-bound endpoint deletion helper."""
import errno
import json
import os
from pathlib import Path
import re
import socket
import struct
import subprocess
import sys
import uuid


class IdentityConflict(Exception):
    pass


def signature(link):
    return {key:link.get(key) for key in ('ifname','ifindex','ifalias','address','link_index')} | {
        'kind':link.get('linkinfo',{}).get('info_kind')}


def context():
    info=os.stat('/proc/self/ns/net')
    path=os.environ.get('DNLAB_RUNTIME_HOST_BOOT_ID_FILE','/proc/sys/kernel/random/boot_id')
    if not os.path.isabs(path):raise IdentityConflict('authoritative host boot ID path must be absolute')
    boot=str(uuid.UUID(Path(path).read_text().strip()))
    return {'boot_id':boot,'device':info.st_dev,'inode':info.st_ino}


def delete_packet(index,sequence,port):
    if type(index) is not int or not 0<index<2**31:raise IdentityConflict('invalid endpoint ifindex')
    body=struct.pack('=BBHiII',socket.AF_UNSPEC,0,0,index,0,0)
    # RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK. No interface name attribute.
    return struct.pack('=IHHII',16+len(body),17,5,sequence,port)+body


def acknowledgement(data,sender,sequence,port):
    if sender!=(0,0) or len(data)<20:raise RuntimeError('invalid netlink acknowledgement')
    length,kind,flags,seq,pid=struct.unpack_from('=IHHII',data)
    if length<20 or length>len(data) or seq!=sequence or pid!=port or kind!=2:
        raise RuntimeError('unexpected netlink acknowledgement')
    error=struct.unpack_from('=i',data,16)[0]
    if error>0:raise RuntimeError('invalid netlink error code')
    if error:raise OSError(-error,os.strerror(-error))


def delete(config):
    expected=config['link'];scope=config['context']
    if (not isinstance(expected,dict) or expected.get('kind')!='veth'
            or not re.fullmatch(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}',expected.get('address',''))
            or type(expected.get('link_index')) is not int or expected['link_index']<=0):
        raise IdentityConflict('invalid qualified endpoint identity')
    index=expected['ifindex'];delete_packet(index,1,0)
    if context()!=scope:raise IdentityConflict('endpoint namespace identity changed')
    # The socket belongs to this verified namespace for its entire lifetime.
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as netlink:
        netlink.settimeout(10);netlink.bind((0,0));port=netlink.getsockname()[0]
        inventory=subprocess.run(['ip','-j','-d','link','show'],capture_output=True,text=True,timeout=10,check=True)
        links=json.loads(inventory.stdout)
        for link in links:
            if 'link_index' not in link and 'link' in link:
                peer=next((other for other in links if other.get('ifname')==link['link']),None)
                if peer is not None:link['link_index']=peer['ifindex']
        current=next((link for link in links if link.get('ifindex')==index),None)
        if current is None:return {'status':'absent','ifindex':index}
        if signature(current)!=expected:raise IdentityConflict('endpoint identity changed before deletion')
        if context()!=scope:raise IdentityConflict('endpoint namespace identity changed')
        sequence=int.from_bytes(os.urandom(4),'little') or 1
        netlink.sendto(delete_packet(index,sequence,port),(0,0))
        data,sender=netlink.recvfrom(65536)
        try:acknowledgement(data,sender,sequence,port)
        except OSError as error:
            if error.errno!=errno.ENODEV:raise
            return {'status':'absent','ifindex':index}
    return {'status':'deleted','ifindex':index}


if __name__=='__main__':
    try:result=delete(json.loads(sys.argv[1]))
    except IdentityConflict as error:result={'status':'conflict','error':str(error)}
    except Exception as error:
        result={'status':'error','error':'kernel endpoint deletion failed','error_type':type(error).__name__,'errno':getattr(error,'errno',None)}
    print(json.dumps(result))
