#!/usr/bin/env python3
"""Local additional jumphost L2 attachment gate; no DHCP/RA or public API claim."""
import argparse
from copy import deepcopy
import json
import select
import socket
import time
import uuid

from jumphost_identity_smoke import run,execute,ManagementWorker,NetworkGuard,desired_network
from dnlab_multinode.services import jumphost
from dnlab_multinode.services.jumphost_host import names
from dnlab_multinode.services.management_services import peer_interface


def attachment_gate(fixture):
    workers=fixture['workers'];test=workers[1];record=test.operate('read');root=fixture['root'];report=fixture['report']
    index=next(i for i,w in enumerate(fixture['management_workers']) if w.plan['lab']==test.lab)
    old=fixture['management_workers'][index];plan=deepcopy(old.plan);token=uuid.uuid4().hex[:8]
    occupied={v.get('linkinfo',{}).get('info_data',{}).get('id') for v in json.loads(execute(['ip','-j','-d','link','show']))}
    vni=next(v for v in range(16001000,16002000) if v not in occupied)
    blue={'bridge':'drspb'+token,'vxlan':'drspv'+token,'vni':vni,'underlay':'lo','local':'127.0.0.1','remotes':[],'address':'198.19.232.1/24'}
    plan['segments']['blue']=blue
    management=ManagementWorker(plan,directory=old.directory)
    fixture['management_workers'][index]=management;fixture['intent']['management'][index]=plan;fixture['save']()
    management.operate('preflight');management.operate('ensure');management.operate('verify-ready')
    origin=management.read();default=origin['networks']['default']['expected'];expected=deepcopy(default)
    expected.update(network=test.lab+'-blue',bridge=blue['bridge'],ipv4_subnet='198.19.232.0/24',ipv4_gateway='198.19.232.1',reserved=['198.19.232.1','198.19.232.254'])
    networks={'default':default,'blue':expected};guard=NetworkGuard(management,networks)
    fixture['network_guards'][test.lab]=guard
    entry={'payload':desired_network(expected),'id':None,'management_lab':test.lab}
    fixture['networks'].append(entry);fixture['save']()
    guard.operate('preflight');guard.operate('ensure');guard.operate('mark-used');guard.operate('verify-ready')
    entry['id']=management.read()['networks']['blue']['id'];fixture['save']()
    attachment={'segment':'blue','network':expected['network'],'bridge':blue['bridge'],'interface':peer_interface(test.lab,'blue'),
                'ipv4':'198.19.232.254/24','ipv6':''}
    request={'request_id':'add-blue','container_id':record['container_id'],'generation':record['config']['generation'],
             'attachment':attachment,'management_intent':expected}
    original=test.run;pending=[True]
    def lost_reply(argv,**kwargs):
        result=original(argv,**kwargs)
        if pending[0] and argv[:4]==['ip','link','add',names(test.lab,'blue')]:
            pending[0]=False;raise RuntimeError('injected lost additional attachment reply')
        return result
    test.run=lost_reply
    try:test.operate('segment-add',request)
    except RuntimeError as error:
        if str(error)!='injected lost additional attachment reply':raise
    else:raise AssertionError('lost additional attachment reply not injected')
    assert test.read()['management_attachments']['blue']['phase']=='recovery_required'
    recovered=jumphost.add_jumphost_management_segment(test.lab,fixture['transport'],container_id=record['container_id'],
        generation=record['config']['generation'],request_id=request['request_id'],attachment=attachment,management_intent=expected,recover=True)
    row=recovered['management_attachments']['blue']
    assert row['phase']=='active' and recovered['config']==record['config'] and recovered['host']==record['host']
    assert recovered['container_id']==record['container_id'] and recovered['started_at']==record['started_at']
    assert test.operate('ensure',record['config'])['management_attachments']['blue']['host']==row['host']
    with test.namespace(recovered) as fd:
        execute(['nsenter','--net=/proc/self/fd/'+str(fd),'ping','-I',attachment['interface'],'-c','1','-W','2','198.19.232.1'],pass_fds=(fd,))
        execute(['nsenter','--net=/proc/self/fd/'+str(fd),'ping','-I',record['config']['attachment']['interface'],'-c','1','-W','2','198.19.231.1'],pass_fds=(fd,))
        marker=('DNLAB-L2-'+uuid.uuid4().hex).encode();seen=set()
        with socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88b5)) as left, socket.socket(socket.AF_PACKET,socket.SOCK_RAW,socket.htons(0x88b5)) as right:
            left.bind((record['config']['attachment']['bridge'],0));right.bind((blue['bridge'],0))
            frame=b'\xff'*6+bytes.fromhex(row['peer']['address'].replace(':',''))+b'\x88\xb5'+marker
            program="import socket,sys;s=socket.socket(socket.AF_PACKET,socket.SOCK_RAW);s.bind((sys.argv[1],0));s.send(bytes.fromhex(sys.argv[2]))"
            execute(['nsenter','--net=/proc/self/fd/'+str(fd),'python3','-c',program,attachment['interface'],frame.hex()],pass_fds=(fd,))
            deadline=time.monotonic()+2
            while time.monotonic()<deadline:
                readable,_,_=select.select([left,right],[],[],deadline-time.monotonic())
                for sock in readable:
                    if marker in sock.recv(65535):seen.add('default' if sock is left else 'blue')
            assert seen=={'blue'},repr(seen)
    report['additional_management']={'container_id':record['container_id'],'started_at':record['started_at'],
        'blue_network_id':entry['id'],'blue_host':row['host'],'blue_peer':row['peer'],'blue_bridge':blue['bridge'],
        'blue_interface':attachment['interface'],'broadcast_seen_only_on_blue':True,'request_id':request['request_id']}
    report['checks'].extend(['additional management endpoint journaled before birth; lost reply recovered through standalone worker',
        'same container birth labels/ID/start time and original attachment; ICMP on both management ports',
        'test EtherType L2 broadcast from blue observed only on blue bridge; no shared L2 domain'])
    fixture['save']()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--image',required=True);parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();print(run(args.image,args.plugin_sha256,args.output,attachment_gate=attachment_gate))
