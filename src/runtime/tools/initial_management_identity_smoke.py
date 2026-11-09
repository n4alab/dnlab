#!/usr/bin/env python3
"""Opt-in image gate on dedicated dnlab-vrf networks; installed plugin unchanged."""
import argparse
import hashlib
import json
import os
import re
import socket
import sqlite3
from pathlib import Path
import sys
import tempfile
import uuid

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.backend import Docker,Linux
from dnlab_runtime.management_network import snapshot
from dnlab_runtime.manifest import Conflict,RuntimeErrorBase
from dnlab_runtime.transport import Client
from dnlab_runtime.endpoint_name_probe import CANARY_PROGRAM,READY_PROGRAM
from smoke import command,wait_for,operation

PLUGIN=Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
STATE=Path('/var/lib/dnlab-vrf-plugin/state.json')


def delete_fixture_interface(linux,entry):
    from dnlab_runtime.kernel_endpoint import context,signature,delete_packet,acknowledgement
    scope=context()
    with socket.socket(socket.AF_NETLINK,socket.SOCK_RAW,socket.NETLINK_ROUTE) as connection:
        connection.bind((0,0));connection.settimeout(10)
        value=linux.link(entry['name'])
        if value is None:return
        if (value.get('ifindex')!=entry.get('ifindex') or value.get('address')!=entry['mac']
                or value.get('ifalias')!=entry['alias'] or value.get('linkinfo',{}).get('info_kind')!=entry['kind']
                or entry['kind']=='vrf' and value.get('linkinfo',{}).get('info_data',{}).get('table')!=entry['table']):
            raise Conflict('fixture host interface changed')
        if json.loads(linux.command(['-j','link','show','master',entry['name']])):raise Conflict('fixture host interface still occupied')
        if scope!=context() or signature(linux.link(entry['name']))!=signature(value):raise Conflict('fixture interface changed before deletion')
        port=connection.getsockname()[0];sequence=int.from_bytes(os.urandom(4),'little') or 1
        connection.sendto(delete_packet(value['ifindex'],sequence,port),(0,0))
        data,sender=connection.recvfrom(65536);acknowledgement(data,sender,sequence,port)
    if linux.link(entry['name']) is not None:raise Conflict('fixture host interface still present')


def run(runtime_image,image,plugin_sha256,*,management_mac=False,webui_bindings=False):
    if os.geteuid()!=0:raise RuntimeError('root required for the isolated local gate')
    if any(not re.fullmatch(r'sha256:[0-9a-f]{64}',value) for value in (runtime_image,image)) or not re.fullmatch(r'[0-9a-f]{64}',plugin_sha256):raise ValueError('immutable images and plugin SHA256 required')
    if hashlib.sha256(PLUGIN.read_bytes()).hexdigest()!=plugin_sha256:raise Conflict('installed plugin fingerprint differs')
    if command(['systemctl','is-active','dnlab-vrf-plugin.service'])!='active':raise Conflict('installed plugin is inactive')
    docker=Docker();linux=Linux();token=uuid.uuid4().hex[:8];lab='initial-mgmt-'+token
    root=Path(tempfile.mkdtemp(prefix='dnlab-initial-management-'));root.chmod(0o700)
    (root/'state').mkdir(mode=0o700);(root/'run').mkdir(mode=0o700)
    client=Client(str(root/'run/runtime.sock'));daemon=None;infra=[];networks={};nodes={};payloads={};requests={}
    baseline=json.loads(STATE.read_text())
    report={'status':'running','scope':'local Linux image + installed dnlab-vrf; no NOS/cross-host qualification',
            'runtime_image':runtime_image,'image':image,'installed_plugin_sha256':plugin_sha256,'checks':[]}
    def record():
        (root/'fixture-intent.json').write_text(json.dumps({'lab':lab,'infra':infra,'networks':networks,'nodes':nodes,'requests':requests},indent=2)+'\n')
    def link(name,kind,extra):
        if linux.link(name):raise Conflict('fixture interface already exists')
        seed=hashlib.sha256((lab+name).encode()).hexdigest()[:10]
        entry={'name':name,'kind':kind,'mac':'02:'+':'.join(seed[i:i+2] for i in range(0,10,2)),'alias':lab}
        if kind=='vrf':entry['table']=int(extra[1])
        infra.append(entry);record()
        linux.command(['link','add',name,'address',entry['mac'],'type',kind,*extra])
        actual=linux.link(name)
        if actual.get('address')!=entry['mac'] or actual.get('linkinfo',{}).get('info_kind')!=kind:raise Conflict('fixture interface creation identity differs')
        entry['ifindex']=actual['ifindex'];record()
        linux.command(['link','set',name,'alias',lab]);linux.command(['link','set',name,'up'])
    def network(color):
        payload=payloads[color];name=payload['Name']
        if docker.request('GET','/networks/'+name,missing_ok=True):raise Conflict('fixture network already exists')
        networks[color]={'payload':payload,'proof':None};record()
        docker.request('POST','/networks/create',payload)
        value=docker.network(name);networks[color]['proof']=snapshot(value);record();return value
    def remove_network(color):
        entry=networks[color];value=docker.request('GET','/networks/'+entry['payload']['Name'],missing_ok=True)
        if value is None:return
        if (snapshot(value)!=entry['proof'] or value.get('Containers')
                or value.get('Labels',{}).get('io.dnlab.spike')!=lab):raise Conflict('fixture network ownership or occupancy changed')
        docker.request('DELETE','/networks/'+value['Id'])
    def owned(node):
        entry=nodes[node];value=docker.inspect(entry['name'])
        if value is not None and (value['Id']!=entry['id'] or value['Config']['Labels'].get('org.dnlab.runtime.lab')!=entry['lab']
                                 or value['Config']['Labels'].get('org.dnlab.runtime.node')!=node):raise Conflict('fixture workload generation changed')
        return value
    def prepare(node,action,revision,key,spec=None):
        raw={'schema_version':1,'lab_id':nodes[node]['lab'],'node_id':node,'action':action,'expected_revision':revision,'request_id':key}
        if spec is not None:raw['spec']=spec
        if action=='start':
            plan=client.request('POST','/v1/plan',raw)
            if plan.get('management_preflight') is not None:raw['management_preflight']=plan['management_preflight']
        requests[nodes[node]['lab']+'/'+node+'/'+key]=raw;record();return raw
    def submit(node,action,revision,key,spec=None,expected='completed',prepared=None):
        raw=prepared if prepared is not None else prepare(node,action,revision,key,spec)
        assert raw['node_id']==node and raw['lab_id']==nodes[node]['lab'] and raw['request_id']==key
        assert raw['action']==action and raw['expected_revision']==revision
        value=client.request('POST','/v1/operations',raw)
        return operation(client,value['id'],expected)
    def pin_count():
        connection=sqlite3.connect('file:'+str(root/'state/journal.sqlite3')+'?mode=ro',uri=True)
        try:return connection.execute('SELECT count(*) FROM management_network_proofs').fetchone()[0]
        finally:connection.close()
    def control_signature():
        value=owned('control')
        assert value and value['State']['Running']
        return {key:value[key] for key in ('Id','State','NetworkSettings')}
    try:
        occupied={v.get('linkinfo',{}).get('info_data',{}).get('table') for v in json.loads(linux.command(['-j','-d','link','show']))}
        occupied.update(v.get('table') for v in json.loads(linux.command(['-j','route','show','table','all'])))
        available=[i for i in range(42000,45000) if i not in occupied]
        if len(available)<2:raise Conflict('no free fixture VRF tables')
        for index,color in enumerate(('test','control')):
            vrf='drspv'+token+str(index);bridge='drspb'+token+str(index)
            link(vrf,'vrf',['table',str(available[index])]);link(bridge,'bridge',[])
            linux.command(['link','set',bridge,'master',vrf]);linux.command(['addr','add','198.19.229.1/24','dev',bridge])
            name=lab+'-'+color
            payloads[color]={'Name':name,'Driver':'dnlab-vrf','EnableIPv6':False,
                'Options':{'dnlab.bridge':bridge,'dnlab.vrf':vrf,'dnlab.lab':lab+('-control' if color=='control' else '')},
                'Labels':{'io.dnlab.spike':lab,'io.dnlab.lab':lab+('-control' if color=='control' else ''),'io.dnlab.managed':'mgmt-vrf'},
                'IPAM':{'Driver':'dnlab-vrf','Options':{'dnlab.tenant':name,'dnlab.reserved':'198.19.229.1','dnlab.host-index':'0','dnlab.host-count':'1'},
                        'Config':[{'Subnet':'198.19.229.0/24','Gateway':'198.19.229.1'}]}}
            network(color)
        name='drsp-initial-mgmt-'+token
        identity=command(['docker','create','--name',name,'--label','io.dnlab.spike='+lab,'--privileged','--network','host','--pid','host',
            '--mount','type=bind,src=/var/run/docker.sock,dst=/var/run/docker.sock','--mount',f'type=bind,src={root},dst={root}',
            '--mount',f'type=bind,src=/proc/sys/kernel/random/boot_id,dst={root}/host-boot-id,readonly',
            '-e',f'DNLAB_RUNTIME_HOST_BOOT_ID_FILE={root}/host-boot-id',runtime_image,'--socket',client.socket_path,'serve','--state-dir',str(root/'state')])
        daemon={'id':identity,'name':name};docker.start(identity);wait_for(lambda:client.request('GET','/v1/capabilities'))
        audit=json.loads(command(['docker','exec','-w','/',identity,'python3','-c',
            'import dnlab_runtime.management_network as m,hashlib,json;from pathlib import Path;p=Path(m.__file__);print(json.dumps({"path":str(p),"sha256":hashlib.sha256(p.read_bytes()).hexdigest()}))']))
        expected=hashlib.sha256((Path(__file__).resolve().parents[1]/'dnlab_runtime/management_network.py').read_bytes()).hexdigest()
        assert '/site-packages/' in audit['path'] and audit['sha256']==expected
        report['installed_module']=audit
        from resource_reservation_probe import probe
        def register_reservation(node,spec):
            nodes[node]={'name':spec['container_name'],'id':None,'lab':lab,'spec':spec,'revision':0};record()
        probe(client=client,docker=docker,state=root/'state',lab=lab,image=image,
              management_network=payloads['test']['Name'],register=register_reservation,report=report)
        # Before the first workload/pin, replace a network after planning it.
        probe_spec={'kind':'linux','container_name':'drsp-init-'+token+'-preflight','image':image,
                    'management':{'network':payloads['control']['Name'],'ipv4':'198.19.229.9'}}
        nodes['preflight']={'name':probe_spec['container_name'],'id':None,'lab':lab+'-control','spec':probe_spec,'revision':0};record()
        observed=prepare('preflight','start',0,'preflight-before-first-allocation',probe_spec)
        assert pin_count()==0 and docker.inspect(probe_spec['container_name']) is None
        old_control=observed['management_preflight']['network']['Id']
        remove_network('control');network('control')
        assert old_control!=networks['control']['proof']['Id']
        before_first=submit('preflight','start',0,'preflight-before-first-allocation',probe_spec,
                            expected='recovery_required',prepared=observed)
        assert 'management preflight changed' in before_first['error'] and pin_count()==0 and owned('preflight') is None
        report['first_allocation_preflight_rejected']=True
        for invalid_name in (lab+'-missing',payloads['control']['Name']):
            invalid={'schema_version':1,'lab_id':lab,'node_id':'invalid-plan','action':'start','expected_revision':0,
                     'request_id':'invalid-plan','spec':{**probe_spec,'management':{'network':invalid_name,'ipv4':'198.19.229.9'}}}
            try:client.request('POST','/v1/plan',invalid)
            except RuntimeErrorBase:pass
            else:raise AssertionError('invalid management plan accepted')
        assert pin_count()==0
        for node in ('test','control'):
            name='drsp-init-'+token+'-'+node
            spec={'kind':'linux','container_name':name,'image':image,'command':['python3','-u','-c',CANARY_PROGRAM,node,'0'],
                  'stop_timeout':3,'management':{'network':payloads[node]['Name'],'ipv4':'198.19.229.2'}}
            if management_mac:spec['management']['mac']='02:da:10:'+':'.join(token[i:i+2] for i in (0,2,4))
            nodes[node]={'name':name,'id':None,'lab':lab+('-control' if node=='control' else ''),'spec':spec,'revision':0};record()
            submit(node,'start',0,'start-'+node,spec)
            view=client.request('GET',f"/v1/nodes/{nodes[node]['lab']}/{node}");nodes[node].update(id=view['container_id'],revision=1);record()
            docker.exec_checked(nodes[node]['id'],['python3','-c',READY_PROGRAM,node],timeout=12)
            assert owned(node)['NetworkSettings']['Networks'][payloads[node]['Name']]['NetworkID']==networks[node]['proof']['Id']
        def mac_observation(node):
            value=owned(node);endpoint=value['NetworkSettings']['Networks'][payloads[node]['Name']]
            from dnlab_runtime.endpoint_uplink import vrf_host_peer
            peer=linux.link(vrf_host_peer(endpoint['NetworkID'],endpoint['EndpointID']))
            with linux.namespace(value['State']['Pid']) as namespace:
                links=json.loads(linux.command(['-j','-d','link','show'],namespace))
            matches=[l for l in links if l.get('link_index')==peer['ifindex'] and peer.get('link_index')==l['ifindex']]
            expected=nodes[node]['spec']['management']['mac']
            assert endpoint['MacAddress']==expected and len(matches)==1 and matches[0]['address']==expected
            return {'container_id':value['Id'],'endpoint_mac':endpoint['MacAddress'],'kernel_mac':matches[0]['address'],'interface':matches[0]['ifname']}
        if management_mac:report['management_mac_before_stop']=mac_observation('test')
        if webui_bindings:
            from webui_binding_probe import prepare as webui_prepare,verify as webui_verify
            spec,allocations,generated=webui_prepare(lab,image,payloads['test']['Name'])
            nodes['webui']={'name':spec['container_name'],'id':None,'lab':lab,'spec':spec,'revision':0};record()
            submit('webui','start',0,'webui-start',spec)
            view=client.request('GET',f'/v1/nodes/{lab}/webui');nodes['webui'].update(id=view['container_id'],revision=1);record()
            report['webui_binding_probe']=webui_verify(docker,nodes['webui']['id'],spec,allocations,lab)
            report['webui_binding_probe']['generated_ports']=generated
            submit('webui','stop',1,'webui-stop');nodes['webui']['revision']=2;record()
            assert owned('webui') is None
        control=control_signature();original=networks['test']['proof']['Id']
        submit('test','stop',1,'stop-test');nodes['test']['revision']=2;assert owned('test') is None
        # An ordinary restart on the original network succeeds with a new VD.
        submit('test','start',2,'same-network-restart',nodes['test']['spec'])
        view=client.request('GET',f'/v1/nodes/{lab}/test');nodes['test'].update(id=view['container_id'],revision=3);record()
        docker.exec_checked(nodes['test']['id'],['python3','-c',READY_PROGRAM,'test'],timeout=12)
        if management_mac:
            report['management_mac_after_start']=mac_observation('test')
            assert report['management_mac_after_start']['container_id']!=report['management_mac_before_stop']['container_id']
            changed=json.loads(json.dumps(nodes['test']['spec']));changed['management']['mac']='02:00:00:00:00:99'
            try:prepare('test','start',3,'change-mac-refused',changed)
            except RuntimeErrorBase:pass
            else:raise AssertionError('changed native MAC accepted')
        submit('test','stop',3,'second-stop');nodes['test']['revision']=4
        assert control_signature()==control
        restart_plan=prepare('test','start',4,'foreign-network-restart',nodes['test']['spec'])
        new_spec={**nodes['test']['spec'],'container_name':'drsp-init-'+token+'-newspawn',
                  'management':dict(nodes['test']['spec']['management'])}
        if management_mac:new_spec['management']['mac']='02:db:10:'+':'.join(token[i:i+2] for i in (0,2,4))
        nodes['newspawn']={'name':new_spec['container_name'],'id':None,'lab':lab,'spec':new_spec,'revision':0};record()
        spawn_plan=prepare('newspawn','start',0,'spawn-on-replacement',new_spec)
        remove_network('test');replacement=network('test');assert replacement['Id']!=original
        rejected=submit('test','start',4,'foreign-network-restart',nodes['test']['spec'],expected='recovery_required',prepared=restart_plan)
        assert 'management network identity or configuration changed' in rejected['error'] and owned('test') is None
        spawn=submit('newspawn','start',0,'spawn-on-replacement',new_spec,expected='recovery_required',prepared=spawn_plan)
        assert 'management network identity or configuration changed' in spawn['error'] and owned('newspawn') is None
        try:client.request('GET',f'/v1/nodes/{lab}/test')
        except RuntimeErrorBase:pass
        else:raise AssertionError('inspect accepted recreated management')
        # Daemon death and recovery must not reset the original network pin.
        docker.signal(identity,'SIGKILL');wait_for(lambda:not docker.inspect(identity)['State']['Running'])
        docker.start(identity);wait_for(lambda:client.request('GET','/v1/capabilities'))
        client.request('POST','/v1/operations/'+rejected['id']+'/reconcile',{})
        replay=operation(client,rejected['id'],'recovery_required')
        assert owned('test') is None and control_signature()==control
        report['checks']=['read-only plan rejects missing/foreign networks without pinning','drift after plan rejects first allocation with zero pins/workloads','installed image module hash matches source','real dnlab-vrf initial boot and ordinary stop',
            'same-network restart creates new VD','recreated same-name/config network rejected before allocation',
            'new VD spawn cannot reset shared network identity','inspect refuses replacement','daemon SIGKILL + recovery preserve original pin','different lab with same subnet: control generation and network unchanged']
        report['checks'].append('existing container/port reservations rejected in plan and admission; cancellation releases without allocation')
        if webui_bindings:report['checks'].append('allocated WebUI IPv4/IPv6 bind preserved in generated YAML and native Docker; HTTP on both; unrequested IPv4 loopback refused; ordinary stop')
        if management_mac:report['checks'].append('stable native MAC verified in Docker and kernel across ordinary stop/start; changed MAC refused; equal MAC in isolated control lab preserved')
        report['original_network_id']=original;report['replacement_network_id']=replacement['Id'];report['rejected_operation']=replay
        report['status']='passed'
    except Exception as error:
        report['status']='failed';report['error']=str(error);raise
    finally:
        errors=[]
        for node,entry in nodes.items():
            try:
                value=owned(node) if entry['id'] else docker.inspect(entry['name'])
                if value is not None:
                    if entry['id'] is None:raise Conflict('fixture has an unacknowledged workload; preserve recovery evidence')
                    submit(node,'stop',entry['revision'],'cleanup-'+node)
                    assert owned(node) is None
            except Exception as error:errors.append('workload '+node+': '+str(error))
        if daemon and not errors:
            try:
                value=docker.inspect(daemon['id'])
                if value:
                    if value['Name']!='/'+daemon['name'] or value['Image']!=runtime_image or value['Config']['Labels'].get('io.dnlab.spike')!=lab:raise Conflict('fixture daemon changed')
                    if value['State']['Running']:
                        docker.signal(daemon['id'],'SIGKILL');wait_for(lambda:not docker.inspect(daemon['id'])['State']['Running'])
                    docker.remove(daemon['id'])
            except Exception as error:errors.append('daemon: '+str(error))
        for color in reversed(tuple(networks)):
            if errors:break
            try:remove_network(color)
            except Exception as error:errors.append('network '+color+': '+str(error))
        for entry in reversed(infra):
            if errors:break
            try:
                value=linux.link(entry['name'])
                if value is None:continue
                if (value.get('address')!=entry['mac'] or value.get('ifindex')!=entry.get('ifindex')
                        or value.get('ifalias')!=entry['alias'] or value.get('linkinfo',{}).get('info_kind')!=entry['kind']):raise Conflict('fixture host interface changed')
                if json.loads(linux.command(['-j','link','show','master',entry['name']])):raise Conflict('fixture host interface still occupied')
                delete_fixture_interface(linux,entry)
            except Exception as error:errors.append('interface '+entry['name']+': '+str(error))
        try:
            assert json.loads(STATE.read_text())==baseline,'plugin state differs from baseline'
            assert hashlib.sha256(PLUGIN.read_bytes()).hexdigest()==plugin_sha256,'installed plugin source changed'
        except Exception as error:errors.append(str(error))
        report['cleanup_verified']=not errors;report['cleanup_errors']=errors
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report['cleanup_verified'],'error':report.get('error')}))
        if errors:raise RuntimeError('fixture cleanup incomplete; consult report')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--runtime-image',required=True);parser.add_argument('--image',required=True);parser.add_argument('--plugin-sha256',required=True)
    parser.add_argument('--management-mac',action='store_true')
    parser.add_argument('--webui-bindings',action='store_true')
    args=parser.parse_args()
    if args.execute:run(args.runtime_image,args.image,args.plugin_sha256,management_mac=args.management_mac,webui_bindings=args.webui_bindings)
    else:print(json.dumps({'mutations_performed':False,'scope':'dedicated local VRFs/bridges/networks and Linux containers; installed plugin unchanged'}))
