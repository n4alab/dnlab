#!/usr/bin/env python3
"""Diagnostic only: equal Docker port requests on stock bridge and dnlab-vrf.

Uses the durable fixture birth helper directly, outside production lifecycle.
No Docker port verification/compensation can preempt process readiness here.
"""
import argparse
import hashlib
import http.client
import ipaddress
import json
import os
from pathlib import Path
import re
import socket
import sys
import time
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE))
from dnlab_runtime.backend import Backend,Docker,Linux,labels
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict,canonical
from dnlab_runtime.management_network import snapshot
from dnlab_runtime.endpoint_name_probe import READY_PROGRAM
from initial_management_identity_smoke import delete_fixture_interface,PLUGIN,STATE
from nos_fixture import NosFixture
from smoke import wait_for


def save(path,value):
    temporary=path.with_suffix(path.suffix+'.pending')
    with temporary.open('w') as stream:
        stream.write(json.dumps(value,indent=2)+'\n');stream.flush();os.fsync(stream.fileno())
    os.replace(temporary,path)
    fd=os.open(path.parent,os.O_RDONLY|os.O_DIRECTORY)
    try:os.fsync(fd)
    finally:os.close(fd)


def probe(address,port,marker):
    connection=http.client.HTTPConnection(address,port,timeout=2)
    try:
        connection.request('GET','/');response=connection.getresponse();body=response.read(1024)
        return {'connected':True,'http_status':response.status,'body_matches':body==marker.encode()}
    except (OSError,http.client.HTTPException) as error:
        return {'connected':False,'error_type':type(error).__name__,'errno':getattr(error,'errno',None)}
    finally:connection.close()


def absence_inventory(api,linux,intent):
    names={entry['name'] for entry in intent['infra']}
    for entry in intent['networks'].values():
        name=(entry['payload'].get('Options') or {}).get('com.docker.network.bridge.name')
        if name:names.add(name)
    return {'containers_absent':all(v.get('id') and api.inspect(v['id']) is None for v in intent['workloads'].values()),
            'networks_absent':all(v.get('id') and api.request('GET','/networks/'+v['id'],missing_ok=True) is None for v in intent['networks'].values()),
            'kernel_interfaces_absent':all(linux.link(name) is None for name in names)}


def program(marker):
    return '''import os,signal,sys,time
signal.signal(signal.SIGTERM,lambda *_:sys.exit(0))
import http.server,threading
MARKER='''+repr(marker)+'''
class Handler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200);self.end_headers();self.wfile.write(MARKER.encode())
    def log_message(self,*args):pass
server=http.server.HTTPServer(('0.0.0.0',8080),Handler)
threading.Thread(target=server.serve_forever,daemon=True).start()
with open('/proc/1/stat') as stream:boot=stream.read().rsplit(')',1)[1].split()[19]
path='/run/dnlab-canary-ready-'+MARKER
with open(path+'.pending','x') as stream:
    os.chmod(path+'.pending',0o600);stream.write(MARKER+'\\n'+boot);stream.flush();os.fsync(stream.fileno())
os.replace(path+'.pending',path)
time.sleep(3600)
'''


def run(image,plugin_sha256,output):
    if os.geteuid()!=0:raise RuntimeError('root required')
    if not re.fullmatch('sha256:[0-9a-f]{64}',image):raise ValueError('immutable local image ID required')
    if hashlib.sha256(PLUGIN.read_bytes()).hexdigest()!=plugin_sha256:raise Conflict('plugin fingerprint changed')
    output=Path(output);output.mkdir(mode=0o700,parents=True,exist_ok=False)
    api=Docker();linux=Linux();token=uuid.uuid4().hex[:8];lab='publication-'+token
    baseline=json.loads(STATE.read_text());host_scope=linux.network_identity()
    journal=Journal(output/'journal');backend=Backend(api,linux)
    report={'status':'running','scope':'direct Docker comparative diagnosis; not production runtime qualification',
            'lab':lab,'image':image,'plugin_sha256':plugin_sha256,'host_scope':host_scope,'cases':{},'cleanup':None}
    intent={'lab':lab,'infra':[],'networks':{},'workloads':{}}
    fixtures={};cleanup_errors=[]
    def record():save(output/'intent.json',intent);save(output/'report.json',report)
    def add_link(name,kind,extra):
        if linux.link(name):raise Conflict('fixture kernel name occupied')
        seed=hashlib.sha256((lab+name).encode()).hexdigest()[:10]
        entry={'name':name,'kind':kind,'mac':'02:'+':'.join(seed[i:i+2] for i in range(0,10,2)),'alias':lab}
        if kind=='vrf':entry['table']=int(extra[1])
        intent['infra'].append(entry);record()
        linux.command(['link','add',name,'address',entry['mac'],'type',kind,*extra])
        value=linux.link(name)
        if value.get('address')!=entry['mac'] or value.get('linkinfo',{}).get('info_kind')!=kind:raise Conflict('created interface differs')
        entry['ifindex']=value['ifindex'];record()
        linux.command(['link','set',name,'alias',lab]);linux.command(['link','set',name,'up'])
    def add_network(case,payload):
        if api.request('GET','/networks/'+payload['Name'],missing_ok=True):raise Conflict('fixture network name occupied')
        entry={'payload':payload,'id':None,'proof':None};intent['networks'][case]=entry;record()
        response=api.request('POST','/networks/create',payload);entry['id']=response['Id'];record()
        value=api.network(entry['id']);entry['proof']=snapshot(value);record();return value
    try:
        report['docker_version']={k:v for k,v in api.request('GET','/version').items() if k in ('Version','ApiVersion','KernelVersion','Os','Arch')}
        # Reserve neither lab ranges nor ports globally: reject occupied ranges,
        # and keep runtime/driver collision errors as observations, never steal.
        networks=api.request('GET','/networks')
        pools=[ipaddress.ip_network(c['Subnet'],strict=False) for n in networks for c in ((n.get('IPAM') or {}).get('Config') or []) if c.get('Subnet')]
        subnets=[ipaddress.ip_network('198.19.'+str(i)+'.0/24') for i in range(160,254)]
        subnets=[n for n in subnets if not any(p.version==4 and p.overlaps(n) for p in pools)]
        if len(subnets)<2:raise Conflict('no free fixture subnets')
        chosen=[str(n) for n in subnets[:2]];report['subnets']=dict(zip(('bridge','vrf'),chosen))
        ports=[]
        for family,address in ((socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')):
            with socket.socket(family,socket.SOCK_STREAM) as connection:
                if family==socket.AF_INET6:connection.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
                connection.bind((address,0));ports.append(connection.getsockname()[1])
        bindings=[{'HostIp':'127.0.0.1','HostPort':str(ports[0])},{'HostIp':'::1','HostPort':str(ports[1])}]
        report['requested_bindings']={'8080/tcp':bindings};record()
        stock=add_network('bridge',{'Name':lab+'-bridge','Driver':'bridge','Labels':{'io.dnlab.spike':lab},
            'Options':{'com.docker.network.bridge.name':'drspc'+token},
            'IPAM':{'Driver':'default','Config':[{'Subnet':chosen[0],'Gateway':str(subnets[0][1])}]}})
        tables={v.get('linkinfo',{}).get('info_data',{}).get('table') for v in json.loads(linux.command(['-j','-d','link','show']))}
        tables.update(v.get('table') for v in json.loads(linux.command(['-j','route','show','table','all'])))
        table=next((i for i in range(42000,45000) if i not in tables),None)
        if table is None:raise Conflict('no free fixture VRF table')
        vrf='drspv'+token;bridge='drspb'+token
        add_link(vrf,'vrf',['table',str(table)]);add_link(bridge,'bridge',[])
        linux.command(['link','set',bridge,'master',vrf]);linux.command(['addr','add',str(subnets[1][1])+'/24','dev',bridge])
        remote=add_network('vrf',{'Name':lab+'-vrf','Driver':'dnlab-vrf','EnableIPv6':False,
            'Options':{'dnlab.bridge':bridge,'dnlab.vrf':vrf,'dnlab.lab':lab},
            'Labels':{'io.dnlab.spike':lab,'io.dnlab.lab':lab,'io.dnlab.managed':'mgmt-vrf'},
            'IPAM':{'Driver':'dnlab-vrf','Options':{'dnlab.tenant':lab,'dnlab.reserved':str(subnets[1][1]),'dnlab.host-index':'0','dnlab.host-count':'1'},
                    'Config':[{'Subnet':chosen[1],'Gateway':str(subnets[1][1])}]}})
        for index,(case,network) in enumerate((('bridge',stock),('vrf',remote))):
            marker=lab+'-'+case
            request={'lab_id':lab,'node_id':case}
            spec={'kind':'linux','container_name':'drsp-'+marker,'image':image,'command':['python3','-u','-c',program(marker)],'stop_timeout':10}
            # Complete non-privileged diagnostic config is in the fixture
            # ledger. Its production spec intentionally declares no management
            # or publication: this diagnoses Docker drivers, not Engine.apply.
            config={'Image':image,'Cmd':spec['command'],'Labels':{**labels(request,spec),'io.dnlab.spike':lab},'StopSignal':'SIGTERM',
                'ExposedPorts':{'8080/tcp':{}},'HostConfig':{'NetworkMode':network['Id'],'PortBindings':{'8080/tcp':bindings},'RestartPolicy':{'Name':'no'},'AutoRemove':False},
                'NetworkingConfig':{'EndpointsConfig':{network['Id']:{'IPAMConfig':{'IPv4Address':str(subnets[index][2])}}}}}
            fixture=NosFixture(journal,backend,request,spec);fixtures[case]=fixture
            intent['workloads'][case]={'request':request,'spec':spec,'config':config};record()
            identity=fixture.create(config);intent['workloads'][case]['id']=identity;record();fixture.start()
            readiness=api.exec_checked(identity,['python3','-c',READY_PROGRAM,marker],timeout=15)
            local_check="import urllib.request; assert urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:8080/',timeout=2).read()=="+repr(marker.encode())
            local_exec=api.exec_checked(identity,['python3','-c',local_check],timeout=5)
            current=backend.inspect(request,spec)
            if not current or current['Id']!=identity or set(current['NetworkSettings']['Networks'])!={network['Name']}:raise Conflict('diagnostic workload attachment changed')
            case_report={'container_id':identity,'birth_intent':fixture.get()['id'],'readiness_exec':readiness,'guest_http_exec':local_exec,
                'configured_bindings':current['HostConfig']['PortBindings'],'observed_bindings':current['NetworkSettings']['Ports'],
                'endpoint':current['NetworkSettings']['Networks'][network['Name']],
                'tcp_ipv4':probe('127.0.0.1',ports[0],marker),'tcp_ipv6':probe('::1',ports[1],marker),
                'unrequested_ipv4':probe('127.0.0.2',ports[0],marker)}
            report['cases'][case]=case_report;record()
            fixture.cleanup(force=False);case_report['ordinary_stop']='verified';record()
        report['status']='diagnosed'
    except BaseException as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error));raise
    finally:
        for case,fixture in reversed(tuple(fixtures.items())):
            try:fixture.cleanup(force=False)
            except Exception as error:cleanup_errors.append(case+': '+type(error).__name__)
        if not cleanup_errors:
            for case,entry in reversed(tuple(intent['networks'].items())):
                try:
                    if entry['id'] is None or entry['proof'] is None:raise Conflict('network creation response/proof missing')
                    current=api.request('GET','/networks/'+entry['id'],missing_ok=True)
                    if current:
                        if snapshot(current)!=entry['proof'] or current.get('Containers'):raise Conflict('network changed or occupied')
                        if case=='bridge':
                            name=current['Options']['com.docker.network.bridge.name']
                            if json.loads(linux.command(['-j','link','show','master',name])):raise Conflict('stock bridge still occupied')
                        api.request('DELETE','/networks/'+entry['id'])
                except Exception as error:cleanup_errors.append(case+': '+type(error).__name__);break
        if not cleanup_errors:
            for entry in reversed(intent['infra']):
                try:
                    if linux.network_identity()!=host_scope:raise Conflict('host scope changed')
                    delete_fixture_interface(linux,entry)
                except Exception as error:cleanup_errors.append(entry['name']+': '+type(error).__name__);break
        try:
            if json.loads(STATE.read_text())!=baseline:raise Conflict('plugin state differs from baseline')
            if hashlib.sha256(PLUGIN.read_bytes()).hexdigest()!=plugin_sha256:raise Conflict('installed plugin changed')
        except Exception as error:cleanup_errors.append(type(error).__name__+': '+str(error))
        absence=absence_inventory(api,linux,intent)
        if not all(absence.values()):cleanup_errors.append('owned resource absence not verified')
        report['cleanup']={'absence_inventory':absence,'verified':not cleanup_errors,'errors':cleanup_errors,'VD_force_sent':False,
                           'plugin_baseline_equal':json.loads(STATE.read_text())==baseline,
                           'plugin_source_unchanged':hashlib.sha256(PLUGIN.read_bytes()).hexdigest()==plugin_sha256}
        record();journal.close();print(output/'report.json',flush=True)
    if cleanup_errors:raise RuntimeError('diagnostic cleanup incomplete; preserve the output journal')
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true',required=True);parser.add_argument('--image',required=True)
    parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args();run(args.image,args.plugin_sha256,args.output)
