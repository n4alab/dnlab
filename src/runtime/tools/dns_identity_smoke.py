#!/usr/bin/env python3
"""Isolated DNS generation/reload gate; only token-scoped Docker resources."""
import argparse
import copy
import dataclasses
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import shlex
import socket
import struct
import subprocess
import sys
import time
import uuid

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'multinode'))
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from dnlab_multinode.services.dns_host import Worker
from dnlab_multinode.services.jumphost_host import execute
from dnlab_multinode.services import dns
from dnlab_runtime.backend import Docker


def query(address, expected, tcp=False):
    transaction = os.urandom(2)
    question = b''.join(bytes([len(p)]) + p.encode() for p in 'fixture.test'.split('.')) + b'\0\0\1\0\1'
    payload = transaction + struct.pack('!HHHHH', 0x100, 1, 0, 0, 0) + question
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as stream:
        stream.settimeout(.5); stream.connect((address, 53))
        if tcp:
            stream.sendall(struct.pack('!H',len(payload))+payload)
            def read(count):
                out=b''
                while len(out)<count:
                    block=stream.recv(count-len(out))
                    if not block: raise RuntimeError('short DNS TCP response')
                    out+=block
                return out
            response=read(struct.unpack('!H',read(2))[0])
        else:
            stream.send(payload); response=stream.recv(4096)
    assert response[:2]==transaction and response[3]&15==0 and struct.unpack('!H',response[6:8])[0]>=1, {'tcp':tcp,'response_hex':response.hex()}
    assert ipaddress.IPv4Address(expected).packed in response[12+len(question):], response.hex()


def run(output, image):
    if os.getuid()!=0 or not image.startswith('sha256:'): raise RuntimeError('root and immutable image ID required')
    root=Path(output);root.mkdir(parents=True,mode=0o700,exist_ok=False)
    token=uuid.uuid4().hex[:8];lab='dnsgate-'+token;name='drsp-dns-'+token;bridge='drspb'+token
    docker=Docker();network_id=None;workers=[];checks=[]
    payload={'Name':name,'Driver':'bridge','Labels':{'io.dnlab.spike':lab},
             'Options':{'com.docker.network.bridge.name':bridge},
             'IPAM':{'Config':[{'Subnet':'198.19.234.0/24','Gateway':'198.19.234.1'}]}}
    intent={'network_payload':payload,'network_id':None,'labs':[]}
    report={'status':'running','checks':checks,'image':image}
    def save():
        for target,value in [('intent.json',intent),('report.json',report)]:
            temporary=root/('.'+target)
            with temporary.open('w') as stream:
                json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
            os.replace(temporary,root/target)
        fd=os.open(root,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def wait_query(ip,expected):
        deadline=time.monotonic()+15
        while True:
            try:query(ip,expected);query(ip,expected,tcp=True);return
            except (OSError,AssertionError):
                if time.monotonic()>deadline: raise
                time.sleep(.1)
    def state(worker):
        r=worker.operate('read');v=worker.container(r)
        return {'id':v['Id'],'started':v['State']['StartedAt'],'file':r['file'],'directory':r['asset_directory']}
    try:
        image_record=docker.request('GET','/images/'+image+'/json')
        if image_record['Id']!=image or image_record.get('Config',{}).get('Volumes'):raise RuntimeError('image proof differs')
        if docker.request('GET','/networks/'+name,missing_ok=True): raise RuntimeError('fixture network occupied')
        save();network_id=docker.request('POST','/networks/create',payload)['Id'];intent['network_id']=network_id;save()
        configs=[]
        for i,suffix in enumerate(('control','test')):
            cfg={'lab':lab+'-'+suffix,'generation':uuid.uuid4().hex,'name':'drsp-dns-'+token+'-'+suffix,'image':image,
                 'network':{'name':name,'bridge':bridge,'subnet':'198.19.234.0/24','gateway':'198.19.234.1'},
                 'ip':'198.19.234.'+str(i+2),'upstream':['192.0.2.53']}
            configs.append(cfg);workers.append(Worker(cfg['lab'],directory=root/'journal'))
            intent['labs'].append(cfg);save()
        control,test=workers
        control_record=control.operate('ensure',configs[0],'192.0.2.10 fixture.test\n')
        probe=subprocess.run(['docker','exec','--user','nobody',control_record['container_id'],'cat','/etc/dnlab-dns/hosts'],capture_output=True,text=True)
        report['unprivileged_asset_probe']={'rc':probe.returncode,'stdout':probe.stdout,'stderr':probe.stderr};save()
        if probe.returncode:raise RuntimeError('DNS unprivileged asset read failed: '+probe.stderr)
        wait_query(configs[0]['ip'],'192.0.2.10');before=state(control)
        fault={'armed':True}
        def lost_create(argv,**kwargs):
            result=execute(argv,**kwargs)
            if fault['armed'] and argv[:2]==['docker','create']:
                fault['armed']=False;raise RuntimeError('injected lost create response')
            return result
        test.run=lost_create
        try:test.operate('ensure',configs[1],'192.0.2.20 fixture.test\n')
        except RuntimeError as error:
            if str(error)!='injected lost create response':raise
        else:raise RuntimeError('create injection missed')
        original=test.operate('recover')['container_id'];wait_query(configs[1]['ip'],'192.0.2.20')
        checks.append('original birth recovered after lost create response; UDP and TCP DNS answers')
        test.run=execute
        def lost_hup(argv,**kwargs):
            result=execute(argv,**kwargs)
            if argv[:4]==['docker','kill','--signal','HUP']:raise RuntimeError('injected lost HUP response')
            return result
        test.run=lost_hup
        try:test.operate('reload',content='192.0.2.21 fixture.test\n')
        except RuntimeError as error:
            if str(error)!='injected lost HUP response':raise
        else:raise RuntimeError('reload injection missed')
        test.run=execute;test.operate('recover');wait_query(configs[1]['ip'],'192.0.2.21')
        assert test.read()['container_id']==original and state(control)==before
        wait_query(configs[0]['ip'],'192.0.2.10')
        checks.append('atomic hosts update and HUP retry preserve generation; control unchanged')
        dns.PATHS=dataclasses.replace(dns.PATHS,dns_journal_dir=str(root/'journal'))
        class Transport:
            def run_input(self,command,payload,timeout):
                result=subprocess.run(shlex.split(command),input=payload,text=True,capture_output=True,timeout=timeout)
                if result.returncode:raise RuntimeError('standalone DNS transport: '+result.stderr[-2000:])
                return result.stdout
        transport=Transport()
        assert dns._guard(transport,test.lab,'preflight')['container_id']==original
        dns.preflight_dns_cleanup(test.lab,transport,configs[1]['generation'])
        dns.destroy_dns(test.lab,transport,configs[1]['generation'])
        dns.verify_dns_cleaned(test.lab,transport,configs[1]['generation'])
        checks.append('actual standalone stdin worker, qualified coordinator cleanup and cleaned verification')
        assert state(control)==before
        checks.append('ordinary SIGTERM shutdown and ID-bound removal; control DNS retained')
        report['status']='passed';save()
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error))
        report['diagnostics']=[]
        for worker in workers:
            try:
                with worker.locked():record=worker.read()
                if record and record.get('container_id'):
                    value=worker.container(record)
                    report['diagnostics'].append({'lab':worker.lab,'state':value['State'] if value else None,
                        'logs':subprocess.run(['docker','logs',record['container_id']],capture_output=True,text=True).stderr if value else ''})
            except Exception as diagnostic:report['diagnostics'].append({'error':str(diagnostic)})
        save();raise
    finally:
        errors=[]
        for worker in reversed(workers):
            try:
                worker.run=execute
                with worker.locked():record=worker.read()
                if record:worker.operate('delete');worker.operate('verify-cleaned')
            except Exception as error:errors.append(str(error))
        if network_id and not errors:
            try:
                value=docker.request('GET','/networks/'+network_id,missing_ok=True)
                if value:
                    if value.get('Labels')!=payload['Labels'] or value.get('Containers') or value['Name']!=name:
                        raise RuntimeError('fixture network ownership/occupancy differs')
                    docker.request('DELETE','/networks/'+network_id)
                assert docker.request('GET','/networks/'+name,missing_ok=True) is None
            except Exception as error:errors.append(str(error))
        report['cleanup']={'verified':not errors,'errors':errors}
        report['source_sha256']=hashlib.sha256(Path(sys.modules[Worker.__module__].__file__).read_bytes()).hexdigest()
        save()
        if errors:raise RuntimeError('DNS fixture cleanup pending: '+repr(errors))
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true')
    parser.add_argument('--image',required=True);parser.add_argument('--output',required=True);args=parser.parse_args()
    if not args.execute:parser.error('--execute required')
    print(json.dumps(run(args.output,args.image),indent=2))
