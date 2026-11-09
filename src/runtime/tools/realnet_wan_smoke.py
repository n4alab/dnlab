#!/usr/bin/env python3
"""Dedicated Docker WAN fixture; no existing network is modified or adopted."""
import argparse
import json
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import uuid

SOURCE=Path(__file__).resolve().parents[2];sys.path[:0]=[str(SOURCE/'multinode')]
from dnlab_multinode.services.realnet_wan_host import Worker,WANError


def run(image):
    root=Path(tempfile.mkdtemp(prefix='dnlab-realnet-wan-'));root.chmod(0o700)
    token=uuid.uuid4().hex[:6];cases=[];container=None
    report={'status':'running','scope':'dedicated shared-WAN ownership/recovery; no production network mutation','crashes':[]}
    def command(args):
        result=subprocess.run(args,text=True,capture_output=True,timeout=45)
        if result.returncode:raise RuntimeError('fixture command failed: '+args[0]+' '+result.stderr.strip())
        return result.stdout
    def inventory():return sorted(v['ID'] for v in (json.loads(line) for line in command(['docker','network','ls','--no-trunc','--format','{{json .}}']).splitlines()))
    baseline=inventory()
    def make(index):
        value={'network':'drsp-wan-'+token+'-'+str(index),'bridge':'drspw'+token+str(index),
               'subnet':f'198.19.{128+(int(token[:2],16)%12)*8+index}.0/24','gateway':f'198.19.{128+(int(token[:2],16)%12)*8+index}.1'}
        worker=Worker(value,directory=root/str(index),run=command);cases.append(worker);return worker
    def selected(worker):
        value=worker.network();bridge=worker.bridge()
        return {'Id':value['Id'],'Created':value['Created'],'IPAM':value['IPAM'],'Options':value['Options'],'Labels':value['Labels'],
                'bridge':worker.signature(bridge)}
    try:
        control=make(0);control.operate();before=selected(control);journal=control.path.read_bytes()
        identity=command(['docker','run','--pull','never','-d','--network',control.config['network'],'--name','drsp-wan-'+token+'-vd',
                          '--label','org.dnlab.fixture='+token,'--entrypoint','python3',image,'-c','import time;time.sleep(3600)']).strip()
        container=json.loads(command(['docker','inspect',identity]))[0]
        assert container['Config']['Labels']=={'org.dnlab.fixture':token}
        control.operate();assert selected(control)==before and control.path.read_bytes()==journal
        command(['nsenter','-t',str(container['State']['Pid']),'-n','ping','-c','1','-W','2',control.config['gateway']])
        for index,(stage,when) in enumerate([(s,w) for s in ('intent','create','active') for w in ('before','after')],start=1):
            worker=make(index)
            def child():
                def kernel(args):
                    mutation=args[:3]==['docker','network','create']
                    if mutation and stage=='create' and when=='before':os.kill(os.getpid(),signal.SIGKILL)
                    output=command(args)
                    if mutation and stage=='create' and when=='after':os.kill(os.getpid(),signal.SIGKILL)
                    return output
                child_worker=Worker(worker.config,directory=worker.directory,run=kernel);original=child_worker.save
                def save(record):
                    match=(stage=='intent' and record['phase']=='creating') or (stage=='active' and record['phase']=='active')
                    if match and when=='before':os.kill(os.getpid(),signal.SIGKILL)
                    original(record)
                    if match and when=='after':os.kill(os.getpid(),signal.SIGKILL)
                child_worker.save=save;child_worker.operate()
            process=multiprocessing.get_context('fork').Process(target=child);process.start();process.join(40)
            if process.is_alive():process.kill();process.join();raise RuntimeError('owned WAN worker timeout')
            assert process.exitcode==-signal.SIGKILL
            existed=worker.network();record=worker.read()
            if record is None:assert existed is None;worker.operate()
            else:worker.operate('recover')
            if existed:assert worker.network()['Id']==existed['Id']
            worker.preflight();stable=selected(worker);body=worker.path.read_bytes();worker.operate()
            assert selected(worker)==stable and worker.path.read_bytes()==body
            assert selected(control)==before and control.path.read_bytes()==journal
            report['crashes'].append({'stage':stage,'when':when,'recovered':True,'id':worker.network()['Id']})
        # Foreign existing network is inspected through a mismatching config;
        # refusing it must preserve the active control network and its member.
        incompatible=dict(control.config,subnet='203.0.113.0/24',gateway='203.0.113.1')
        try:Worker(incompatible,directory=root/'incompatible',run=command).operate()
        except WANError:pass
        else:raise RuntimeError('incompatible shared WAN accepted')
        assert selected(control)==before;control.preflight()
        command(['nsenter','-t',str(container['State']['Pid']),'-n','ping','-c','1','-W','2',control.config['gateway']])
        report.update(status='passed',active_reuse_read_only=True,control_preserved=True,gateway_reachable=True,incompatible_refused=True)
    except Exception as error:
        report['status']='failed';report['error']=str(error)
        report['network_diagnostics']=[]
        for worker in cases:
            try:report['network_diagnostics'].append({'config':worker.config,'record':worker.read(),'network':worker.network(),'bridge':worker.bridge()})
            except Exception as diagnostic:report['network_diagnostics'].append({'diagnostic_error':str(diagnostic)})
        raise
    finally:
        try:
            if container:
                value=json.loads(command(['docker','inspect',container['Id']]))[0]
                assert value['Id']==container['Id'] and value['Image']==container['Image'] and value['Config']['Labels']=={'org.dnlab.fixture':token}
                if value['State']['Running']:command(['docker','kill','--signal','KILL',container['Id']])
                command(['docker','wait',container['Id']]);command(['docker','rm',container['Id']])
            for worker in reversed(cases):
                value=worker.network()
                if value:
                    record=worker.read()
                    assert record and value['Labels']==worker.labels(record) and value['Name']==worker.config['network'] and not value['Containers']
                    identity=value['Id'];command(['docker','network','rm',identity]);assert worker.network() is None
                assert worker.bridge() is None
            report['cleanup_verified']=inventory()==baseline
        except Exception as error:report['cleanup_verified']=False;report['cleanup_error']=str(error)
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
        print(json.dumps({'report':str(root/'report.json'),'status':report['status'],'cleanup_verified':report.get('cleanup_verified')}))
    if not report.get('cleanup_verified'):raise RuntimeError('fixture cleanup incomplete')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--execute',action='store_true');parser.add_argument('--image',required=True);args=parser.parse_args()
    if not args.execute:parser.error('explicit --execute required')
    run(args.image)
