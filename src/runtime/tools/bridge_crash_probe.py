"""Dedicated bridge workers: real SIGKILL and WAL recovery, optionally in Docker."""
import argparse
from dataclasses import asdict
import hashlib
import importlib
import json
from pathlib import Path
import signal
import subprocess
import sys

sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from dnlab_runtime.bridge import BridgeLinux,BridgeManager
from dnlab_runtime.bridge_identity import BridgeIdentity
from dnlab_runtime.journal import Journal
from vxlan_crash_probe import CrashLinux,checkpoint
from vxlan_smoke import NamespaceLinux,ping,frame_probe

MODULES=('backend','vxlan','journal','bridge','bridge_identity','endpoint_reservations')


def mutation(argv):
    return (argv[:2]==['ip','link'] and argv[2] in ('add','set','delete')
            or argv[:2] in (['tc','filter'],['tc','qdisc']) and argv[2] in ('add','del')
            or argv[:2] in (['iptables','-I'],['iptables','-D']))


class BridgeCrashLinux(CrashLinux):
    def run(self,argv,**kwargs):
        mutating=mutation(argv)
        if mutating:
            self.mutations+=1;self.crash(argv,'before')
        result=NamespaceLinux.run(self,argv,**kwargs)
        if mutating:self.crash(argv,'after')
        return result


def worker(path):
    config=json.loads(path.read_text())
    if not config['namespace'].startswith('drsp-cbr-') or not config['identity']['lab_id'].startswith('bridge-fixture-'):
        raise ValueError('isolated bridge fixture required')
    metadata={}
    for name in MODULES:
        source=Path(importlib.import_module('dnlab_runtime.'+name).__file__)
        metadata[name]={'path':str(source),'sha256':hashlib.sha256(source.read_bytes()).hexdigest()}
        if metadata[name]['sha256']!=config['expected_core_hashes'][name]:
            raise ValueError('runtime source digest mismatch: '+name)
        if config.get('executor_image') and source.is_relative_to(Path(__file__).resolve().parents[1]):
            raise ValueError('image worker imported host runtime source')
    config['runtime_metadata']=metadata
    journal=Journal(Path(config['journal']))
    try:
        manager=BridgeManager(journal,BridgeLinux(BridgeCrashLinux(config)))
        identity=BridgeIdentity(**config['identity'])
        if config['action']=='create':manager.create(identity,**config['arguments'])
        elif config['action'] in ('delete','recover'):manager.delete(identity)
        else:raise ValueError('unknown worker action')
        print(json.dumps({'phase':manager.row(identity.digest)['phase'],'runtime_metadata':metadata}))
    finally:journal.close()


def run_worker(path,config):
    checkpoint(path,config)
    if config.get('executor_image'):
        from vxlan_container_worker import run_image_worker
        return run_image_worker(path,config,harness='bridge_crash_probe.py')
    return subprocess.run([sys.executable,str(Path(__file__).resolve()),'--execute','--config',str(path)],
                          text=True,capture_output=True,timeout=20)


def probe(root,report,names,manager,identities,sources,*,worker_image=None):
    records=report['crash_recovery']=[]
    identity=identities['b'];key=identity.digest
    config={'namespace':names['host'],'journal':str(root/'state'),'identity':asdict(identity),
            'arguments':{'sources':sources['b'],'mtu':1450},
            'expected_core_hashes':{name:hashlib.sha256(Path(importlib.import_module('dnlab_runtime.'+name).__file__).read_bytes()).hexdigest() for name in MODULES}}
    if worker_image:
        config['executor_image']=worker_image;report['worker_image']=worker_image
    manager.create(identities['a'],sources=sources['a'],mtu=1450)
    other=manager.row(identities['a'].digest)['payload']
    try:
        created=run_worker(root/'worker-create.json',dict(config,action='create'))
        assert created.returncode==0,created.stderr
        report['worker_create']=json.loads(created.stdout)
        manager.verify(identity,manager.row(key)['payload'])
        report['worker_traffic']=ping(names['b1'],'198.19.204.2')
        report['worker_frames']={protocol:frame_probe(names['b1'],names['b2'],destination,ethertype)
                                for protocol,destination,ethertype in [('lldp','0180c200000e','88cc'),('lacp','0180c2000002','8809')]}
        deleted=run_worker(root/'worker-delete.json',dict(config,action='delete'))
        assert deleted.returncode==0,deleted.stderr
        report['worker_delete']=json.loads(deleted.stdout)
        for action,count in [('create',13),('delete',11)]:
            for position in range(1,count+1):
                for when in ('before','after'):
                    case=f'{action}-{position}-{when}'
                    record={'case':case,'status':'running'};records.append(record)
                    checkpoint(root/'report.json',report)
                    if action=='delete':manager.create(identity,**config['arguments'])
                    trace=root/(case+'-trace.json')
                    killed=run_worker(root/(case+'.json'),dict(config,action=action,trace=str(trace),crash_mutation=position,crash_when=when))
                    assert killed.returncode==(137 if worker_image else -signal.SIGKILL),f'{case}: {killed.stdout} {killed.stderr}'
                    record['trace']=json.loads(trace.read_text())
                    record['interrupted_phase']=manager.row(key)['phase']
                    assert record['interrupted_phase']==('creating' if action=='create' else 'deleting')
                    recovered=run_worker(root/(case+'-recover.json'),dict(config,action='recover'))
                    assert recovered.returncode==0,f'{case}: {recovered.stdout} {recovered.stderr}'
                    record['recovery']=json.loads(recovered.stdout)
                    assert record['recovery']['phase']=='cleaned' and manager.row(key)['phase']=='cleaned'
                    assert manager.bridge(identity,manager.row(key)['payload']) is None
                    for source in sources['b']:
                        assert not manager.linux.filters(source['ifname'])
                        assert not manager.linux.filters(source['ifname'],'egress')
                        assert not manager.clsact(source['ifname'])
                    manager.verify(identities['a'],other)
                    record['status']='passed';checkpoint(root/'report.json',report)
        report['other_lab_traffic']=ping(names['a1'],'198.19.204.2')
        if worker_image:
            entries=json.loads((root/'worker-containers.json').read_text())
            assert all(entry['phase']=='removed' for entry in entries)
            report['image_packaging_qualified']=True
    finally:
        manager.delete(identities['a'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true');parser.add_argument('--config',type=Path)
    args=parser.parse_args()
    if not args.execute or args.config is None:parser.error('requires --execute --config')
    worker(args.config)
