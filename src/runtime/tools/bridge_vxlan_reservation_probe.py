"""Exercise exclusive bridge/VXLAN source use inside the existing fixture."""
from dnlab_runtime.link_identity import VxlanIdentity
from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vxlan import VxlanManager


def probe(report,manager,executor,identities,sources,*,root,names,worker_image=None):
    linux=manager.linux
    executor.run(['ip','link','add','reserve-under','type','dummy'])
    executor.run(['ip','address','add','198.18.206.1/24','dev','reserve-under'])
    executor.run(['ip','link','set','dev','reserve-under','up'])
    name=sources['b'][0]['ifname']
    executor.run(['tc','qdisc','add','dev',name,'clsact'])
    vxlan=VxlanManager(manager.journal,linux)
    identity=VxlanIdentity(identities['b'].lab_id,'reservation-probe',name,3010)
    arguments={'source':sources['b'][0],'underlay':'reserve-under','local':'198.18.206.1','remote':'198.18.206.2','mtu':1450}
    manager.create(identities['a'],sources=sources['a'],mtu=1450)
    other=manager.row(identities['a'].digest)['payload']
    def create_bridge(*,conflict=False):
        if not worker_image:
            manager.create(identities['b'],sources=sources['b'],mtu=1450)
            return
        from dataclasses import asdict
        import hashlib,importlib
        from pathlib import Path
        from bridge_crash_probe import MODULES,run_worker
        config={'namespace':names['host'],'journal':str(root/'state'),'identity':asdict(identities['b']),
                'arguments':{'sources':sources['b'],'mtu':1450},'action':'create','executor_image':worker_image,
                'expected_core_hashes':{name:hashlib.sha256(Path(importlib.import_module('dnlab_runtime.'+name).__file__).read_bytes()).hexdigest() for name in MODULES}}
        result=run_worker(root/('reservation-conflict.json' if conflict else 'reservation-create.json'),config)
        if conflict:
            assert result.returncode!=0 and 'source reserved by another local link' in result.stderr
            report['image_reservation_conflict_rejected']=True
            raise Conflict('source reserved by another local link')
        assert result.returncode==0,result.stderr
    try:
        vxlan.create(identity,**arguments)
        payload=vxlan.row(identity.digest)['payload'];count=len(executor.commands)
        try:create_bridge(conflict=True)
        except Conflict as error:assert str(error)=='source reserved by another local link'
        else:raise AssertionError('bridge accepted active VXLAN endpoint')
        assert len(executor.commands)==count
        vxlan.verify(identity,payload);manager.verify(identities['a'],other)
        vxlan.delete(identity)
        create_bridge()
        payload=manager.row(identities['b'].digest)['payload'];count=len(executor.commands)
        try:vxlan.create(identity,**arguments)
        except Conflict as error:assert str(error)=='source reserved by another local link'
        else:raise AssertionError('VXLAN accepted active bridge endpoint')
        assert len(executor.commands)==count
        manager.verify(identities['b'],payload);manager.verify(identities['a'],other)
        manager.delete(identities['b'])
        vxlan.create(identity,**arguments);vxlan.verify(identity,vxlan.row(identity.digest)['payload'])
        vxlan.delete(identity)
        assert manager.clsact(name) and not linux.filters(name)
        executor.run(['tc','qdisc','del','dev',name,'clsact'])
        report['shared_endpoint_reservations']={'status':'passed','checks':[
            'bridge rejects active VXLAN before kernel mutation','VXLAN rejects active bridge before kernel mutation',
            'original link and other lab remain verified','explicit delete/create permits transport change',
            'preexisting clsact preserved','both primitive journals cleaned']}
    finally:
        manager.delete(identities['a'])
