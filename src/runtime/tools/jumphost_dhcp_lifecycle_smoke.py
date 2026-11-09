#!/usr/bin/env python3
"""Isolated structural DHCP stop/write/exec recovery, retaining the offline fence."""
import argparse
import uuid

from jumphost_identity_smoke import run
from jumphost_dhcp_smoke import content
from dhcp_process_birth_smoke import save_json
from dnlab_multinode.services.jumphost_host import DockerExecHTTP, JumphostError


def service_gate(root,configs,workers,report,*,finalize_readiness=False):
    control,worker=workers;control_before=control.operate('read');record=worker.operate('read')
    request={'container':record['config']['name'],'generation':record['config']['generation'],
        'request_id':uuid.uuid4().hex,'content':content('198.19.231.12','198.19.231.54').replace('12h','24h')}
    before={name:dict(row['identity']) for name,row in record['dhcp_assets']['files'].items()}
    with worker.locked():worker.begin_dhcp_structural_operation(record,request)
    save_json(root/'dhcp-lifecycle-intent.json',record['dhcp_structural_operation'])
    stop=worker.dhcp_structural_stop;stops=[0];stop_fault=[True]
    def interrupted_stop(current,expected):
        stops[0]+=1;receipt=stop(current,expected)
        if stop_fault[0]:stop_fault[0]=False;raise JumphostError('injected stop receipt loss')
        return receipt
    worker.dhcp_structural_stop=interrupted_stop
    class Replies:
        def __init__(self):self.docker=DockerExecHTTP();self.faults={'create':True,'start':True};self.creates=0;self.starts=0
        def call(self,method,path,payload=None,**kwargs):
            stage='create' if method=='POST' and path.endswith('/exec') else 'start' if method=='POST' and path.endswith('/start') else None
            if stage=='create':self.creates+=1
            if stage=='start':self.starts+=1
            result=self.docker.call(method,path,payload,**kwargs)
            if stage and self.faults[stage]:
                self.faults[stage]=False;raise JumphostError('injected '+stage+' reply loss')
            return result
    docker=Replies();recoveries=[]
    try:
        for stage in ('stop receipt','create reply','start reply'):
            record=worker.read()
            try:
                with worker.locked():worker.resume_dhcp_structural_operation(record,docker=docker)
            except JumphostError as error:
                if str(error)!='injected '+stage+' loss':raise
                recoveries.append(stage)
                persisted=worker.read()
                save_json(root/('dhcp-lifecycle-'+stage.replace(' ','-')+'.json'),persisted['dhcp_structural_operation'])
            else:raise AssertionError('expected fault not exercised: '+stage)
        record=worker.read()
        with worker.locked():service=worker.resume_dhcp_structural_operation(record,docker=docker)
        assert record['phase']=='dhcp_structure_pending'
        assert record['dhcp_structural_operation']['phase']=='service-ready'
        assert {name:row['identity'] for name,row in record['dhcp_assets']['files'].items()}==before
        assert stops[0]==docker.creates==docker.starts==1
        old=record['dhcp_structural_operation']['original_service']
        assert service['container']==old['container'] and service['host_pid']!=old['host_pid']
        assert service['operation_nonce']==record['dhcp_structural_operation']['launch']['nonce']
        record=worker.read()
        with worker.locked():assert worker.resume_dhcp_structural_operation(record,docker=docker)==service
        assert stops[0]==docker.creates==docker.starts==1
        assert control.operate('read')==control_before
        save_json(root/'dhcp-lifecycle-service-ready.json',record['dhcp_structural_operation'])
        if finalize_readiness:
            save=worker.save;armed=[True]
            def uncertain_commit(current):
                save(current)
                if armed[0] and current['phase']=='active' and current.get('dhcp_expected_service')==service:
                    armed[0]=False;raise OSError('injected final commit reply loss')
            worker.save=uncertain_commit
            try:
                try:
                    with worker.locked():worker.finalize_dhcp_structural_operation(record,request)
                except OSError as error:
                    if str(error)!='injected final commit reply loss':raise
                else:raise AssertionError('final commit fault missed')
            finally:worker.save=save
            record=worker.read()
            with worker.locked():proof=worker.finalize_dhcp_structural_operation(record,request)
            assert proof['level']=='dhcp-listeners' and not proof['packet_readiness_verified']
            assert record['phase']=='active' and record['dhcp_expected_service']==service
            assert record['dhcp_service_nonce']==service['operation_nonce']
            save_json(root/'dhcp-lifecycle-readiness.json',proof)
            dynamic=dict(request,request_id=uuid.uuid4().hex,
                content=request['content'].replace('198.19.231.12','198.19.231.13'))
            updated=worker.operate('dhcp-refresh',dynamic)
            assert updated['phase']=='active' and worker.dhcp_service(updated)==service
            assert stops[0]==docker.creates==docker.starts==1
            assert control.operate('read')==control_before
            report['dhcp_listener_finalization']={'level':proof['level'],'listeners':proof['listeners'],
                'final_commit_reply_lost':True,'replay_qualified':True,'nonce_generation_preserved':True,
                'dynamic_refresh_on_committed_main':True,'phase':updated['phase'],
                'packet_readiness_verified':False,'coordinator_fence_released':False}
            report['checks'].append('DHCP listener ownership and committed config qualified; uncertain final commit replay; dynamic refresh on new main without daemon restart; coordinator fence not released')
        report['dhcp_structural_lifecycle']={'recoveries':recoveries,'stops':stops[0],
            'exec_creates':docker.creates,'exec_starts':docker.starts,'nonce_bound_new_service':True,
            'same_original_container':True,'original_asset_inodes':True,'control_preserved':True,
            'retry_same_generation':True,'phase':record['phase'],'service_phase':'listener-ready' if finalize_readiness else 'service-ready',
            'packet_readiness_verified':False,'coordinator_fence_released':False}
        report['checks'].append('whole structural intent before stop; lost stop/create/start replies recovered from worker journal; one new nonce-bound DHCP service in original helper; coordinator fence unreleased without packet-readiness claim')
    except Exception as error:
        current=worker.read()
        save_json(root/'dhcp-lifecycle-failure.json',{'error_type':type(error).__name__,'error':str(error),
            'operation':current.get('dhcp_structural_operation'),'assets':current.get('dhcp_structure'),
            'stops':stops[0],'creates':docker.creates,'starts':docker.starts})
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True)
    parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--output',required=True)
    parser.add_argument('--finalize-readiness',action='store_true');args=parser.parse_args()
    gate=lambda *values:service_gate(*values,finalize_readiness=args.finalize_readiness)
    print(run(args.image,args.plugin_sha256,args.output,dhcp_config=content,service_gate=gate))
