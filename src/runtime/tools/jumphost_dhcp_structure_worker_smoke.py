#!/usr/bin/env python3
"""Isolated worker recovery of stopped DHCP asset writes; no service restart."""
import argparse
import os
import uuid
from unittest.mock import patch

from jumphost_identity_smoke import run
from jumphost_dhcp_smoke import content
from dhcp_process_birth_smoke import save_json
from dnlab_multinode.services.jumphost_host import DHCPHostService, JournaledDHCPStop


def service_gate(root,configs,workers,report):
    control,worker=workers;control_before=control.operate('read');record=worker.operate('read')
    with worker.namespace(record) as fd:
        with DHCPHostService(worker,record,fd) as service:original=service.observe()
    stop_path=root/'dhcp-structural-stop.json'
    intent={'id':uuid.uuid4().hex,'service':original,'phase':'intent','attempted':False,'receipt':None}
    save_json(stop_path,intent)
    def probe(expected):
        with worker.namespace(record) as fd:
            with DHCPHostService(worker,record,fd) as service:return service.shutdown_status(expected)
    def stop(expected):
        with worker.namespace(record) as fd:
            with DHCPHostService(worker,record,fd) as service:return service.stop(expected)
    receipt=JournaledDHCPStop(intent,lambda:save_json(stop_path,intent),probe,stop).run()
    request={'container':record['config']['name'],'generation':record['config']['generation'],
        'request_id':uuid.uuid4().hex,'content':content('198.19.231.12','198.19.231.54').replace('12h','24h')}
    old={name:dict(row['identity']) for name,row in record['dhcp_assets']['files'].items()}
    with worker.locked():worker.begin_dhcp_structure_assets(record,request,receipt)
    original_pwrite=os.pwrite;armed=[True];inode=old['main']['inode']
    def interrupted(fd,data,offset):
        if os.fstat(fd).st_ino==inode and armed[0]:
            armed[0]=False;original_pwrite(fd,data[:max(1,len(data)//2)],offset)
            raise OSError('injected partial main pwrite reply loss')
        return original_pwrite(fd,data,offset)
    try:
        with patch.object(os,'pwrite',interrupted):
            with worker.locked():worker.write_dhcp_structure_assets(record)
    except OSError as error:
        if str(error)!='injected partial main pwrite reply loss':raise
    else:raise AssertionError('partial main fault not exercised')
    record=worker.read();save_json(root/'dhcp-structural-partial.json',record['dhcp_structure'])
    before=worker.path.read_bytes();worker.dhcp_preflight(record)
    assert before==worker.path.read_bytes(),'readonly partial preflight saved journal'
    with worker.locked():committed=worker.write_dhcp_structure_assets(record)
    worker.dhcp_preflight(record)
    assert record['phase']=='dhcp_structure_pending'
    assert record['dhcp_structure']['assets']['phase']=='ready'
    assert {name:row['identity'] for name,row in committed.items()}==old
    assert worker.dhcp_structure_closed(record,original)['service_exit']==receipt
    with worker.locked():assert worker.write_dhcp_structure_assets(record)==committed
    assert control.operate('read')==control_before
    assert worker.container(record)['Id']==original['container']['id']
    assert worker.container(record)['State']['StartedAt']==original['container']['started_at']
    save_json(root/'dhcp-structural-ready.json',worker.read()['dhcp_structure'])
    report['dhcp_worker_assets']={'partial_write_reopened':True,'readonly_full_preflight':True,
        'all_files_ready':True,'original_inodes':True,'retry_unchanged':True,
        'original_exit_reverified_after_main_change':True,'container_preserved':True,
        'control_preserved':True,'daemon_restarted':False,'phase':record['phase']}
    report['checks'].append('worker-bound partial structural main recovery; full attachment preflight and original exit reverified after three-file commit; still pending, no restart/readiness claim')


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True)
    parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args()
    print(run(args.image,args.plugin_sha256,args.output,dhcp_config=content,service_gate=service_gate))
