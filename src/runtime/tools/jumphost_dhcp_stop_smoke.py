#!/usr/bin/env python3
"""Isolated real host-probe recovery after DHCP exit but before receipt commit."""
import argparse
import json
import uuid

from jumphost_identity_smoke import run
from jumphost_dhcp_smoke import content
from dhcp_process_birth_smoke import save_json
from dnlab_multinode.services.jumphost_host import DHCPHostService, JournaledDHCPStop


def service_gate(root, configs, workers, report):
    control,test=workers;control_before=control.operate('read');record=test.operate('read')
    with test.namespace(record) as fd:
        with DHCPHostService(test,record,fd) as service:original=service.observe()
    path=root/'dhcp-stop-operation.json'
    intent={'id':uuid.uuid4().hex,'service':original,'phase':'intent','attempted':False,'receipt':None}
    save_json(path,intent);signals=[0];armed=[True]
    def probe(expected):
        with test.namespace(record) as fd:
            with DHCPHostService(test,record,fd) as service:return service.shutdown_status(expected)
    def stop(expected):
        signals[0]+=1
        with test.namespace(record) as fd:
            with DHCPHostService(test,record,fd) as service:receipt=service.stop(expected)
        save_json(root/'dhcp-exit-before-commit.json',receipt)
        if armed[0]:armed[0]=False;raise RuntimeError('injected exit receipt reply loss')
        return receipt
    try:
        try:JournaledDHCPStop(intent,lambda:save_json(path,intent),probe,stop).run()
        except RuntimeError as error:
            if str(error)!='injected exit receipt reply loss':raise
        else:raise AssertionError('exit receipt fault not exercised')
        persisted=json.loads(path.read_text())
        assert persisted['phase']=='stopping' and persisted['attempted'] and persisted['receipt'] is None
        intent=persisted
        receipt=JournaledDHCPStop(intent,lambda:save_json(path,intent),probe,stop).run()
        assert intent['phase']=='stopped' and intent['receipt']==receipt
        assert JournaledDHCPStop(intent,lambda:save_json(path,intent),probe,stop).run()==receipt
        assert signals[0]==1,'recovery/replay sent another TERM'
        assert test.container(record)['State']['StartedAt']==original['container']['started_at']
        assert test.container(record)['Id']==original['container']['id']
        assert control.operate('read')==control_before
        report['dhcp_shutdown_recovery']={'service':original,'stop_id':intent['id'],
            'phase':intent['phase'],'stop_calls':signals[0],'receipt_lost_after_exit':True,
            'journal_reopened':True,'replay_reverified_exit':True,'container_preserved':True,
            'control_preserved':True,'daemon_restart_attempted':False}
        report['checks'].append('actual host shutdown probe; lost receipt after verified TERM exit; durable stop recovery/replay without another signal, daemon/container restart or control change')
    except Exception as error:
        save_json(root/'dhcp-stop-failure.json',{'error_type':type(error).__name__,'error':str(error),
            'stop_calls':signals[0],'journal':json.loads(path.read_text())})
        raise


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--image',required=True)
    parser.add_argument('--plugin-sha256',required=True);parser.add_argument('--output',required=True)
    args=parser.parse_args()
    print(run(args.image,args.plugin_sha256,args.output,dhcp_config=content,service_gate=service_gate))
