#!/usr/bin/env python3
"""Isolated DHCP refresh/recovery/replay guard with two management attachments."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import uuid

from jumphost_identity_smoke import run, execute
from jumphost_segments_smoke import attachment_gate
from jumphost_dhcp_smoke import content, service_gate
from dnlab_multinode.services.jumphost_host import JumphostError, MUTATE_PROGRAM, canonical


def preflight_gate(root, configs, workers, report):
    # First qualify actual offers, unchanged process, lost-HUP acknowledgement
    # recovery and the standalone worker with the additional L2 present.
    service_gate(root, configs, workers, report)
    control,test=workers;control_before=control.operate('read')
    original=test.operate('read');row=deepcopy(original['management_attachments']['blue'])
    service=test.dhcp_service(original);directory=test.dhcp_directory(original)
    fixture={'host':row['host'],'context':row['context'],'temporary_alias':row['alias']+'-canary',
             'restored':True,'cases':[]}
    def save():
        path=root/'dhcp-preflight-canary.json';temporary=root/'.dhcp-preflight-canary'
        with temporary.open('w') as stream:
            json.dump(fixture,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path);test.sync_asset_directory(root)
    def alias(changed):
        expected=deepcopy(row['host'])
        if not changed:expected['ifalias']=fixture['temporary_alias']
        fixture['restored']=False;save()
        payload={'context':row['context'],'link':expected,'operation':'alias',
                 'value':fixture['temporary_alias'] if changed else row['alias']}
        execute(['python3','-c',MUTATE_PROGRAM,canonical(payload)])
        fixture['restored']=not changed;save()
    def files():
        return {p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in directory.iterdir()}
    original_signal=signal.pidfd_send_signal;signals=[]
    def tracked(fd,value,*args):
        signals.append(int(value));return original_signal(fd,value,*args)
    signal.pidfd_send_signal=tracked
    try:
        for index,phase in enumerate(('fresh','recover','replay','before-hup'),14):
            request={'container':configs[1]['name'],'generation':configs[1]['generation'],
                     'request_id':uuid.uuid4().hex,'content':content('198.19.231.'+str(index),'192.0.2.55')}
            original_service=test.dhcp_service;original_run=test.run
            if phase=='recover':
                def lost_ack(record,action='inspect',expected=None):
                    result=original_service(record,action,expected)
                    if action=='reload':raise RuntimeError('injected lost DHCP acknowledgement')
                    return result
                test.dhcp_service=lost_ack
                try:test.operate('dhcp-refresh',request)
                except RuntimeError as error:
                    if str(error)!='injected lost DHCP acknowledgement':raise
                else:raise AssertionError('missing lost acknowledgement')
                finally:test.dhcp_service=original_service
            elif phase=='replay':test.operate('dhcp-refresh',request)
            before=files();signal_count=len(signals);armed=[phase=='before-hup']
            if armed[0]:
                def after_syntax(argv,**kwargs):
                    result=original_run(argv,**kwargs)
                    if armed[0] and argv[:2]==['docker','exec'] and argv[3:5]==['dnsmasq','--test']:
                        armed[0]=False;alias(True)
                    return result
                test.run=after_syntax
            else:alias(True)
            try:
                try:test.operate('recover' if phase=='recover' else 'dhcp-refresh',None if phase=='recover' else request)
                except JumphostError as error:rejection=str(error)
                else:raise AssertionError('unqualified additional attachment accepted: '+phase)
                assert not armed[0]
                assert len(signals)==signal_count,'unexpected signal on attachment conflict'
                if phase!='before-hup':assert files()==before,'assets changed despite initial conflict'
                assert test.dhcp_service(test.read())==service
                if phase in ('recover','before-hup'):assert test.read()['phase']=='recovery_required'
                case={'phase':phase,'rejection':rejection,'signals_sent_on_conflict':len(signals)-signal_count,
                      'assets_unchanged_on_initial_conflict':files()==before,'service_unchanged':True}
                fixture['cases'].append(case);save()
            finally:
                test.run=original_run
                if not fixture['restored']:alias(False)
            result=test.operate('recover' if phase in ('recover','before-hup') else 'dhcp-refresh',
                                None if phase in ('recover','before-hup') else request)
            assert result['phase']=='active' and result['container_id']==original['container_id']
            assert test.dhcp_service(result)==service
            assert control.operate('read')==control_before
            case['qualified_retry_active']=True;save()
        report['dhcp_additional_preflight']=fixture
        report['checks'].append('additional L2 alias conflict blocks fresh/recovery/replay and pre-HUP boundary; no signal on conflict; qualified retry preserves original daemon/container and control lab')
    finally:
        signal.pidfd_send_signal=original_signal
        if not fixture['restored']:alias(False)


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--image',required=True);parser.add_argument('--plugin-sha256',required=True)
    parser.add_argument('--output',required=True);args=parser.parse_args()
    print(run(args.image,args.plugin_sha256,args.output,dhcp_config=content,
              attachment_gate=attachment_gate,service_gate=preflight_gate))
