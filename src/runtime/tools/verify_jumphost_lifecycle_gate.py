#!/usr/bin/env python3
"""Read-only independent audit of one integrated local jumphost gate."""
import argparse
import hashlib
import json
from pathlib import Path
import sqlite3
import sys

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from dnlab_runtime.backend import Docker,Linux
from management_service_diagnostics import private_json
from jumphost_lifecycle_audit import audit_cli,audit_lifecycle,digest,require


def read(path):return json.loads(Path(path).read_text())


def database(path,tables):
    path=Path(path).resolve();wal=path.with_name(path.name+'-wal')
    require(not wal.exists() or wal.stat().st_size==0,'audit requires closed checkpointed SQLite journals')
    connection=sqlite3.connect(path.as_uri()+'?mode=ro&immutable=1',uri=True)
    connection.row_factory=sqlite3.Row
    try:
        connection.execute('BEGIN')
        return {name:[dict(row) for row in connection.execute('SELECT * FROM '+name)] for name in tables}
    finally:connection.close()


def exited(proof):
    try:
        fields=(Path('/proc')/str(proof['pid'])/'stat').read_text().rsplit(')',1)[1].split()
        return fields[19]!=proof['start'] or fields[0]=='Z'
    except FileNotFoundError:return True


def inventory(api):
    result={'containers':{},'networks':{}}
    for row in api.request('GET','/containers/json?all=1'):
        item=api.request('GET','/containers/'+row['Id']+'/json')
        result['containers'][row['Id']]={k:item[k] for k in ('Id','Name','Image')}
        result['containers'][row['Id']]['state']={k:item['State'][k] for k in ('Pid','StartedAt','Running')}
        result['containers'][row['Id']]['restart_count']=item['RestartCount']
    for row in api.request('GET','/networks'):
        item=api.request('GET','/networks/'+row['Id'])
        result['networks'][row['Id']]={k:item.get(k) for k in ('Name','Driver','IPAM','Options','Labels','Containers')}
    return result


def one(root,name):
    paths=list((root/name).glob('*.json'))
    require(len(paths)==1,'original '+name+' journal ambiguous')
    return read(paths[0])


def verify(root,*,api=None,linux=None):
    root=Path(root).resolve();preflight=root.with_name(root.name+'-preflight')
    api=api or Docker();linux=linux or Linux()
    recipe=read(preflight/'recipe.json');before=read(preflight/'protected-before.json')
    metadata=read(preflight/'preflight.json');report=read(root/'report.json')
    require(recipe['output']==str(root),'gate output identity differs')
    require(report['status']=='passed' and report['cleanup']['verified'] is True,'gate did not pass')
    coordinator=database(root/'.runtime-operations/operations.sqlite3',
                         ('operations','public_requests','management_barriers','initial_batches'))
    runtime=database(root/'runtime/state/journal.sqlite3',
                     ('operations','workload_generations','stop_sessions','journal_identity','nodes','management_network_proofs'))
    require(len(runtime['journal_identity'])==1,'runtime journal identity ambiguous')
    runtime['journal_id']=runtime['journal_identity'][0]['identity']
    history=read(root/'native-jumphost-lifecycle.json');lab=history['owner']['lab'];node=history['owner']['node']
    states=list(root.glob('.*.multinode.json'));require(len(states)==1,'public state ambiguous')
    public=read(states[0]);jump=one(root,'jump');dns=one(root,'dns');relay=one(root,'relay')
    config=read(root/'native-jumphost-stage-intent.json')
    require(jump['phase']==dns['phase']==relay['phase']=='cleaned','helper journal cleanup incomplete')
    require(relay['config']==config and relay['image']['Id']==recipe['images']['relay']
            and jump['image']['Id']==recipe['images']['jumphost']
            and dns['image']['Id']==recipe['images']['dns'],'helper original image/config differs')
    lifecycle=audit_lifecycle(history,coordinator,runtime,public,lab=lab,node=node,
                              ledger=root/'.runtime-operations',jumphost=jump,relay=config)
    plan=read(root/'native-jumphost-cli-plan.json')
    stems={'cli-'+label+'-'+action:(label,action) for label in ('before','after') for action in ('connect','log')}
    require(plan['lab']==lab and plan['generation']==config['generation']
            and set(plan['slots'])==set(stems) and len(set(plan['slots'].values()))==4,'four original CLI slots required')
    http=read(root/'managed-http-workload.json');cli=[];owner=None
    for stem,(_,action) in stems.items():
        asset=read(root/(stem+'-assets.json'));execution=read(root/(stem+'-exec.json'))
        capture=read(root/(stem+'-assets.output.json'))
        if owner is None:
            owner=asset['owner']
            require(all(owner[k]==jump[k] for k in ('config','image','nonce','container_id','context','namespace'))
                    and owner['process']['started_at']==jump['started_at']
                    and owner['process']['namespace']==[jump['namespace']['device'],jump['namespace']['inode']],
                    'original jumphost process binding differs')
        proof=audit_cli(asset,execution,capture,owner=owner,nonce=plan['slots'][stem],
                        action=action,node=node,workload_nonce=http['nonce'])
        current=api.request('GET','/exec/'+proof['id']+'/json',missing_ok=True)
        require(current is None or (current['ID']==proof['id'] and current['ContainerID']==jump['container_id']
                and current['Running'] is False and current['ExitCode']==0),'original CLI exec still active or replaced')
        cli.append(proof)
    require(len({v['id'] for v in cli})==4,'CLI exec IDs collide')
    require(report['native_jumphost_lifecycle']['cli_verified'] is True
            and report['native_jumphost_cleanup']['verified'] is True
            and set(report['native_jumphost_cleanup']['cli_exec_ids'])=={v['id'] for v in cli},'CLI report/cleanup receipt differs')
    relay_before=read(root/'native-relay-process-before.json');relay_after=read(root/'native-relay-process-after.json')
    require(relay_before==relay_after and relay_before['container_id']==relay['container_id']
            and report['native_jumphost_lifecycle']['relay_process_before']==relay_before
            and report['native_jumphost_lifecycle']['relay_process_after']==relay_after,'relay restarted during VD lifecycle')
    require(exited(relay_before) and exited(owner['process']) and exited(read(root/'native-runtime-process.json')),
            'original helper/runtime process remains live')
    barriers=coordinator['management_barriers'];require(len(barriers)==1,'management parent ambiguous')
    barrier=json.loads(barriers[0]['payload']);bundle=barrier['plan']['services']
    require(barrier['phase']=='released' and barrier['readiness_fingerprint']==digest(barrier['readiness'])
            and barrier['release_checks']=={'master':1}
            and barrier['readiness']['hosts']['master']['scope']=='management-network-services-v1',
            'original management service release differs')
    batches=coordinator['initial_batches'];require(len(batches)==1,'initial batch ambiguous')
    batch=batches[0];payload=json.loads(batch['payload']);published=report['initial_workload_publication']
    initial_request={k:v for k,v in history['births'][0]['request'].items() if k!='management_preflight'}
    require(batch['phase']=='completed' and not batch['cancel_requested'] and batch['fingerprint']==digest(payload)
            and len(payload['original'])==1 and payload['original'][0]['request']==initial_request
            and payload['management_parent']==http['admission']['parent']==published['original_management_parent']
            and payload['management_parent']['operation_fingerprint']==digest(barrier)
            and payload['compilation']['fingerprint']==http['admission']['compilation_fingerprint']
            and payload['compilation']['fingerprint']==digest({k:v for k,v in payload['compilation'].items() if k!='fingerprint'})
            and published['replay_unchanged'] is True and published['container_id']==history['births'][0]['container_id'],
            'original managed initial admission/publication differs')
    require(public['dnlab_deployed'] is False and public['jumphost']['generation']==bundle['jumphost']['generation']
            and public['jumphost']['ssh_port']==bundle['jumphost']['port']
            and public['dns']['generation']==bundle['dns']['config']['generation'],'public helper metadata differs')
    containers=set(lifecycle['original_ids']);containers.add(http['spec']['container_name'])
    networks=set();links=set();packet_execs=[]
    for directory in ('jump','dns','relay','external','management','probes'):
        for path in (root/directory).glob('*.json'):
            row=read(path);cfg=row.get('config',{})
            if directory in ('jump','dns','relay'):
                containers.update(v for v in (cfg.get('name'),row.get('container_id')) if v)
            if directory=='external':networks.update(v for v in (cfg.get('network'),row.get('id')) if v);links.add(cfg['bridge'])
            if directory=='management':
                require(row['phase']=='cleaned','management cleanup pending')
                links.update(row.get('resources',{}))
                for network in row.get('networks',{}).values():
                    networks.update(v for v in (network.get('id'),network.get('expected',{}).get('network')) if v)
            if directory=='probes':
                require(row['phase']=='cleaned','probe cleanup pending')
                key=digest(['management-probe-v1',row['request']]);containers.update(('dnlab-probe-'+key[:24],row['container_id']));links.add('dmp'+key[:12])
                operation=row.get('packet_execution') or {}
                if operation.get('id'):
                    current=api.request('GET','/exec/'+operation['id']+'/json',missing_ok=True)
                    require(operation.get('exit_verified') is True and operation.get('process') is not None,
                            'packet exec exit proof missing')
                    p=operation['process'];require(exited({'pid':p['host_pid'],'start':p['start']}),'original packet process remains live')
                    require(current is None or (current['ContainerID']==row['container_id'] and current['Running'] is False
                            and current['ExitCode']==operation['exit_code']),'packet exec still running or changed')
                    packet_execs.append(operation['id'])
            for value in [row]+list(row.get('management_attachments',{}).values()):
                if isinstance(value.get('host'),dict) and value['host'].get('ifname'):links.add(value['host']['ifname'])
    gui_db=database(root/'gui-client/journal.sqlite3',('nos_fixture_intents',))
    require(len(gui_db['nos_fixture_intents'])==1,'GUI original generation ambiguous')
    gui=json.loads(gui_db['nos_fixture_intents'][0]['payload']);forward=read(root/'gui-forwarding.json')
    require(gui['phase']=='cleaned' and forward['cleanup_verified'] is True,'GUI cleanup incomplete')
    containers.update((gui['container_id'],gui['original']['spec']['container_name']))
    gp=forward['client_generation'];require(exited({'pid':gp['pid'],'start':gp['process_start']}),'original GUI PID1 remains live')
    resources=[]
    for name in sorted(containers):resources.append({'kind':'container','identity':name,'absent':api.request('GET','/containers/'+name+'/json',missing_ok=True) is None})
    for name in sorted(networks):resources.append({'kind':'network','identity':name,'absent':api.request('GET','/networks/'+name,missing_ok=True) is None})
    for name in sorted(links):resources.append({'kind':'link','identity':name,'absent':linux.link(name) is None})
    require(all(row['absent'] for row in resources),'owned resource remains')
    require(not (root/'runtime/run/runtime.sock').exists(),'runtime socket remains')
    require(inventory(api)==before,'protected/global resource inventory changed')
    require(Path('/proc/sys/kernel/random/boot_id').read_text().strip()==metadata['current_boot_id'],'host boot changed')
    require(hashlib.sha256(Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py').read_bytes()).hexdigest()==recipe['plugin_sha256']
            and read('/var/lib/dnlab-vrf-plugin/state.json')==read(root/'plugin-baseline.json'),'installed plugin changed')
    repo=SOURCE.parent.parent
    require(all(hashlib.sha256((repo/name).read_bytes()).hexdigest()==sha for name,sha in recipe['source_sha256'].items()),'source manifest changed')
    reservations=read(root/'vni/registry.json')['reservations']
    require(all(row['phase']=='released' for row in reservations.values()),'VNI reservations remain')
    return {'verified':True,'lifecycle':lifecycle,'cli_execs':cli,'packet_execs':packet_execs,'resources':resources,
            'protected_containers':len(before['containers']),'protected_networks':len(before['networks']),
            'relay_process_stable':True,'original_processes_exited':True,'plugin_unchanged':True}


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--output',required=True);args=parser.parse_args()
    result=verify(args.output);private_json(Path(args.output)/'independent-jumphost-lifecycle.json',result)
    print(json.dumps({'verified':result['verified'],'resources':len(result['resources']),'cli_execs':len(result['cli_execs'])}))
