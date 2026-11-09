"""Independent offline evidence checks for the integrated jumphost gate.

These functions do not invoke producers, repair journals or operate resources.
The caller supplies original service/baseline proofs and read-only DB snapshots.
"""
from copy import deepcopy
import hashlib
import json
import re

from jumphost_cli_program import build


def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()).hexdigest()


def require(condition,description):
    if not condition:raise ValueError(description)


def audit_cli(asset,execution,captured,*,owner,nonce,action,node,workload_nonce):
    """Bind the full raw output to the original command, exec and namespace."""
    require(asset['owner']==execution['owner']==owner,'CLI owner differs')
    require(asset['nonce']==execution['nonce']==captured['nonce']==nonce
            and re.fullmatch('[0-9a-f]{32}',nonce),'CLI nonce differs')
    require(asset['action']==action and asset['node']==node,'CLI target differs')
    require(asset['output']=='/run/dnlab-cli-'+nonce+'.jsonl','CLI output path differs')
    identity=asset['identity']
    require(isinstance(identity,list) and len(identity)==4 and all(type(v) is int for v in identity)
            and identity==captured['identity'] and identity[2:]==[asset['account']['uid'],asset['account']['gid']]
            and identity[2]>0 and identity[3]>0,'CLI output/account identity differs')
    if action=='connect':
        command=("printf '%s%s\\n' 'relay-console-' '"+nonce+"'; exit\n").encode()
        marker=('relay-console-'+nonce).encode()
    else:
        require(action=='log','unknown CLI action')
        command=b'\n';marker=('READY:'+workload_nonce).encode()
    require(bytes.fromhex(asset['command_hex'])==command and bytes.fromhex(asset['marker_hex'])==marker
            and marker not in command,'CLI command/marker differs')
    profile={**{k:deepcopy(asset[k]) for k in ('nonce','output','identity','action','node','command_hex','marker_hex')},
             'cli':'/usr/local/bin/vd','timeout':15}
    expected={'User':'labuser','Cmd':['python3','-I','-c',build(profile),nonce],
              **{k:False for k in ('AttachStdin','AttachStdout','AttachStderr','Tty','Privileged')}}
    require(execution['config']==expected,'CLI frozen exec command differs')
    require(execution['phase']=='completed' and execution['exit_verified'] is True
            and execution['create_attempted'] is True and execution['start_attempted'] is True
            and type(execution['exit_code']) is int and execution['exit_code']==0
            and re.fullmatch('[0-9a-f]{64}',execution['id']),'CLI exec not completed')
    raw=bytes.fromhex(captured['raw_hex']);sha=hashlib.sha256(raw).hexdigest()
    require(len(raw)<=1048576 and raw.endswith(b'\n') and sha==captured['sha256'],
            'CLI raw journal hash/tail differs')
    events=[json.loads(line) for line in raw.splitlines()]
    birth={'nonce':nonce,'kind':'asset_birth','value':{'intent_sha256':digest({k:v for k,v in asset.items() if k!='identity'})}}
    require(events and events[0]==birth,'CLI original asset birth differs')
    body=events[1:]
    require(len(body)>=4 and [v['kind'] for v in body[:2]]==['wrapper_birth','client_birth']
            and body[-1]['kind']=='completed' and all(v['kind']=='progress' for v in body[2:-1])
            and all(set(v)=={'nonce','kind','value'} and v['nonce']==nonce for v in body),
            'CLI event history differs')
    for event in body[:2]:
        p=event['value']
        require(set(p)=={'pid','start','namespace'} and type(p['pid']) is int and p['pid']>0
                and isinstance(p['start'],str) and p['start'].isdigit()
                and p['namespace']==owner['process']['namespace'],'CLI process birth differs')
    require(body[0]['value']['pid']!=body[1]['value']['pid'],'CLI process births collide')
    counts=(0,0);seen_marker=False;closed=False
    for event in body[2:-1]:
        p=event['value']
        require(set(p)=={'stdout_bytes','stderr_bytes','marker_seen','input_closed','exit_code'},'CLI progress fields differ')
        current=(p['stdout_bytes'],p['stderr_bytes'])
        require(all(type(v) is int and v>=old for v,old in zip(current,counts))
                and sum(current)<=131072,'CLI byte progress regressed')
        require(type(p['marker_seen']) is bool and type(p['input_closed']) is bool
                and (not seen_marker or p['marker_seen']) and (not closed or p['input_closed'])
                and (not p['input_closed'] or seen_marker),'CLI input closed before response')
        seen_marker=seen_marker or p['marker_seen'];closed=closed or p['input_closed'];counts=current
    result=body[-1]['value'];output=bytes.fromhex(result['output_hex'])
    require(seen_marker and closed and p['exit_code']==0 and type(p['exit_code']) is int
            and counts==(len(output),0) and marker in output and not output.startswith(b'ERR '),
            'CLI output/exit progress differs')
    require(set(result)=={'nonce','output_hex','exit_verified','exit_code','marker_seen_before_input_close'}
            and result['nonce']==nonce and result['exit_verified'] is True
            and result['marker_seen_before_input_close'] is True
            and type(result['exit_code']) is int and result['exit_code']==0
            and execution['result']=={**result,'journal_sha256':sha},'CLI result receipt differs')
    return {'id':execution['id'],'container_id':owner['container_id'],'nonce':nonce,
            'journal_sha256':sha,'client_birth':body[1]['value'],'verified':True}


def audit_lifecycle(history,coordinator,runtime,public,*,lab,node,ledger,jumphost,relay):
    """Cross-check original births, public receipts and native DB generations."""
    require(history['owner']=={'lab':lab,'node':node,'ledger':str(ledger)}
            and history['cleanup_verified'] is True,'lifecycle owner/cleanup differs')
    births=history['births'];steps=history['steps']
    require(len(births)==2 and len(steps)==2 and [s['action'] for s in steps]==['restart','stop']
            and all(s['phase']=='completed' for s in steps),'lifecycle scope/steps differ')
    require(births[1]['generation']==births[0]['generation']+1
            and births[0]['container_id']!=births[1]['container_id']
            and births[0]['target']==births[1]['target']
            and births[0]['request']['spec']==births[1]['request']['spec'],'birth history differs')
    ops={(r['lab'],r['request_id']):r for r in coordinator['operations']}
    native_ops={r['id']:r for r in runtime['operations']}
    generations={(r['lab'],r['node'],r['generation']):r for r in runtime['workload_generations']}
    sessions={r['operation_id']:json.loads(r['payload']) for r in runtime['stop_sessions']}

    def child(key):
        row=ops[(lab,key)];request=json.loads(row['request']);target=json.loads(row['target'])
        require(row['node']==node and row['phase']=='completed' and not row['cancel_requested']
                and not row['native_force_requested'] and row['fingerprint']==digest(
                    {'request':request,'target':target,'journal_id':row['journal_id']}),'coordinator child differs')
        op=native_ops[row['operation_id']];payload=json.loads(op['payload'])
        require(op['lab']==lab and op['node']==node and op['request_id']==key and op['phase']=='completed'
                and not op['cancel_requested'] and not op['recovery_force'] and op['hash']==digest(payload)
                and all(payload.get(k)==v for k,v in request.items() if k!='management_preflight'),
                'runtime child differs')
        if request['action']=='stop':
            session=sessions[op['id']]
            require(not request.get('force') and session['stage']=='finished',
                    'ordinary coordinated shutdown not finished')
            require(session['lab']==lab and session['node']==node and session['links']==[]
                    and session['proofs']==[] and set(session['owners'])=={node}
                    and request['expected_stop_fingerprint']==digest({**session,'stage':'prepared'}),
                    'original stop preflight fingerprint differs')
        return row,request,target

    for birth in births:
        binding=birth['binding'];row,request,target=child(binding['birth_request_id'])
        generation=generations[(lab,node,birth['generation'])]
        require(request==birth['request'] and target==birth['target']
                and row['operation_id']==birth['creator_operation_id']
                and row['journal_id']==birth['journal_id']==runtime['journal_id']
                and binding=={'backend':'custom','journal_id':row['journal_id'],
                    'birth_request_id':row['request_id'],'container_id':birth['container_id'],
                    'generation':birth['generation'],'spec_fingerprint':digest(request['spec']),
                    'revision':request['expected_revision']+1},'birth binding differs')
        require(generation['creator']==row['operation_id'] and generation['container_id']==birth['container_id']
                and generation['spec']==digest(request['spec']) and generation['phase']=='cleaned'
                and generation['committed_revision']==binding['revision']+1,'native generation not cleaned')
        if request['spec'].get('management'):
            proof=request['management_preflight'];management=request['spec']['management']
            require(set(proof)=={'journal_id','request_fingerprint','management','network'}
                    and proof['journal_id']==row['journal_id'] and proof['management']==management
                    and proof['request_fingerprint']==digest({k:v for k,v in request.items() if k!='management_preflight'}),
                    'original management preflight binding differs')
            observed=[r for r in runtime['management_network_proofs'] if
                      (r['lab'],r['node'],r['generation'],r['name'])==(lab,node,request.get('lab_generation',1),management['network'])]
            require(len(observed)==1,'original management network proof missing')
            recorded=json.loads(observed[0]['payload'])
            creator=births[0]['creator_operation_id']
            require(request.get('lab_generation',1)==births[0]['request'].get('lab_generation',1)
                    and recorded['operation_id']==creator and recorded['network']==proof['network']
                    and recorded['request_fingerprint']==native_ops[creator]['hash'],
                    'native management generation proof differs')
    require(steps[0]['before']==births[0] and steps[0]['after']==births[1]
            and steps[1]['before']==steps[1]['after']==births[1],'step birth transition differs')
    parents={r['request_id']:r for r in coordinator['public_requests'] if r['lab']==lab}
    for step in steps:
        row=parents[step['request_id']];payload=json.loads(row['payload'])
        require(row==step['receipt'] and row['node']==node and row['action']==step['action']
                and not row['force'] and row['phase']=='completed','public receipt differs')
        require(payload['origin_fingerprint']==digest({'lab':lab,'request_id':row['request_id'],'node':node,
                    'action':row['action'],'force':False,'origin':payload['origin']})
                and payload['inventory_phase']=='published','public origin/publication differs')
        inventory=payload['inventory'];manifest=inventory['manifest']
        require(inventory['phase']=='published' and inventory['fingerprint']==digest(manifest)
                and manifest['lab']==lab and manifest['host']=='master' and manifest['exclude'] is None,
                'inventory intent differs')
        desired=manifest['desired'];name=births[-1]['request']['spec']['container_name']
        expected=name+'='+relay['bind_ip']+':'+str(relay['port'])+':'+relay['api_key']+':custom:'+births[-1]['container_id']+'\n'
        require(desired['lab']==lab and desired['generation']==jumphost['config']['generation']
                and desired['container_id']==jumphost['container_id'] and desired['vds']==node+'='+name+'\n'
                and desired['relays']==expected,'published VD identity differs')
        for request in payload['requests'].values():
            _,original,_=child(request['request_id'])
            # The native stop footprint was independently checked above.
            strip=lambda value:{k:v for k,v in value.items() if k not in ('management_preflight','expected_stop_fingerprint')}
            require(strip(request)==strip(original),'public child intent differs')
    final=public['node_runtime'][node];binding=final['runtime_binding']
    require(final['state']=='stopped' and final['runtime_status']['committed_state']=='stopped'
            and final['runtime_status']['container_state']=='absent'
            and {k:v for k,v in binding.items() if k!='stop_request_id'}==births[-1]['binding']
            and binding['stop_request_id'] in [r['request_id'] for r in json.loads(steps[-1]['receipt']['payload'])['requests'].values()],
            'final public stopped owner differs')
    require(all(r['phase'] in ('completed','failed','cancelled') for r in runtime['operations'] if r['lab']==lab)
            and all(r['phase'] in ('completed','failed','cancelled') for r in coordinator['operations'] if r['lab']==lab)
            and all(r['phase']=='completed' for r in parents.values()),'pending operations remain')
    return {'verified':True,'original_ids':[b['container_id'] for b in births],
            'generation_count':len(births),'ordinary_stops_verified':True}
