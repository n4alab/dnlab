"""Independent checks consume real producer journals, then reject altered proof."""
from copy import deepcopy
import json

import pytest

from tests.test_native_jumphost_cli_cleanup import qualified_cli,stage,inventory,configure,native,assets
from tests.test_native_jumphost_stage_recovery_diagnostic import reopen
import native_jumphost_stage as fixture
from jumphost_lifecycle_audit import audit_cli,audit_lifecycle


def cli_proof(qualified_cli):
    value,docker,control,relay,world,asset=qualified_cli
    data=[json.loads(path.read_text()) for path in
          (asset.path,value.root/'cli-before-connect-exec.json',asset.path.with_suffix('.output.json'))]
    options={'owner':deepcopy(world.owner),'nonce':asset.record['nonce'],'action':'connect',
             'node':'R1','workload_nonce':'f'*32}
    return data,options


def test_independent_cli_audit_accepts_original_complete_raw_journal(qualified_cli):
    data,options=cli_proof(qualified_cli)
    result=audit_cli(*data,**options)
    assert result['verified'] and result['id']=='d'*64


@pytest.mark.parametrize('corruption',['owner','nonce','identity','command','running','hash','tail','raw','result'])
def test_independent_cli_audit_rejects_changed_proof(qualified_cli,corruption):
    data,options=cli_proof(qualified_cli);asset,execution,captured=data
    if corruption=='owner':options['owner']['container_id']='a'*64
    elif corruption=='nonce':execution['nonce']='a'*32
    elif corruption=='identity':captured['identity'][1]+=1
    elif corruption=='command':execution['config']['Cmd'][2]='replacement'
    elif corruption=='running':execution['phase']='starting'
    elif corruption=='hash':captured['sha256']='0'*64
    elif corruption=='tail':captured['raw_hex']=captured['raw_hex'][:-2]
    elif corruption=='raw':captured['raw_hex']='00'
    else:execution['result']['exit_verified']=False
    with pytest.raises(ValueError):audit_cli(*data,**options)


def lifecycle_proof(stage):
    value,docker,control,relay=stage
    value.prepare();value.restart();value.cleanup()
    store=value.store;db=value.runtime.journal.db
    rows=lambda connection,table:[dict(row) for row in connection.execute('SELECT * FROM '+table)]
    coordinator={key:rows(store.db,key) for key in ('operations','public_requests')}
    runtime={key:rows(db,key) for key in ('operations','workload_generations','stop_sessions','management_network_proofs')}
    runtime['journal_id']=value.runtime.journal.identity
    state=fixture.states.load_state(value.topo.name,value.root).to_dict()
    options={'lab':value.topo.name,'node':value.node,'ledger':store.directory,
             'jumphost':deepcopy(control['record']),'relay':deepcopy(value.config)}
    return [deepcopy(value.lifecycle.record),coordinator,runtime,state],options


def test_independent_lifecycle_audit_crosschecks_both_databases(stage):
    data,options=lifecycle_proof(stage)
    assert audit_lifecycle(*data,**options)['verified']


@pytest.mark.parametrize('corruption',['creator','container','hash','stop','publication','state','receipt'])
def test_independent_lifecycle_audit_rejects_changed_history_or_receipts(stage,corruption):
    data,options=lifecycle_proof(stage);history,coordinator,runtime,state=data
    if corruption=='creator':runtime['workload_generations'][0]['creator']='replacement'
    elif corruption=='container':history['births'][0]['container_id']='f'*64
    elif corruption=='hash':coordinator['operations'][0]['fingerprint']='0'*64
    elif corruption=='stop':runtime['stop_sessions'][0]['payload']='{"stage":"shutdown_requested"}'
    elif corruption=='publication':history['steps'][0]['receipt']['phase']='pending'
    elif corruption=='state':state['node_runtime']['R1']['state']='running'
    else:history['steps'][0]['receipt']['payload']='{}'
    with pytest.raises(ValueError):audit_lifecycle(*data,**options)


@pytest.mark.parametrize('native',[True],indirect=True)
def test_independent_lifecycle_audit_preserves_management_pin_across_vd_generations(stage):
    data,options=lifecycle_proof(stage)
    assert len(data[2]['management_network_proofs'])==1
    assert audit_lifecycle(*data,**options)['verified']


@pytest.mark.parametrize('native',[True],indirect=True)
@pytest.mark.parametrize('field',['network','operation_id','request_fingerprint'])
def test_independent_management_proof_cannot_change(stage,field):
    data,options=lifecycle_proof(stage)
    row=data[2]['management_network_proofs'][0];payload=json.loads(row['payload'])
    if field=='network':payload['network']['Id']='f'*64
    else:payload[field]='f'*64
    row['payload']=json.dumps(payload)
    with pytest.raises(ValueError,match='management generation proof differs'):
        audit_lifecycle(*data,**options)
