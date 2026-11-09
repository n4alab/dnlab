import json
import shlex

import pytest

from dnlab_multinode.services.custom_runtime import RuntimeClient,CustomRuntimeError

ID='a'*32
CAPS={'schema_version':1,'link_actions':['create','delete','recover'],
      'link_endpoint_ownership':'committed native-linux node revision and kernel identity'}


class SSH:
    def __init__(self,values):self.values=list(values);self.commands=[]
    def run(self,command):
        self.commands.append(command)
        return json.dumps(self.values.pop(0))


def test_container_cli_submission_is_quoted_and_returns_durable_id():
    ssh=SSH([CAPS,{'id':ID,'phase':'queued','error':''}])
    client=RuntimeClient(ssh,container_name='runtime-spike')
    payload={'request_id':'req1','lab_id':"lab'; $(touch /tmp/forbidden)"}
    assert client.submit(payload)['id']==ID
    tokens=shlex.split(ssh.commands[1])
    assert tokens[:2]==['printf','%s'] and json.loads(tokens[2])==payload
    assert tokens[3:]==['|','docker','exec','-i','runtime-spike','dnlab-runtime','--socket',client.socket_path,'link-submit']


def test_incompatible_runtime_is_rejected_before_submit():
    ssh=SSH([{'schema_version':1}])
    with pytest.raises(CustomRuntimeError,match='lacks'):
        RuntimeClient(ssh).submit({})
    assert len(ssh.commands)==1


def test_pending_timeout_retains_id_without_second_submission_or_fallback():
    ssh=SSH([{'id':ID,'phase':'applying','error':''},{'id':ID,'phase':'applying','error':''}])
    values=iter([0,0,1,2])
    with pytest.raises(CustomRuntimeError,match='still pending: '+ID):
        RuntimeClient(ssh).wait(ID,timeout=1,clock=lambda:next(values),sleep=lambda _:None)
    assert all('link-status' in command for command in ssh.commands)
    assert not any('containerlab' in command for command in ssh.commands)


def test_recovery_required_does_not_implicitly_retry():
    ssh=SSH([{'id':ID,'phase':'recovery_required','error':'ownership mismatch'}])
    with pytest.raises(CustomRuntimeError,match='recovery_required'):
        RuntimeClient(ssh).wait(ID)
    assert len(ssh.commands)==1


def test_invalid_container_name_cannot_reach_ssh():
    ssh=SSH([])
    with pytest.raises(CustomRuntimeError,match='container name'):
        RuntimeClient(ssh,container_name='runtime; touch /tmp/forbidden').qualify()
    assert not ssh.commands


def test_completed_operation_with_empty_error_is_successful():
    value={'id':ID,'phase':'completed','error':''}
    assert RuntimeClient(SSH([value])).wait(ID)==value


@pytest.mark.parametrize('phase',['failed','cancelled','recovery_required'])
def test_terminal_operation_error_is_reported_without_retry(phase):
    ssh=SSH([{'id':ID,'phase':phase,'error':'owned cleanup incomplete'}])
    with pytest.raises(CustomRuntimeError,match=phase+': owned cleanup incomplete'):
        RuntimeClient(ssh).wait(ID)
    assert len(ssh.commands)==1


@pytest.mark.parametrize('value',[
    {'error':'request rejected'},
    {'id':ID,'phase':'unknown','error':''},
    {'id':ID,'phase':'queued','error':None},
    {'id':'wrong','phase':'queued','error':''},
    {'id':ID,'phase':'queued'},
    [],
])
def test_invalid_operation_response_is_rejected(value):
    with pytest.raises(CustomRuntimeError,match='invalid'):
        RuntimeClient(SSH([value])).wait(ID)


def test_valid_response_for_different_operation_is_rejected():
    with pytest.raises(CustomRuntimeError,match='identity changed'):
        RuntimeClient(SSH([{'id':'b'*32,'phase':'completed','error':''}])).wait(ID)


def test_bridge_requires_explicit_runtime_capability_before_submit():
    ssh=SSH([CAPS])
    with pytest.raises(CustomRuntimeError,match='link kind'):RuntimeClient(ssh).submit({'kind':'bridge'})
    assert len(ssh.commands)==1


def test_bridge_payload_passes_through_qualified_adapter_without_scheduler_logic():
    ssh=SSH([{**CAPS,'link_kinds':['vxlan','bridge']},{'id':ID,'phase':'queued','error':''}])
    payload={'kind':'bridge','endpoints':[{'node_id':'a'},{'node_id':'b'}]}
    assert RuntimeClient(ssh).submit(payload)['id']==ID
    assert json.loads(shlex.split(ssh.commands[1])[2])==payload


NODE_CAPS={'resource_preflight':'read-only journal reservations; atomic admission before mutation','schema_version':1,'kinds':['linux'],'actions':['start','stop'],'persistent_operations':True,'cancellation':True,
           'workload_generation':'durable birth nonce and Docker ID; no implicit replacement adoption',
           'node_ownership':'committed node revision, container labels and index-bound kernel endpoint identity'}


class StdinSSH(SSH):
    def __init__(self,values):super().__init__(values);self.inputs=[]
    def run_input(self,command,payload):
        self.inputs.append(payload);return self.run(command)


def node_request():
    return {'schema_version':1,'lab_id':'lab','node_id':'a','request_id':'start-a','action':'start','expected_revision':0,
            'spec':{'kind':'linux','env':{'TOKEN':'fixture-sensitive-value'}}}


def test_native_submit_uses_stdin_and_validates_accepted_context():
    request=node_request();accepted={'id':ID,'phase':'queued','error':'','lab':'lab','node':'a','request_id':'start-a'}
    ssh=StdinSSH([NODE_CAPS,accepted]);client=RuntimeClient(ssh,container_name='runtime-spike')
    assert client.submit_node(request)==accepted
    assert json.loads(ssh.inputs[0])==request
    assert 'fixture-sensitive-value' not in ' '.join(ssh.commands) and 'printf' not in ssh.commands[-1]
    assert shlex.split(ssh.commands[-1])==['docker','exec','-i','runtime-spike','dnlab-runtime','--socket',client.socket_path,'submit']


def test_native_submit_has_no_command_argument_fallback_without_stdin_transport():
    ssh=SSH([NODE_CAPS])
    with pytest.raises(CustomRuntimeError,match='stdin'):RuntimeClient(ssh).submit_node(node_request())
    assert len(ssh.commands)==1 and 'fixture-sensitive-value' not in ssh.commands[0]


@pytest.mark.parametrize('change',[{'schema_version':True},{'kinds':['cisco_n9kv']},{'actions':None},
    {'actions':[{}]},{'workload_generation':None},{'node_ownership':'legacy'},{'persistent_operations':False},{'cancellation':False}])
def test_native_capability_mismatch_refused_before_payload(change):
    ssh=StdinSSH([{**NODE_CAPS,**change}])
    with pytest.raises(CustomRuntimeError,match='lifecycle'):RuntimeClient(ssh).submit_node(node_request())
    assert not ssh.inputs and len(ssh.commands)==1


def test_native_submit_rejects_response_for_another_lab():
    ssh=StdinSSH([NODE_CAPS,{'id':ID,'phase':'queued','error':'','lab':'other','node':'a','request_id':'start-a'}])
    with pytest.raises(CustomRuntimeError,match='context'):RuntimeClient(ssh).submit_node(node_request())


def test_native_wait_timeout_does_not_resubmit_cancel_or_fallback():
    ssh=SSH([{'id':ID,'phase':'verifying','error':''}]);ticks=iter([0,2])
    with pytest.raises(CustomRuntimeError,match='still pending: '+ID):
        RuntimeClient(ssh).wait_node(ID,timeout=1,clock=lambda:next(ticks))
    assert len(ssh.commands)==1 and shlex.split(ssh.commands[0])[-2:]==['status',ID]


def test_native_cancel_and_recovery_are_explicit_and_force_is_optional():
    ssh=SSH([{'id':ID,'phase':'cancelling','error':''},{'id':ID,'phase':'queued','error':''},
             {'id':ID,'phase':'queued','error':''}]);client=RuntimeClient(ssh)
    client.node_operation(ID,action='cancel');client.node_operation(ID,action='reconcile');client.node_operation(ID,action='reconcile',force=True)
    assert shlex.split(ssh.commands[0])[-2:]==['cancel',ID]
    assert shlex.split(ssh.commands[1])[-2:]==['reconcile',ID]
    assert shlex.split(ssh.commands[2])[-3:]==['reconcile',ID,'--force']
    with pytest.raises(CustomRuntimeError):client.node_operation(ID,action='status',force=True)
    assert len(ssh.commands)==3


@pytest.mark.parametrize('timeout',[None,True,0,-1,float('nan'),float('inf')])
def test_native_wait_rejects_unbounded_or_invalid_timeout_before_ssh(timeout):
    ssh=SSH([])
    with pytest.raises(CustomRuntimeError,match='timeout'):RuntimeClient(ssh).wait_node(ID,timeout=timeout)
    assert not ssh.commands


REQUEST_CAPS={**NODE_CAPS,'request_controls':'lab/node request lookup and durable cancellation before submit'}


def test_cancel_by_request_uses_stdin_and_does_not_require_known_operation_id():
    request=node_request();value={'id':ID,'lab':'lab','node':'a','request_id':'start-a','phase':'cancelled','error':''}
    ssh=StdinSSH([REQUEST_CAPS,value]);assert RuntimeClient(ssh).cancel_node_request(request)==value
    assert json.loads(ssh.inputs[0])==request and 'fixture-sensitive-value' not in ssh.commands[-1]
    assert shlex.split(ssh.commands[-1])[-1]=='cancel-request'


def test_request_lookup_is_read_only_and_can_distinguish_missing():
    request=node_request();value={'lab_id':'lab','node_id':'a','request_id':'start-a','operation':None}
    ssh=SSH([REQUEST_CAPS,value]);assert RuntimeClient(ssh).find_node_request(request) is None
    assert shlex.split(ssh.commands[-1])[-4:]==['request-status','lab','a','start-a']
    assert 'fixture-sensitive-value' not in ' '.join(ssh.commands)


def test_request_lookup_validates_returned_operation_context():
    request=node_request();value={'lab_id':'lab','node_id':'a','request_id':'start-a',
        'operation':{'id':ID,'phase':'queued','error':'','lab':'foreign','node':'a','request_id':'start-a'}}
    with pytest.raises(CustomRuntimeError,match='invalid request operation'):
        RuntimeClient(SSH([REQUEST_CAPS,value])).find_node_request(request)


def test_request_controls_refuse_old_runtime_before_query_or_cancel():
    ssh=StdinSSH([NODE_CAPS,NODE_CAPS]);client=RuntimeClient(ssh)
    with pytest.raises(CustomRuntimeError,match='request controls'):client.find_node_request(node_request())
    with pytest.raises(CustomRuntimeError,match='request controls'):client.cancel_node_request(node_request())
    assert len(ssh.commands)==2 and not ssh.inputs


def test_bound_client_sends_expected_journal_metadata_before_command():
    ssh=StdinSSH([NODE_CAPS,{'id':ID,'phase':'queued','error':'','lab':'lab','node':'a','request_id':'start-a'}])
    client=RuntimeClient(ssh).bound_to('b'*32)
    assert client.submit_node(node_request())['id']==ID
    assert shlex.split(ssh.commands[-1])[-3:]==['--expected-journal-id','b'*32,'submit']
    with pytest.raises(CustomRuntimeError,match='binding'):client.bound_to('c'*32)


def test_matching_lookup_uses_stdin_and_requires_content_capability():
    request=node_request();value={'lab_id':'lab','node_id':'a','request_id':'start-a','operation':None}
    ssh=StdinSSH([{**REQUEST_CAPS,'request_content_check':True},value]);client=RuntimeClient(ssh)
    assert client.find_node_request(request,verify_content=True) is None
    assert json.loads(ssh.inputs[0])==request and shlex.split(ssh.commands[-1])[-1]=='--match-input'
    assert 'fixture-sensitive-value' not in ssh.commands[-1]
    with pytest.raises(CustomRuntimeError,match='content matching'):
        RuntimeClient(SSH([REQUEST_CAPS])).find_node_request(request,verify_content=True)


def test_coordinated_stop_stage_requires_capability_and_stdin():
    caps={**REQUEST_CAPS,'coordinated_stop':'verified exit, explicit local cleanup, explicit finalization'}
    value={'id':ID,'lab':'lab','node':'a','phase':'awaiting_finalization','error':'','stop_stage':'links_cleaned','shutdown_verified':True}
    ssh=StdinSSH([caps,value]);client=RuntimeClient(ssh)
    assert client.node_stop_stage(ID,'lab','a','cleanup')==value
    assert json.loads(ssh.inputs[0])=={'lab_id':'lab','node_id':'a','stage':'cleanup'}
    assert shlex.split(ssh.commands[-1])[-2:]==['stop-stage',ID]
    with pytest.raises(CustomRuntimeError,match='coordinated'):
        RuntimeClient(SSH([REQUEST_CAPS])).node_stop_stage(ID,'lab','a','cleanup')


INSPECT_CAPS={**NODE_CAPS,'journal_id':ID,
              'node_inspection':'consistent committed node, qualified workload and pending operation'}


def inspection_view():
    return {'lab_id':'lab','node_id':'a','journal_id':ID,'revision':2,'committed_state':'stopped',
            'committed_spec_fingerprint':'c'*64,'container_state':'running','container_id':'b'*64,
            'guest_readiness':'unknown','workload':{'generation':2,'phase':'bound','container_id':'b'*64,
            'creator_operation_id':'d'*32,'spec_fingerprint':'e'*64,'committed_revision':None},
            'operation':{'id':'d'*32,'request_id':'restart','action':'start','phase':'verifying',
                         'cancel_requested':False,'recovery_force':False}}


def test_bound_node_inspection_preserves_separate_states():
    view=inspection_view();ssh=SSH([INSPECT_CAPS,view]);client=RuntimeClient(ssh).bound_to(ID)
    assert client.inspect_node('lab','a')==view
    assert shlex.split(ssh.commands[-1])[-3:]==['inspect','lab','a']
    assert '--expected-journal-id' in ssh.commands[-1]


def test_node_inspection_accepts_additive_typed_docker_reference():
    view=inspection_view()
    view.update(workload_ref={'backend':'docker','kind':'container','id':view['container_id']},workload_state='running')
    assert RuntimeClient(SSH([INSPECT_CAPS,view])).bound_to(ID).inspect_node('lab','a')==view


@pytest.mark.parametrize('fault',['backend','kind','id','state','partial'])
def test_node_inspection_refuses_conflicting_backend_reference(fault):
    view=inspection_view()
    view.update(workload_ref={'backend':'docker','kind':'container','id':view['container_id']},workload_state='running')
    if fault=='state':view['workload_state']='stopped'
    elif fault=='partial':view.pop('workload_ref')
    else:view['workload_ref'][fault]='foreign'
    with pytest.raises(CustomRuntimeError,match='backend reference'):
        RuntimeClient(SSH([INSPECT_CAPS,view])).bound_to(ID).inspect_node('lab','a')


@pytest.mark.parametrize('field,value',[('journal_id','f'*32),('lab_id','other'),('node_id','other'),
    ('revision',True),('revision',-1),('committed_state','absent'),('container_id','f'*64),
    ('container_state','absent'),('guest_readiness','ready'),('workload',None),('operation',None)])
def test_node_inspection_refuses_inconsistent_response(field,value):
    view=inspection_view();view[field]=value
    ssh=SSH([INSPECT_CAPS,view])
    with pytest.raises(CustomRuntimeError):RuntimeClient(ssh).bound_to(ID).inspect_node('lab','a')


@pytest.mark.parametrize('field,value',[('generation',True),('generation',0),('phase','legacy'),
    ('creator_operation_id','f'*32),('container_id','f'*64),('committed_revision',False)])
def test_node_inspection_refuses_changed_workload_proof(field,value):
    view=inspection_view();view['workload'][field]=value
    ssh=SSH([INSPECT_CAPS,view])
    with pytest.raises(CustomRuntimeError):RuntimeClient(ssh).bound_to(ID).inspect_node('lab','a')


def test_node_inspection_requires_binding_and_inspection_capability():
    ssh=SSH([])
    with pytest.raises(CustomRuntimeError,match='binding'):RuntimeClient(ssh).inspect_node('lab','a')
    assert not ssh.commands
    ssh=SSH([{**NODE_CAPS,'journal_id':ID}])
    with pytest.raises(CustomRuntimeError,match='consistent'):RuntimeClient(ssh).bound_to(ID).inspect_node('lab','a')
    assert len(ssh.commands)==1


def test_node_inspection_checks_runtime_journal_before_read():
    ssh=SSH([{**INSPECT_CAPS,'journal_id':'f'*32}])
    with pytest.raises(CustomRuntimeError,match='journal'):RuntimeClient(ssh).bound_to(ID).inspect_node('lab','a')
    assert len(ssh.commands)==1


@pytest.mark.parametrize('field,value',[('journal_id','b'*32),('lab_id','other'),('closure_id','b'*32),('generation',True),('generation',2),('phase','open')])
def test_lab_closure_refuses_unbound_receipt(field,value):
    caps={**NODE_CAPS,'runtime_cleanup':'verified exited local stop; durable coordinator intent; no generic removal',
          'lab_closure':'durable closing fence; qualified stop children only; explicit generation reopen'}
    receipt={'lab_id':'lab','journal_id':ID,'closure_id':ID,'generation':1,'phase':'closing'}
    receipt[field]=value
    ssh=StdinSSH([caps,receipt]);client=RuntimeClient(ssh).bound_to(ID)
    with pytest.raises(CustomRuntimeError,match='receipt'):
        client.lab_closure('lab','close',{'closure_id':ID,'generation':1,'stops':[]})
    assert shlex.split(ssh.commands[-1])[-2:]==['lab-close','lab']
    assert json.loads(ssh.inputs[0])['closure_id']==ID


@pytest.mark.parametrize('method',['plan_node','submit_node'])
def test_management_request_refuses_old_runtime_before_payload(method):
    request=node_request();request['spec']['management']={'network':'mgmt','ipv4':'192.0.2.2'}
    ssh=StdinSSH([NODE_CAPS])
    with pytest.raises(CustomRuntimeError,match='initial management network identity'):
        getattr(RuntimeClient(ssh),method)(request)
    assert len(ssh.commands)==1 and ssh.inputs==[]


def test_management_bound_client_retains_requirement_and_accepts_exact_capability():
    caps={**NODE_CAPS,'management_network_identity':'durable initial network ID/configuration; retained across stop; no implicit adoption',
          'management_preflight':'read-only management proof; request-bound apply and recovery before allocation'}
    client=RuntimeClient(StdinSSH([caps]),require_management_identity=True).bound_to(ID)
    assert client.require_management_identity is True
    assert client.qualify_node()['management_network_identity']==caps['management_network_identity']
    with pytest.raises(CustomRuntimeError,match='initial management network identity'):
        RuntimeClient(StdinSSH([NODE_CAPS]),require_management_identity=True).qualify_node()


@pytest.mark.parametrize('method',['plan_node','submit_node'])
def test_management_preflight_capability_required_even_when_identity_is_supported(method):
    caps={**NODE_CAPS,'management_network_identity':'durable initial network ID/configuration; retained across stop; no implicit adoption'}
    request=node_request();request['spec']['management']={'network':'mgmt'}
    ssh=StdinSSH([caps])
    with pytest.raises(CustomRuntimeError,match='request-bound management preflight'):
        getattr(RuntimeClient(ssh),method)(request)
    assert len(ssh.commands)==1 and ssh.inputs==[]


@pytest.mark.parametrize('method',['plan_node','submit_node'])
def test_data_endpoint_request_refuses_runtime_without_preflight_before_payload(method):
    request=node_request();request['spec']['endpoints']=[{'host_interface':'drsp-test','node_interface':'eth1'}]
    ssh=StdinSSH([NODE_CAPS])
    with pytest.raises(CustomRuntimeError,match='data endpoint preflight'):
        getattr(RuntimeClient(ssh),method)(request)
    assert len(ssh.commands)==1 and ssh.inputs==[]


@pytest.mark.parametrize('method',['plan_node','submit_node'])
def test_start_requires_resource_preflight_capability_before_payload(method):
    caps={k:v for k,v in NODE_CAPS.items() if k!='resource_preflight'}
    ssh=StdinSSH([caps])
    with pytest.raises(CustomRuntimeError,match='journal reservation preflight'):
        getattr(RuntimeClient(ssh),method)(node_request())
    assert len(ssh.commands)==1 and ssh.inputs==[]


@pytest.mark.parametrize('contract',[None,False,'unqualified snapshot'])
def test_initial_deployment_requires_exact_node_preflight_capability(contract):
    caps={**NODE_CAPS,'initial_node_preflight':contract}
    ssh=StdinSSH([caps])
    with pytest.raises(CustomRuntimeError,match='initial node state preflight'):
        RuntimeClient(ssh).qualify_node(initial_deployment=True)
    assert not ssh.inputs and len(ssh.commands)==1


def test_mac_start_requires_capability_before_sending_manifest():
    request=node_request();request['spec']['management']={'network':'mgmt','mac':'02:11:22:33:44:55'}
    caps={**NODE_CAPS,'management_network_identity':'durable initial network ID/configuration; retained across stop; no implicit adoption',
          'management_preflight':'read-only management proof; request-bound apply and recovery before allocation'}
    ssh=StdinSSH([caps])
    with pytest.raises(CustomRuntimeError,match='native management MAC identity'):RuntimeClient(ssh).submit_node(request)
    assert ssh.inputs==[]
