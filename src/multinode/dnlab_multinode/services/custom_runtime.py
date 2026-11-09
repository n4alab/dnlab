"""Opt-in local runtime client over existing SSH, with no scheduling authority.

Callers provide placement, node specs/revisions, endpoint owners and stable
request ID, plus VNI for VXLAN. Native lifecycle manifests require SSH stdin.
This adapter is not enabled by existing
deploy/link controllers.
"""
from dataclasses import dataclass,replace
import json
import math
import re
import shlex
import time


class CustomRuntimeError(RuntimeError):
    pass


@dataclass(frozen=True)
class RuntimeClient:
    ssh: object
    socket_path: str = '/run/dnlab-runtime/runtime.sock'
    container_name: str | None = None
    expected_journal_id: str | None = None
    require_management_identity: bool = False

    def bound_to(self,journal_id):
        if (not isinstance(journal_id,str) or not re.fullmatch(r'[0-9a-f]{32}',journal_id)
                or self.expected_journal_id is not None and self.expected_journal_id!=journal_id):
            raise CustomRuntimeError('runtime journal binding differs')
        return replace(self,expected_journal_id=journal_id)

    def prefix(self):
        if not self.socket_path.startswith('/') or '\x00' in self.socket_path:
            raise CustomRuntimeError('runtime socket path must be absolute')
        command = ['dnlab-runtime','--socket',self.socket_path]
        if self.expected_journal_id is not None:
            if not re.fullmatch(r'[0-9a-f]{32}',self.expected_journal_id):raise CustomRuntimeError('invalid runtime journal binding')
            command+=['--expected-journal-id',self.expected_journal_id]
        if self.container_name is not None:
            if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,127}', self.container_name):
                raise CustomRuntimeError('invalid runtime container name')
            command = ['docker','exec','-i',self.container_name,*command]
        return command

    def invoke(self, action, *args, payload=None):
        if action not in ('management-plan','management-acquire','management-activate','management-cancel','management-release','capabilities','lab-close','lab-finish','lab-reopen','inspect','link-plan','link-submit','link-status','link-cancel','link-inspect',
                          'plan','submit','status','cancel','reconcile','request-status','cancel-request','stop-stage'):
            raise CustomRuntimeError('unsupported runtime invocation')
        command = shlex.join([*self.prefix(),action,*args])
        stdin_payload=None
        if payload is not None:
            encoded = json.dumps(payload,sort_keys=True,separators=(',',':'),allow_nan=False)
            if action in ('management-plan','management-acquire','management-activate','management-cancel','management-release','plan','submit','cancel-request','request-status','stop-stage','lab-close','lab-finish','lab-reopen') or action in ('link-plan','link-submit') and callable(getattr(self.ssh,'run_input',None)):
                stdin_payload=encoded
            else:command = "printf '%s' " + shlex.quote(encoded) + ' | ' + command
        if stdin_payload is not None:
            if not callable(getattr(self.ssh,'run_input',None)):
                raise CustomRuntimeError('runtime lifecycle requires SSH stdin transport')
            output=self.ssh.run_input(command,stdin_payload)
        else:output = self.ssh.run(command)
        try:
            value = json.loads(output)
        except (ValueError,TypeError) as error:
            raise CustomRuntimeError('runtime returned invalid JSON') from error
        if not isinstance(value,dict):
            raise CustomRuntimeError('runtime rejected request or returned invalid response')
        if action in ('link-submit','link-status','link-cancel','submit','status','cancel','reconcile','cancel-request','stop-stage'):
            # Operation envelopes always include an error field, even when
            # queued or completed successfully. It describes the operation,
            # rather than rejection of this request.
            if (not isinstance(value.get('id'),str)
                    or not re.fullmatch(r'[0-9a-f]{32}',value['id'])
                    or value.get('phase') not in (('queued','applying','completed','failed','cancelled','recovery_required')
                        if action.startswith('link-') else ('queued','validating','applying','verifying','cancelling','compensating',
                                                             'completed','failed','cancelled','recovery_required','awaiting_link_cleanup','awaiting_finalization'))
                    or not isinstance(value.get('error'),str)):
                raise CustomRuntimeError('runtime returned invalid operation response')
        elif 'error' in value:
            raise CustomRuntimeError('runtime rejected request or returned invalid response')
        return value

    def management_barrier(self,lab,action,payload):
        if (action not in ('plan','acquire','activate','cancel','release') or self.expected_journal_id is None
                or not isinstance(lab,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',lab)):
            raise CustomRuntimeError('management barrier requires bound runtime context')
        caps=self.qualify_node(inspection=True)
        if (caps.get('journal_id')!=self.expected_journal_id
                or caps.get('management_barrier')!='offline workload fence v2; read-only preflight; acquisition cancellation tombstones; provisioning seal'):
            raise CustomRuntimeError('runtime lacks offline management barrier')
        value=self.invoke('management-'+action,lab,payload=payload)
        if (value.get('lab_id')!=lab or value.get('journal_id')!=self.expected_journal_id
                or type(value.get('generation')) is not int
                or action=='plan' and value.get('mutations_performed') is not False
                or any(value.get(k)!=v for k,v in payload.items())
                or value.get('phase') not in ({'plan':('planned',),'acquire':('held','released'),'activate':('applying',),'cancel':('cancelled',),'release':('released',)}[action])
                or not isinstance(value.get('workload_fingerprint'),str) or not re.fullmatch('[0-9a-f]{64}',value['workload_fingerprint'])):
            raise CustomRuntimeError('offline management receipt differs')
        return value

    def lab_closure(self,lab,action,payload):
        if action not in ('close','finish','reopen') or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',lab):
            raise CustomRuntimeError('invalid lab closure context')
        if self.expected_journal_id is None:raise CustomRuntimeError('lab closure requires journal binding')
        caps=self.qualify_node(cleanup=True)
        if caps.get('lab_closure')!='durable closing fence; qualified stop children only; explicit generation reopen':
            raise CustomRuntimeError('runtime lacks durable lab closure')
        value=self.invoke('lab-'+action,lab,payload=payload)
        expected_generation=payload['generation']+(action=='reopen')
        if (value.get('lab_id')!=lab or value.get('journal_id')!=self.expected_journal_id
                or value.get('closure_id')!=payload['closure_id'] or type(value.get('generation')) is not int
                or value['generation']!=expected_generation
                or value.get('phase') not in (('closing','closed') if action=='close' else ('closed',) if action=='finish' else ('open',))
                or action=='reopen' and value.get('reopen_request_id')!=payload['request_id']):
            raise CustomRuntimeError('runtime lab closure receipt differs')
        return value

    def qualify_node(self, *, kind='linux', request_controls=False, coordinated_stop=False, inspection=False, cleanup=False, management_identity=False, data_endpoints=False, resource_preflight=False, initial_deployment=False, management_mac=False):
        value=self.invoke('capabilities')
        if (type(value.get('schema_version')) is not int or value['schema_version']!=1
                or not isinstance(value.get('actions'),list) or not all(isinstance(x,str) for x in value['actions'])
                or not isinstance(value.get('kinds'),list) or not all(isinstance(x,str) for x in value['kinds'])
                or value.get('persistent_operations') is not True
                or value.get('cancellation') is not True or not {'start','stop'}<=set(value.get('actions',[]))
                or kind!='linux' or kind not in value.get('kinds',[])
                or value.get('workload_generation')!='durable birth nonce and Docker ID; no implicit replacement adoption'
                or value.get('node_ownership')!='committed node revision, container labels and index-bound kernel endpoint identity'):
            raise CustomRuntimeError('runtime lacks the required native node lifecycle protocol')
        if (management_identity or self.require_management_identity) and value.get('management_network_identity')!='durable initial network ID/configuration; retained across stop; no implicit adoption':
            raise CustomRuntimeError('runtime lacks durable initial management network identity')
        if (management_identity or self.require_management_identity) and value.get('management_preflight')!='read-only management proof; request-bound apply and recovery before allocation':
            raise CustomRuntimeError('runtime lacks request-bound management preflight')
        if management_mac and value.get('management_mac_identity')!='optional native endpoint MAC; verified lifecycle; stable across restart':
            raise CustomRuntimeError('runtime lacks native management MAC identity')
        if initial_deployment and value.get('initial_node_preflight')!='read-only committed/workload/operation snapshot for initial starts':
            raise CustomRuntimeError('runtime lacks initial node state preflight')
        if resource_preflight and value.get('resource_preflight')!='read-only journal reservations; atomic admission before mutation':
            raise CustomRuntimeError('runtime lacks journal reservation preflight')
        if data_endpoints and value.get('endpoint_preflight')!='read-only data endpoint preflight; durable allocation evidence before create':
            raise CustomRuntimeError('runtime lacks data endpoint preflight')
        if request_controls and value.get('request_controls')!='lab/node request lookup and durable cancellation before submit':
            raise CustomRuntimeError('runtime lacks durable request controls')
        if coordinated_stop and value.get('coordinated_stop')!='verified exit, explicit local cleanup, explicit finalization':
            raise CustomRuntimeError('runtime lacks coordinated stop phases')
        if cleanup and value.get('runtime_cleanup')!='verified exited local stop; durable coordinator intent; no generic removal':
            raise CustomRuntimeError('runtime lacks qualified cleanup delegation')
        if inspection and value.get('node_inspection')!='consistent committed node, qualified workload and pending operation':
            raise CustomRuntimeError('runtime lacks consistent node inspection')
        return value

    def plan_node(self, request):
        self.qualify_node(kind=request.get('spec',{}).get('kind','linux'),coordinated_stop=request.get('stop_mode')=='coordinated',management_identity=bool(request.get('spec',{}).get('management')),data_endpoints=bool(request.get('spec',{}).get('endpoints')),resource_preflight=request.get('action')=='start',management_mac=bool((request.get('spec',{}).get('management') or {}).get('mac')))
        return self.invoke('plan',payload=request)

    def submit_node(self, request):
        self.qualify_node(kind=request.get('spec',{}).get('kind','linux'),coordinated_stop=request.get('stop_mode')=='coordinated',management_identity=bool(request.get('spec',{}).get('management')),data_endpoints=bool(request.get('spec',{}).get('endpoints')),resource_preflight=request.get('action')=='start',management_mac=bool((request.get('spec',{}).get('management') or {}).get('mac')))
        value=self.invoke('submit',payload=request)
        if any(value.get(field)!=request.get(key) for field,key in (('lab','lab_id'),('node','node_id'),('request_id','request_id'))):
            raise CustomRuntimeError('runtime accepted operation context differs')
        return value

    def cancel_node_request(self, request):
        self.qualify_node(kind=request.get('spec',{}).get('kind','linux'),request_controls=True)
        value=self.invoke('cancel-request',payload=request)
        if any(value.get(field)!=request.get(key) for field,key in (('lab','lab_id'),('node','node_id'),('request_id','request_id'))):
            raise CustomRuntimeError('runtime cancelled operation context differs')
        return value

    def find_node_request(self, request, *, verify_content=False):
        caps=self.qualify_node(request_controls=True)
        if verify_content and caps.get('request_content_check') is not True:
            raise CustomRuntimeError('runtime lacks request content matching')
        value=self.invoke('request-status',request['lab_id'],request['node_id'],request['request_id'],
                          *(['--match-input'] if verify_content else []),payload=request if verify_content else None)
        if any(value.get(key)!=request.get(key) for key in ('lab_id','node_id','request_id')) or 'operation' not in value:
            raise CustomRuntimeError('runtime request lookup context differs')
        operation=value['operation']
        if operation is None:return None
        if (not isinstance(operation,dict) or not isinstance(operation.get('id'),str)
                or not re.fullmatch(r'[0-9a-f]{32}',operation['id']) or not isinstance(operation.get('error'),str)
                or operation.get('phase') not in ('queued','validating','applying','verifying','cancelling','compensating',
                                                'completed','failed','cancelled','recovery_required','awaiting_link_cleanup','awaiting_finalization')
                or any(operation.get(field)!=request.get(key) for field,key in (('lab','lab_id'),('node','node_id'),('request_id','request_id')))):
            raise CustomRuntimeError('runtime returned invalid request operation')
        return operation

    def inspect_node(self,lab,node):
        if (self.expected_journal_id is None
                or any(not isinstance(v,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',v) for v in (lab,node))):
            raise CustomRuntimeError('node inspection requires journal binding and valid context')
        caps=self.qualify_node(inspection=True)
        if caps.get('journal_id')!=self.expected_journal_id:
            raise CustomRuntimeError('runtime inspection journal identity differs')
        value=self.invoke('inspect',lab,node)
        if (value.get('lab_id')!=lab or value.get('node_id')!=node
                or value.get('journal_id')!=self.expected_journal_id
                or type(value.get('revision')) is not int or value['revision']<0
                or value.get('committed_state') not in ('absent','running','stopped')
                or (value['revision']==0)!=(value['committed_state']=='absent')
                or value.get('container_state') not in ('absent','running','stopped')
                or value.get('guest_readiness')!='unknown'
                or 'container_id' not in value or 'workload' not in value or 'operation' not in value):
            raise CustomRuntimeError('runtime node inspection context or state differs')
        def hashed(v,size):return isinstance(v,str) and re.fullmatch('[0-9a-f]{'+str(size)+'}',v) is not None
        cid=value['container_id'];committed=value.get('committed_spec_fingerprint')
        if ((cid is None)!=(value['container_state']=='absent') or cid is not None and not hashed(cid,64)
                or (committed is None if value['revision']>0 else committed is not None)
                or committed is not None and not hashed(committed,64)):
            raise CustomRuntimeError('runtime inspection identity is invalid')
        birth=value['workload']
        if birth is not None:
            if (not isinstance(birth,dict) or type(birth.get('generation')) is not int or birth['generation']<1
                    or birth.get('phase') not in ('reserved','bound','running','cleaned')
                    or not hashed(birth.get('creator_operation_id'),32) or not hashed(birth.get('spec_fingerprint'),64)
                    or 'container_id' not in birth or birth['container_id'] is not None and not hashed(birth['container_id'],64)
                    or 'committed_revision' not in birth or birth['committed_revision'] is not None and
                       (type(birth['committed_revision']) is not int or birth['committed_revision']<1)
                    or cid is not None and (birth['container_id']!=cid or birth['phase'] not in ('bound','running'))):
                raise CustomRuntimeError('runtime inspection workload proof is invalid')
        elif cid is not None:raise CustomRuntimeError('runtime inspection workload proof is missing')
        operation=value['operation']
        if operation is not None:
            if (not isinstance(operation,dict) or not hashed(operation.get('id'),32)
                    or not isinstance(operation.get('request_id'),str)
                    or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,62}',operation['request_id'])
                    or operation.get('action') not in ('start','stop')
                    or operation.get('phase') not in ('queued','validating','applying','verifying','cancelling','compensating','recovery_required','awaiting_link_cleanup','awaiting_finalization')
                    or type(operation.get('cancel_requested')) is not bool or type(operation.get('recovery_force')) is not bool):
                raise CustomRuntimeError('runtime inspection operation is invalid')
        if birth and birth['phase'] in ('reserved','bound') and (not operation or operation['action']!='start'
                or operation['id']!=birth['creator_operation_id']):
            raise CustomRuntimeError('runtime inspection pending birth context differs')
        if 'workload_ref' in value or 'workload_state' in value:
            expected=None if cid is None else {'backend':'docker','kind':'container','id':cid}
            if ('workload_ref' not in value or 'workload_state' not in value
                    or value['workload_ref']!=expected or value['workload_state']!=value['container_state']):
                raise CustomRuntimeError('runtime inspection workload backend reference differs')
        return value

    def node_stop_stage(self, operation_id, lab, node, stage):
        if not isinstance(operation_id,str) or not re.fullmatch(r'[0-9a-f]{32}',operation_id) or stage not in ('cleanup','finalize'):
            raise CustomRuntimeError('invalid coordinated stop identity or stage')
        self.qualify_node(coordinated_stop=True,request_controls=True)
        value=self.invoke('stop-stage',operation_id,payload={'lab_id':lab,'node_id':node,'stage':stage})
        if value['id']!=operation_id or value.get('lab')!=lab or value.get('node')!=node:
            raise CustomRuntimeError('coordinated stop response context differs')
        return value

    def node_operation(self, operation_id, *, action='status', force=False):
        if not isinstance(operation_id,str) or not re.fullmatch(r'[0-9a-f]{32}',operation_id):
            raise CustomRuntimeError('invalid operation identity')
        if action not in ('status','cancel','reconcile') or type(force) is not bool or force and action!='reconcile':
            raise CustomRuntimeError('invalid lifecycle operation action or force')
        value=self.invoke(action,operation_id,*(['--force'] if force else []))
        if value['id']!=operation_id:raise CustomRuntimeError('runtime operation identity changed')
        return value

    def wait_node(self, operation_id, *, timeout=60, clock=time.monotonic, sleep=time.sleep):
        if type(timeout) not in (int,float) or not math.isfinite(timeout) or timeout<=0:
            raise CustomRuntimeError('invalid lifecycle wait timeout')
        deadline=clock()+timeout
        while True:
            value=self.node_operation(operation_id)
            if value['phase']=='completed':return value
            if value['phase'] in ('failed','cancelled','recovery_required'):
                raise CustomRuntimeError(f'native node operation {value["phase"]}: {value["error"]}')
            if clock()>=deadline:raise CustomRuntimeError(f'native node operation still pending: {operation_id}')
            sleep(min(.2,max(0,deadline-clock())))

    def qualify(self, *, kind=None):
        capabilities = self.invoke('capabilities')
        if capabilities.get('schema_version') != 1 or not {'create','delete','recover'} <= set(capabilities.get('link_actions',[])):
            raise CustomRuntimeError('runtime lacks the required local link protocol')
        if capabilities.get('link_endpoint_ownership') != 'committed native-linux node revision and kernel identity':
            raise CustomRuntimeError('runtime link ownership contract differs')
        if kind is not None and kind not in capabilities.get('link_kinds',[]):
            raise CustomRuntimeError('runtime lacks the requested local link kind')
        return capabilities

    def plan(self, request):
        self.qualify(kind=request.get('kind'))
        return self.invoke('link-plan',payload=request)

    def submit(self, request):
        self.qualify(kind=request.get('kind'))
        value = self.invoke('link-submit',payload=request)
        if not isinstance(value.get('id'),str) or not re.fullmatch(r'[0-9a-f]{32}',value['id']):
            raise CustomRuntimeError('runtime returned invalid operation identity')
        return value

    def wait(self, operation_id, *, timeout=60, clock=time.monotonic, sleep=time.sleep):
        if not re.fullmatch(r'[0-9a-f]{32}',operation_id) or timeout <= 0:
            raise CustomRuntimeError('invalid operation identity or timeout')
        deadline = clock()+timeout
        while True:
            value = self.invoke('link-status',operation_id)
            if value.get('id') != operation_id:
                raise CustomRuntimeError('runtime operation identity changed')
            phase = value.get('phase')
            if phase == 'completed':
                return value
            if phase in ('failed','cancelled','recovery_required'):
                raise CustomRuntimeError(f'local link operation {phase}: {value.get("error", "")}')
            if clock() >= deadline:
                # The accepted operation may still be live. Retain its ID;
                # never submit another mutation or fall back to Containerlab.
                raise CustomRuntimeError(f'local link operation still pending: {operation_id}')
            sleep(min(.2,max(0,deadline-clock())))
