"""A native HTTP workload admitted and removed only by the original coordinator."""
from pathlib import Path
import json
from copy import deepcopy
import re
import subprocess
import time
import uuid
from management_service_diagnostics import private_json
from dnlab_multinode.services.runtime_operations import OperationDriver,digest,encoded
from dnlab_runtime.backend import Docker


def program(nonce):
    if len(nonce)!=32 or any(c not in '0123456789abcdef' for c in nonce):raise ValueError('original HTTP nonce required')
    return '''import json,signal
from http.server import HTTPServer,BaseHTTPRequestHandler
nonce=__NONCE__
body=json.dumps({'nonce':nonce,'role':'dnlab-native-http'},sort_keys=True).encode()
running=True
def stop(*args):
 global running
 running=False
signal.signal(signal.SIGTERM,stop)
signal.signal(signal.SIGINT,stop)
class Handler(BaseHTTPRequestHandler):
 def setup(self):
  super().setup();self.connection.settimeout(2)
 def do_GET(self):
  if self.path!='/dnlab-probe/'+nonce:
   self.send_error(404);return
  self.send_response(200);self.send_header('Content-Type','application/json')
  self.send_header('Content-Length',str(len(body)));self.send_header('X-Dnlab-Fixture',nonce)
  self.send_header('Connection','close');self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
server=HTTPServer(('0.0.0.0',8080),Handler);server.timeout=.2
print('READY:'+nonce,flush=True)
try:
 while running:server.handle_request()
finally:server.server_close()
'''.replace('__NONCE__',repr(nonce))


class Workload:
    def __init__(self,root,lab,node,image,management,target,runtime,store,*,gate_context=None):
        self.path=Path(root)/'http-workload.json';self.runtime=runtime;self.store=store;self.api=Docker()
        self.driver=OperationDriver(store,lambda actual:runtime if actual==target else self.wrong_target())
        existing=self.path.exists()
        self.record=json.loads(self.path.read_text()) if existing else {
            'phase':'planned','nonce':uuid.uuid4().hex,'lab':lab,'node':node,'image':image,
            'management':management,'target':target,'journal_id':runtime.expected_journal_id,'cleanup_verified':False}
        if any(self.record.get(k)!=v for k,v in {'lab':lab,'node':node,'image':image,'management':management,'target':target,'journal_id':runtime.expected_journal_id}.items()):
            raise RuntimeError('HTTP workload original intent differs')
        nonce=self.record['nonce']
        self.spec={'kind':'linux','image':image,'container_name':'drsp-http-'+nonce[:12],
                   'command':['python3','-u','-c',program(nonce)],'stop_timeout':5,'management':management}
        self.start={'schema_version':1,'lab_id':lab,'node_id':node,'request_id':'http-start-'+nonce,
                    'expected_revision':0,'action':'start','spec':self.spec}
        if self.record.get('spec',self.spec)!=self.spec or self.record.get('start',self.start)!=self.start:
            raise RuntimeError('HTTP workload source or original request differs')
        self.record.update(spec=self.spec,start=self.start)
        from native_scope_registration import bind_gate_context
        bind_gate_context(self.record,gate_context,existing=existing)
        self.save()

    @staticmethod
    def wrong_target():raise RuntimeError('HTTP workload original runtime target differs')

    def save(self):private_json(self.path,self.record)

    def drive(self,request):
        self.driver.prepare(request,self.record['target']);deadline=time.monotonic()+45
        while True:
            result=self.driver.advance(self.record['lab'],request['request_id'])
            if result['phase']=='completed':return result
            if result['phase'] in ('failed','cancelled','recovery_required'):
                raise RuntimeError('HTTP workload operation '+result['phase'])
            if time.monotonic()>=deadline:raise RuntimeError('HTTP workload operation still pending')
            time.sleep(.05)

    def ensure(self):
        if self.api.request('GET','/images/'+self.record['image']+'/json')['Id']!=self.record['image']:
            raise RuntimeError('pinned native HTTP image required')
        self.record['phase']='starting';self.save()
        self.drive(self.start)
        view=self.runtime.inspect_node(self.record['lab'],self.record['node'])
        if (view['operation'] is not None or view['committed_state']!='running' or view['container_state']!='running'
                or self.record.get('container_id') not in (None,view['container_id'])):
            raise RuntimeError('original HTTP workload generation differs')
        self.record.update(container_id=view['container_id'],revision=view['revision'],workload=view['workload'],phase='running');self.save()
        deadline=time.monotonic()+15
        while True:
            current=self.runtime.inspect_node(self.record['lab'],self.record['node'])
            if current['container_id']!=self.record['container_id'] or current['operation'] is not None:
                raise RuntimeError('HTTP workload changed during readiness')
            logs=subprocess.run(['docker','logs','--tail','10',current['container_id']],capture_output=True,timeout=5)
            if logs.returncode:raise RuntimeError('original HTTP workload logs unavailable')
            if ('READY:'+self.record['nonce']).encode() in logs.stdout:break
            if time.monotonic()>=deadline:raise RuntimeError('original HTTP workload listener not ready')
            time.sleep(.05)
        return {'node':self.record['node'],'ip':self.record['management']['ipv4'],'vd_port':8080,
                'nonce':self.record['nonce'],'path':'/dnlab-probe/'+self.record['nonce']}

    def verify(self):
        view=self.runtime.inspect_node(self.record['lab'],self.record['node'])
        if (view['operation'] is not None or view['container_id']!=self.record['container_id']
                or view['revision']!=self.record['revision'] or view['committed_state']!='running'
                or view['container_state']!='running' or view['workload']!=self.record['workload']):
            raise RuntimeError('original HTTP workload changed during proxy request')
        return view

    def cleanup_start(self):
        original=self.store.get(self.record['lab'],self.start['request_id'],private=True)
        request={k:v for k,v in original['request'].items() if k!='management_preflight'}
        if (encoded(request)!=encoded(self.start) or original['phase']!='completed' or not original['operation_id']
                or original['target']!=self.record['target'] or original['journal_id']!=self.record['journal_id']
                or original['request']['spec']!=self.spec):
            raise RuntimeError('HTTP workload original completed start required for cleanup')
        return original

    def cleanup_view(self,view,original,*,stopped):
        fields={'journal_id','lab_id','node_id','operation','committed_state','container_state','container_id','revision','workload'}
        if not isinstance(view,dict) or not fields<=view.keys():
            raise RuntimeError('HTTP workload cleanup observation incomplete')
        revision=self.start['expected_revision']+1
        birth=view.get('workload') or {};cid=birth.get('container_id')
        phase='cleaned' if stopped else 'running';current_revision=revision+int(stopped)
        if (view.get('journal_id')!=original['journal_id'] or view.get('lab_id')!=self.record['lab']
                or view.get('node_id')!=self.record['node'] or view.get('operation') is not None
                or view.get('committed_state')!=('stopped' if stopped else 'running')
                or view.get('container_state')!=('absent' if stopped else 'running')
                or view.get('revision')!=current_revision or type(view.get('revision')) is not int
                or not isinstance(cid,str) or not re.fullmatch('[0-9a-f]{64}',cid)
                or view.get('container_id')!=(None if stopped else cid)
                or birth.get('creator_operation_id')!=original['operation_id']
                or birth.get('spec_fingerprint')!=digest(self.spec)
                or type(birth.get('generation')) is not int or birth['generation']<1
                or birth.get('phase')!=phase or birth.get('committed_revision')!=current_revision
                or type(birth.get('committed_revision')) is not int):
            raise RuntimeError('HTTP workload cleanup identity or transition differs')
        if self.record.get('container_id') not in (None,cid) or self.record.get('revision') not in (None,revision):
            raise RuntimeError('HTTP workload cleanup original generation differs')
        saved=self.record.get('workload')
        if stopped and (not self.record.get('container_id') or self.record.get('revision') is None):
            raise RuntimeError('HTTP workload cleanup original generation missing')
        if saved is not None:
            expected=deepcopy(saved);expected.update(phase=phase,committed_revision=current_revision)
            if birth!=expected:raise RuntimeError('HTTP workload cleanup birth proof differs')
        elif stopped:
            raise RuntimeError('HTTP workload cleanup original birth proof missing')
        else:
            self.record.update(container_id=cid,revision=revision,workload=deepcopy(birth));self.save()

    def cleanup_stop(self):
        stop={'schema_version':1,'lab_id':self.record['lab'],'node_id':self.record['node'],
              'request_id':'http-stop-'+self.record['nonce'],'expected_revision':self.start['expected_revision']+1,'action':'stop'}
        if 'lab_generation' in self.start:stop['lab_generation']=self.start['lab_generation']
        saved=self.record.get('stop')
        if saved is not None:
            # Older fixture requests omitted the optional default generation.
            # Compare its semantics, but never rewrite the original request.
            normalize=lambda r:{**r,'lab_generation':r.get('lab_generation',1)}
            if encoded(normalize(saved))!=encoded(normalize(stop)):
                raise RuntimeError('HTTP workload cleanup original stop differs')
            return saved
        return stop

    def verify_cleanup_stop(self,stop):
        if self.record.get('stop')!=stop or not self.store.contains(self.record['lab'],stop['request_id']):
            raise RuntimeError('HTTP workload original stop intent missing')
        saved=self.store.get(self.record['lab'],stop['request_id'],private=True)
        if (saved['request']!=stop or saved['target']!=self.record['target'] or saved['journal_id']!=self.record['journal_id']
                or saved.get('native_force_requested')):
            raise RuntimeError('HTTP workload original stop ownership differs')
        receipt=self.runtime.find_node_request(stop,verify_content=True)
        if (not receipt or receipt.get('phase')!='completed' or receipt.get('cancel_requested')
                or receipt.get('recovery_force') or receipt.get('lab')!=self.record['lab']
                or receipt.get('node')!=self.record['node'] or receipt.get('request_id')!=stop['request_id']
                or saved['operation_id'] and saved['operation_id']!=receipt.get('id')):
            raise RuntimeError('HTTP workload original completed stop not verified')
        if saved['phase']!='completed':self.store.observe(self.record['lab'],stop['request_id'],receipt)
        elif not saved['operation_id']:raise RuntimeError('HTTP workload completed stop identity missing')

    def cleanup(self):
        self.record.update(phase='cleanup_pending',cleanup_verified=False);self.save()
        if not self.store.contains(self.record['lab'],self.start['request_id']):
            if self.record.get('container_id') or self.record.get('workload') or self.record.get('stop'):
                raise RuntimeError('HTTP workload original start intent missing')
            self.record.update(phase='cleaned',cleanup_verified=True);self.save();return
        original=self.cleanup_start()
        view=self.runtime.inspect_node(self.record['lab'],self.record['node'])
        stop=self.cleanup_stop()
        if view['committed_state']!='stopped':
            self.cleanup_view(view,original,stopped=False)
            if self.store.contains(self.record['lab'],stop['request_id']) and self.store.get(self.record['lab'],stop['request_id'])['phase']=='completed':
                raise RuntimeError('HTTP workload running after committed stop')
            self.record['stop']=stop;self.save();self.drive(stop)
        view=self.runtime.inspect_node(self.record['lab'],self.record['node'])
        self.cleanup_view(view,original,stopped=True)
        self.verify_cleanup_stop(stop)
        if self.api.inspect(self.record['container_id']) is not None:
            raise RuntimeError('original HTTP workload container still present')
        self.record.update(phase='cleaned',cleanup_verified=True);self.save()
