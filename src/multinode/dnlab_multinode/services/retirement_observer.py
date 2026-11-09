"""Bounded SSH/stdin read-only observer for original local batch retirement."""
from copy import deepcopy
import json
from pathlib import Path
import shlex

from .jumphost import _WORKER_BOOTSTRAP
from .paths import PATHS
from .mgmt_network import PLUGIN_STATE
from .runtime_operations import RuntimeOperationError,digest


def program():
    directory=Path(__file__).parent
    source="network={'__name__':'_network'}\nexec("+repr((directory/'management_network_host.py').read_text())+",network)\n"
    source+="host={'__name__':'_host'}\nexec("+repr((directory/'management_host.py').read_text())+",host)\n"
    source+="retire={'__name__':'_retire','NetworkError':network['NetworkError']}\nexec("+repr((directory/'retirement_network.py').read_text())+",retire)\n"
    source+='''
import json,sys
from urllib.parse import quote
request=json.load(sys.stdin)
if request['action']=='observe':
 worker=host['Worker'](request['plan'],directory=request['directory'])
 guard=network['NetworkGuard'](worker,request['networks'],socket_path=request['socket'],plugin_path=request['plugin'])
 proof=retire['observe'](guard,request['allowed'])
elif request['action']=='absence':
 docker=network['Docker'](request['socket'])
 for value in request['containers']:
  for identity in (value['id'],value['name']):
   if docker.call('GET','/containers/'+quote(identity,safe='')+'/json',absent=True) is not None:
    raise RuntimeError('retirement original ID/name remains or was replaced')
 proof={'absent':request['containers']}
else:raise RuntimeError('unsupported retirement observation')
print(json.dumps({'request_fingerprint':host['digest'](request),'proof':proof}))
'''
    return source


class NetworkObserver:
    def __init__(self,metadata,clients,*,paths=PATHS):
        self.metadata,self.clients,self.paths=deepcopy(metadata),clients,paths
        if set(clients)!=set(metadata['plans']) or set(metadata['plans'])!=set(metadata['networks']):
            raise RuntimeOperationError('complete original retirement host inventory required')

    def invoke(self,host,request):
        request={**request,'socket':self.paths.docker_socket.removeprefix('unix://')}
        value=json.loads(self.clients[host].run_input(shlex.join(['python3','-c',_WORKER_BOOTSTRAP]),
            json.dumps({'source':program(),'request':request}),timeout=180))
        if not isinstance(value,dict) or value.get('request_fingerprint')!=digest(request) or not isinstance(value.get('proof'),dict):
            raise RuntimeOperationError('retirement observation acknowledgement differs')
        return value['proof']

    def __call__(self,allowed):
        if set(allowed)!=set(self.clients):raise RuntimeOperationError('all original retirement hosts required')
        return {host:self.invoke(host,{'action':'observe','plan':self.metadata['plans'][host],
            'networks':self.metadata['networks'][host],'allowed':allowed[host],
            'directory':self.paths.management_journal_dir,'plugin':PLUGIN_STATE}) for host in sorted(self.clients)}

    def verify_absent(self,births):
        hosts={}
        for birth in births.values():
            hosts.setdefault(birth['target']['host'],[]).append({'id':birth['binding']['container_id'],
                'name':birth['request']['spec']['container_name']})
        if not set(hosts)<=set(self.clients):raise RuntimeOperationError('original retirement workload host missing')
        for host,containers in sorted(hosts.items()):
            if self.invoke(host,{'action':'absence','containers':containers})!={'absent':containers}:
                raise RuntimeOperationError('retirement absence proof differs')
