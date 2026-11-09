"""Allocated WebUI -> generated YAML/native bindings -> isolated HTTP checks."""
import json
from pathlib import Path
import socket
import sys
import urllib.error
import urllib.request

SOURCE=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(SOURCE.parent/'multinode'))
import yaml
from dnlab_multinode.models.topology import DistributedTopology,VDNode,InfraHost,MgmtConfig,JumphostConfig,JumphostNet
from dnlab_multinode.models.schedule import SchedulePlan,HostAssignment
from dnlab_multinode.services.generator import generate_micro_topology_files
from dnlab_multinode.services.webui_bindings import runtime_binding
from smoke import wait_for


def prepare(lab,image,network):
    allocations=[]
    for address,family in (('127.0.0.1',socket.AF_INET),('::1',socket.AF_INET6)):
        with socket.socket(family,socket.SOCK_STREAM) as probe:
            if family==socket.AF_INET6:probe.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
            probe.bind(('0.0.0.0' if family==socket.AF_INET else '::',0));port=probe.getsockname()[1]
        allocations.append({'bind_ip':address,'host_port':port,'container_port':8080,'proto':'tcp'})
    node=VDNode(name='webui',kind='linux',image=image,mgmt_ipv4='198.19.229.20')
    topo=DistributedTopology(name=lab,master=InfraHost('master','127.0.0.1','fixture','unused',True),workers={},
        underlay_iface='unused',jumphost=JumphostConfig(image='unused'),
        jumphost_net=JumphostNet('unused','unused','192.0.2.0/24','192.0.2.1'),nodes={'webui':node},links=[],
        mgmt=MgmtConfig(network,'unused','198.19.229.0/24','198.19.229.1'))
    plan=SchedulePlan(lab_name=lab,assignments={'master':HostAssignment('master','127.0.0.1',['webui'])})
    document=yaml.safe_load(generate_micro_topology_files(topo,plan,{'webui':allocations})['master']['webui'])
    expected=[f"127.0.0.1:{allocations[0]['host_port']}:8080/tcp",f"[::1]:{allocations[1]['host_port']}:8080/tcp"]
    assert document['topology']['nodes']['webui']['ports']==expected
    program="import http.server,signal,sys,threading,time; signal.signal(signal.SIGTERM,lambda *_:sys.exit(0)); "
    program+="exec(\"class Handler(http.server.BaseHTTPRequestHandler):\\n def do_GET(self):\\n  body=b'"+lab+"'; self.send_response(200); self.end_headers(); self.wfile.write(body)\\n def log_message(self,*args): pass\"); "
    program+="server=http.server.HTTPServer(('0.0.0.0',8080),Handler); threading.Thread(target=server.serve_forever,daemon=True).start(); time.sleep(3600)"
    spec={'kind':'linux','container_name':'drsp-'+lab+'-webui','image':image,'stop_timeout':5,
          'management':{'network':network,'ipv4':node.mgmt_ipv4},'command':['python3','-u','-c',program],
          'ports':[runtime_binding(a) for a in allocations]}
    return spec,allocations,expected


def verify(docker,identity,spec,allocations,lab):
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
    def body(address,port):
        address='['+address+']' if ':' in address else address
        with opener.open('http://'+address+':'+str(port)+'/',timeout=2) as response:return response.read().decode()
    for a in allocations:
        def ready(a=a):
            try:return body(a['bind_ip'],a['host_port'])==lab
            except (OSError,urllib.error.URLError):return False
        wait_for(ready)
    value=docker.inspect(identity)
    assert value and value['Id']==identity and value['Config']['Image']==spec['image'] and value['State']['Running']
    expected=[{'HostIp':a['bind_ip'],'HostPort':str(a['host_port'])} for a in allocations]
    actual=value['NetworkSettings']['Ports']['8080/tcp']
    assert sorted(actual,key=lambda p:p['HostIp'])==sorted(expected,key=lambda p:p['HostIp'])
    assert sorted(value['HostConfig']['PortBindings']['8080/tcp'],key=lambda p:p['HostIp'])==sorted(expected,key=lambda p:p['HostIp'])
    try:body('127.0.0.2',allocations[0]['host_port'])
    except urllib.error.URLError as error:
        if not isinstance(error.reason,ConnectionRefusedError):raise
    else:raise AssertionError('unrequested loopback address serves the bound WebUI')
    return {'status':'passed','bindings':expected,'http_ipv4':True,'http_ipv6':True,
            'unrequested_ipv4_loopback_refused':True,'wildcard_binding_present':any(p['HostIp'] in ('','0.0.0.0','::') for p in actual)}
