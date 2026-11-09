#!/usr/bin/env python3
"""Isolated image/serial recovery qualification, without touching lab networks.

The image must contain the updated entrypoint and inventory.py. This gate uses
synthetic TCP serials rather than a NOS and does not qualify browser idle time.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import uuid

ROOT=Path(__file__).resolve().parents[3]
sys.path.insert(0,str(ROOT/'src/multinode'))
from dnlab_multinode.services.management_network_host import Docker

spec=importlib.util.spec_from_file_location('relay_fixture',ROOT/'src/multinode/runtime-relay/relay.py')
relay=importlib.util.module_from_spec(spec);spec.loader.exec_module(relay)

SERIAL_FIXTURE=r'''
import json,os,signal,socket,subprocess,threading,time
stop=threading.Event();children=[]
signal.signal(signal.SIGTERM,lambda *a:stop.set())
def hold(conn):
 stop.wait();conn.close()
def serve(port):
 server=socket.socket();server.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);server.bind(('127.0.0.1',port));server.listen();server.settimeout(.1)
 while not stop.is_set():
  try:conn,_=server.accept()
  except socket.timeout:continue
  conn.sendall(b'fixture serial ready\r\n')
  threading.Thread(target=hold,args=(conn,),daemon=True).start()
 server.close()
for port in (5000,5001):
 threading.Thread(target=serve,args=(port,),daemon=True).start()
time.sleep(.2)
for port in (5000,5001):
 child=subprocess.Popen(['telnet','127.0.0.1',str(port)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.STDOUT);children.append(child)
open('/tmp/drsp-clients.json','w').write(json.dumps([p.pid for p in children]))
while not stop.wait(.1):
 for child in children:child.poll()
for child in children:
 if child.poll() is None:child.terminate()
for child in children:child.wait(timeout=3)
'''


def run(output,image):
    root=Path(output);root.mkdir(mode=0o700,parents=True,exist_ok=False)
    docker=Docker('/var/run/docker.sock');token=uuid.uuid4().hex
    name='drsp-relay-'+token[:12];labels={'org.dnlab.fixture':'jumphost-relay','org.dnlab.nonce':token}
    image_proof=docker.call('GET','/images/'+image+'/json')
    labels={**(image_proof['Config'].get('Labels') or {}),**labels}
    config={'Image':image,'Entrypoint':['python3'],'Cmd':['-u','-c',SERIAL_FIXTURE],
            'Labels':labels,'HostConfig':{'NetworkMode':'none','RestartPolicy':{'Name':'no'}}}
    intent={'name':name,'config':config,'container_id':None,'create_attempted':False,'create_returned':False}
    report={'status':'running','checks':[],'cleanup_verified':False}
    def save(file,value):
        with (root/file).open('w') as stream:
            json.dump(value,stream,indent=2);stream.flush();os.fsync(stream.fileno())
        fd=os.open(root,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    def inspect():
        value=docker.call('GET','/containers/'+(intent['container_id'] or name)+'/json',absent=True)
        if value is None:return None
        if (value['Name']!='/'+name or value['Image']!=image or value['Config']['Labels']!=labels
                or value['Config']['Entrypoint']!=config['Entrypoint'] or value['Config']['Cmd']!=config['Cmd']
                or value['HostConfig']['NetworkMode']!='none'
                or intent['container_id'] and value['Id']!=intent['container_id']):
            raise RuntimeError('fixture birth identity differs')
        return value
    def execute(args,input=None,success=True):
        value=inspect()
        if not value:raise RuntimeError('fixture missing')
        result=subprocess.run(['docker','exec','-i',value['Id'],*args],input=input,text=True,capture_output=True,timeout=20)
        if success and result.returncode:raise RuntimeError('fixture exec failed: '+result.stderr[-1000:])
        return result
    failure=None;broker=None
    save('intent.json',intent)
    try:
        if docker.call('GET','/images/'+image+'/json')['Id']!=image:raise RuntimeError('immutable image required')
        intent['create_attempted']=True;save('intent.json',intent)
        result=docker.call('POST','/containers/create?name='+name,config)
        intent['container_id']=result['Id'];intent['create_returned']=True;save('intent.json',intent)
        inspect();docker.call('POST','/containers/'+result['Id']+'/start')
        for _ in range(40):
            ready=execute(['test','-f','/tmp/drsp-clients.json'],success=False)
            if ready.returncode==0:break
            time.sleep(.1)
        else:raise RuntimeError('fixture serial readiness timed out')
        before=json.loads(execute(['cat','/tmp/drsp-clients.json']).stdout)
        for source,target in (('entrypoint.sh','/entrypoint.sh'),('inventory.py','/usr/local/lib/dnlab-inventory.py')):
            expected=hashlib.sha256((ROOT/'src/multinode/jumphost'/source).read_bytes()).hexdigest()
            actual=execute(['sha256sum',target]).stdout.split()[0]
            if actual!=expected:raise RuntimeError('candidate source differs')

        observe="import json,os; p=json.load(open('/tmp/drsp-clients.json')); print(json.dumps([os.path.exists('/proc/'+str(v)) and open('/proc/'+str(v)+'/stat').read().split()[2]!='Z' for v in p]))"
        assert json.loads(execute(['python3','-c',observe]).stdout)==[True,True]
        relay._cleanup_container_telnet(intent['container_id'],'5000')
        assert json.loads(execute(['python3','-c',observe]).stdout)==[False,True]
        report['checks'].append('real pidfd recovery terminates only selected TCP serial client; other port preserved')
        broker=relay._ConsoleBroker(intent['container_id'])
        broker._start_upstream(['docker','exec','-it',intent['container_id'],'telnet','127.0.0.1','5000'],'5000')
        deadline=time.monotonic()+5
        while time.monotonic()<deadline:
            with broker._lock:
                if b'fixture serial ready' in broker._history:break
            time.sleep(.05)
        else:raise RuntimeError('new upstream did not receive synthetic serial payload')
        broker.close()
        if broker._cleanup_error is not None:raise RuntimeError('broker cleanup failed')
        assert json.loads(execute(['python3','-c',observe]).stdout)==[False,True]
        report['checks'].append('real broker reopens recovered serial, receives server payload and closes without affecting control port')

        desired={'lab':'fixture','generation':token,'container_id':intent['container_id'],'request_id':token,
                 'vds':'r1=fixture-runtime\n','relays':'fixture-runtime=192.0.2.10:23001:fixture-key\n','motd':'fixture\n'}
        execute(['python3','/usr/local/lib/dnlab-inventory.py'],json.dumps({'action':'apply','previous':None,'desired':desired}))
        readable=execute(['su','-s','/bin/sh','labuser','-c','cat /etc/dnlab-relays']).stdout
        assert readable==desired['relays']
        assert execute(['su','-s','/bin/sh','nobody','-c','cat /etc/dnlab-relays'],success=False).returncode!=0
        bootstrap="from pathlib import Path; import subprocess; s=Path('/entrypoint.sh').read_text(); s=s[s.index('# A qualified refresh'):s.index('# ── Routing / NAT')]; subprocess.run(['bash','-ec',s],check=True)"
        execute(['python3','-c',bootstrap])
        assert execute(['cat','/etc/dnlab-relays']).stdout==desired['relays']
        report['checks'].append('candidate entrypoint restores persistent relay map despite missing bootstrap environment; labuser reads and nobody is denied')
        assert inspect()['Id']==intent['container_id'] and before[1]>0
        report['status']='passed'
    except Exception as error:
        failure=error;report.update(status='failed',error_type=type(error).__name__,error=str(error))
    finally:
        try:
            if broker is not None:broker.close()
            value=inspect()
            if value is None and intent['create_attempted'] and not intent['create_returned']:
                raise RuntimeError('create outcome uncertain; cleanup_pending retained for explicit recovery')
            if value:
                if value['State']['Running']:
                    docker.call('POST','/containers/'+value['Id']+'/kill?signal=SIGTERM')
                    if docker.call('POST','/containers/'+value['Id']+'/wait?condition=not-running').get('StatusCode')!=0:
                        raise RuntimeError('fixture shutdown failed')
                inspect();docker.call('DELETE','/containers/'+value['Id']+'?force=false')
            report['cleanup_verified']=inspect() is None
        except Exception as error:report.update(status='failed',cleanup_error=str(error))
        save('report.json',report)
    print(json.dumps(report))
    if failure:raise failure
    if report['status']!='passed':raise RuntimeError('fixture cleanup incomplete')


if __name__=='__main__':
    parser=argparse.ArgumentParser();parser.add_argument('--output',required=True);parser.add_argument('--image',required=True);args=parser.parse_args()
    run(args.output,args.image)
