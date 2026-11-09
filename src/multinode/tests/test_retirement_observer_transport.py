"""Actual stdin worker transport against an inert Unix HTTP server."""
from dataclasses import replace
import json
from http.server import BaseHTTPRequestHandler
import shlex
import socketserver
import subprocess
import threading

import pytest

from dnlab_multinode.services.retirement_observer import NetworkObserver,program
from dnlab_multinode.services.paths import PATHS
from dnlab_multinode.services.runtime_operations import RuntimeOperationError


@pytest.mark.parametrize('present',[False,True])
def test_original_absence_worker_only_gets_id_and_name(tmp_path,present):
    requests=[]
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            requests.append(self.path)
            payload=json.dumps({'Id':'a'*64} if present else {'message':'No such container'}).encode()
            self.send_response(200 if present else 404);self.send_header('Content-Length',str(len(payload)));self.end_headers();self.wfile.write(payload)
        def log_message(self,*args):pass
    server=socketserver.UnixStreamServer(str(tmp_path/'http.sock'),Handler)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    class Client:
        def run_input(self,command,payload,**kwargs):
            argv=shlex.split(command)
            assert sum(len(a) for a in argv)<4096
            assert len(json.loads(payload)['source'])>10000
            result=subprocess.run(argv,input=payload,text=True,capture_output=True,timeout=kwargs['timeout'])
            if result.returncode:raise RuntimeOperationError(result.stderr)
            return result.stdout
    observer=NetworkObserver({'plans':{'master':{}},'networks':{'master':{}}},{'master':Client()},
        paths=replace(PATHS,docker_socket='unix://'+str(tmp_path/'http.sock')))
    births={'R1':{'target':{'host':'master'},'binding':{'container_id':'a'*64},'request':{'spec':{'container_name':'original-vd'}}}}
    try:
        if present:
            with pytest.raises(RuntimeOperationError,match='remains or was replaced'):observer.verify_absent(births)
            assert requests==['/containers/'+'a'*64+'/json']
        else:
            observer.verify_absent(births)
            assert requests==['/containers/'+'a'*64+'/json','/containers/original-vd/json']
    finally:server.shutdown();server.server_close();thread.join(timeout=3)


def test_wrong_observer_response_is_not_absence():
    class Client:
        def run_input(self,*a,**k):return '{}'
    observer=NetworkObserver({'plans':{'master':{}},'networks':{'master':{}}},{'master':Client()})
    with pytest.raises(RuntimeOperationError,match='acknowledgement differs'):
        observer.invoke('master',{'action':'absence','containers':[]})
