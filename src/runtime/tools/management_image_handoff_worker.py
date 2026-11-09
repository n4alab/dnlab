"""Fixture program supplied to a tracked Docker exec; not a production API."""
import hashlib
import importlib
import json
import os
from pathlib import Path
import signal
import sqlite3
import sys
import time

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.stable_management import Handoff,StablePort


def run(config):
    journal=Journal(Path(config['state_dir']));backend=Backend();Engine(journal,backend)
    port=StablePort(backend,config['request'],config['spec'],config['mac'])
    handoff=Handoff(journal,backend,config['request'],config['spec'],port,spike_owner=config['spike_owner'])
    def record(stage,**extra):
        event={'stage':stage,'action':config['action'],'lab':config['request']['lab_id'],
               'node':config['request']['node_id'],'pid':os.getpid(),'monotonic_ns':time.monotonic_ns(),**extra}
        fd=os.open(config['events'],os.O_WRONLY|os.O_CREAT|os.O_APPEND,0o600)
        try:
            data=(json.dumps(event)+'\n').encode()
            while data:data=data[os.write(fd,data):]
            os.fsync(fd)
        finally:os.close(fd)
    def crash(stage):
        record('crash',boundary=stage);os.kill(os.getpid(),signal.SIGKILL)
    try:
        modules={}
        for name in ('backend','stable_management','management_authority','execution','kernel_endpoint'):
            path=Path(importlib.import_module('dnlab_runtime.'+name).__file__)
            if '/site-packages/dnlab_runtime/' not in str(path):raise RuntimeError('worker must import installed image modules')
            modules[name]={'path':str(path),'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
        record('started',modules=modules,network_identity=backend.linux.network_identity())
        action=config['action']
        if action=='submit':
            result=handoff.submit(config['request_id'],config['target_name'],config['target_ip'],expected_node_revision=config['revision'])
        else:
            operation_id=config['operation_id']
            if action=='execute':
                original=handoff.phase
                def phase(identity,value,error=''):
                    if value=='completed' and config.get('crash')=='before':crash('before')
                    original(identity,value,error)
                    if value=='completed' and config.get('crash')=='after':crash('after')
                handoff.phase=phase
                if config.get('crash')=='during':
                    def interrupt(action,table,column,*args):
                        if action==sqlite3.SQLITE_UPDATE and table=='nodes' and column=='revision':crash('during')
                        return sqlite3.SQLITE_OK
                    journal.db.set_authorizer(interrupt)
                if config.get('fail_target_bind'):
                    target=handoff.get(operation_id)['payload']['target'];original_bind=port.bind
                    def bind(connection,**kwargs):
                        if connection==target:raise RuntimeErrorBase('fixture post-connect bind failure')
                        return original_bind(connection,**kwargs)
                    port.bind=bind
                result=handoff.execute(operation_id)
            elif action=='get':result=handoff.get(operation_id)
            elif action=='rollback':result=handoff.rollback(operation_id)
            else:raise RuntimeError('unsupported fixture worker action')
        record('finished',operation_id=result['id'],phase=result['phase'])
        return result
    except RuntimeErrorBase as error:
        record('refused',error_type=type(error).__name__,detail=str(error))
        raise
    finally:journal.close()


if __name__=='__main__':
    try:print(json.dumps({'ok':True,'result':run(json.load(sys.stdin))}))
    except RuntimeErrorBase as error:
        print(json.dumps({'ok':False,'error_type':type(error).__name__,'error':str(error)}));sys.exit(1)
