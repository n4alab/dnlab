#!/usr/bin/env python3
"""Opt-in isolated external jumphost network ownership/crash gate."""
import argparse
import hashlib
import ipaddress
import json
import multiprocessing
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
import uuid

SOURCE = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(SOURCE/'multinode'), str(SOURCE/'runtime')]
from dnlab_multinode.services.jumphost_network_host import Worker, Docker, NetworkError
from dnlab_runtime.backend import Docker as FixtureDocker


def run(output):
    root = Path(output); root.mkdir(mode=0o700, exist_ok=False)
    docker = Docker(); fixture_docker = FixtureDocker(); workers = []
    baseline = sorted(v['Id'] for v in docker.inventory())
    plugin = Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
    plugin_state = Path('/var/lib/dnlab-vrf-plugin/state.json')
    plugin_hash = hashlib.sha256(plugin.read_bytes()).hexdigest()
    plugin_before = json.loads(plugin_state.read_text())
    report = {'status':'running','scope':'shared external network birth/identity/recovery; no VD or DHCP qualification','cases':[]}
    token = uuid.uuid4().hex[:6]
    def save(): (root/'report.json').write_text(json.dumps(report,indent=2)+'\n')
    save()
    reserved = [ipaddress.ip_network(v['Subnet']) for row in docker.inventory()
                for v in (row.get('IPAM') or {}).get('Config') or [] if v.get('Subnet')]
    routes = json.loads(subprocess.check_output(['ip','-j','route','show','table','all'],text=True))
    reserved += [ipaddress.ip_network(v['dst']) for v in routes if v.get('dst') and v['dst'] != 'default']
    pool = (v for v in ipaddress.ip_network('198.18.0.0/15').subnets(new_prefix=28)
            if not any(other.version == 4 and v.overlaps(other) for other in reserved))
    def make(index):
        subnet = next(pool)
        cfg = dict(network='drsp-jhn-'+token+'-'+str(index), bridge='drspj'+token+str(index),
                   subnet=str(subnet), gateway=str(subnet.network_address+1))
        worker = Worker(cfg,directory=root/str(index)); workers.append(worker)
        with (root/'intent.json').open('w') as stream:
            json.dump({'networks':[dict(config=w.config,directory=str(w.directory)) for w in workers],
                       'baseline_network_ids':baseline,'plugin_sha256':plugin_hash,'plugin_state':plugin_before},stream,indent=2)
            stream.flush(); os.fsync(stream.fileno())
        fd = os.open(root,os.O_DIRECTORY)
        try: os.fsync(fd)
        finally: os.close(fd)
        return worker
    def snapshot(worker):
        record = worker.read(); value,_ = worker.observe(); worker.verify(record,value)
        return {'id':value['Id'],'created':value['Created'],'labels':value['Labels'],'options':value['Options'],
                'ipam':value['IPAM'],'bridge':worker.signature(worker.bridge())}
    def standalone(worker, action):
        program = SOURCE/'multinode/dnlab_multinode/services/jumphost_network_host.py'
        request = dict(config=worker.config,directory=str(worker.directory),socket='/var/run/docker.sock',action=action)
        value = subprocess.run([sys.executable,'-c',program.read_text()],input=json.dumps(request),text=True,capture_output=True,timeout=50)
        if value.returncode: raise RuntimeError('standalone worker failed: '+value.stderr[-2000:])
        return json.loads(value.stdout)
    try:
        control = make(0)
        assert control.preflight()['network_id'] is None
        ack = control.operate(); original = snapshot(control); body = control.path.read_bytes()
        assert standalone(control,'ensure')['network_id'] == ack['network_id']
        assert control.path.read_bytes() == body and snapshot(control) == original
        report['cases'].append('same qualified generation reused by standalone caller')
        for index,(stage,when) in enumerate([(s,w) for s in ('intent','create','id','active') for w in ('before','after')],1):
            worker = make(index)
            def child():
                own = Worker(worker.config,directory=worker.directory)
                original_save = own.save; original_create = own.docker.create
                def kill(): os.kill(os.getpid(),signal.SIGKILL)
                def save_record(record):
                    match = (stage=='intent' and not record['id'] or stage=='id' and record['id'] and not record['bridge']
                             or stage=='active' and record['phase']=='active')
                    if match and when=='before': kill()
                    original_save(record)
                    if match and when=='after': kill()
                def create(payload):
                    if stage=='create' and when=='before': kill()
                    value = original_create(payload)
                    if stage=='create' and when=='after': kill()
                    return value
                own.save = save_record; own.docker.create = create; own.operate()
            process = multiprocessing.get_context('fork').Process(target=child)
            process.start(); process.join(40)
            if process.is_alive():
                process.kill(); process.join(); raise RuntimeError('owned fixture worker timeout')
            assert process.exitcode == -signal.SIGKILL
            before,_ = worker.observe(); record = worker.read()
            recovered = standalone(worker,'ensure' if record is None else 'recover')
            if before: assert recovered['network_id'] == before['Id']
            stable = snapshot(worker); journal = worker.path.read_bytes()
            assert standalone(worker,'ensure')['network_id'] == stable['id']
            assert snapshot(worker) == stable and worker.path.read_bytes() == journal
            assert snapshot(control) == original and control.path.read_bytes() == body
            report['cases'].append(dict(stage=stage,when=when,id=stable['id'],recovered=True)); save()
        incompatible = Worker(dict(control.config, gateway=str(ipaddress.ip_address(control.config['gateway'])+1)), directory=control.directory)
        try: incompatible.operate()
        except NetworkError: pass
        else: raise RuntimeError('incompatible shared network accepted')
        try: Worker(control.config,directory=root/'unqualified').operate()
        except NetworkError: pass
        else: raise RuntimeError('shared network adopted without original intent')
        try: control.operate('delete')
        except NetworkError: pass
        else: raise RuntimeError('per-lab shared network deletion exposed')
        assert snapshot(control) == original and control.path.read_bytes() == body
        report['cases'].append('incompatible/unqualified reuse and per-lab delete refused; control unchanged')
        report['status'] = 'passed'
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error)); raise
    finally:
        errors = []
        for worker in reversed(workers):
            try:
                value,_ = worker.observe()
                if value:
                    # Recovery is allowed only for this fixture's prior durable
                    # intent; it qualifies the existing generation before delete.
                    worker.operate('recover'); record = worker.read()
                    worker.verify(record,value)
                    if value['Containers']: raise RuntimeError('fixture network still has consumers')
                    fixture_docker.request('DELETE','/networks/'+value['Id'])
                deadline = time.monotonic()+5
                while worker.bridge() is not None and time.monotonic()<deadline: time.sleep(.05)
                assert worker.docker.inspect(worker.config['network']) is None and worker.bridge() is None
            except Exception as error: errors.append(str(error))
        report['cleanup'] = dict(verified=not errors,errors=errors)
        try:
            assert sorted(v['Id'] for v in docker.inventory()) == baseline
            assert hashlib.sha256(plugin.read_bytes()).hexdigest() == plugin_hash
            assert json.loads(plugin_state.read_text()) == plugin_before
            report['baseline_verified'] = True
        except Exception as error:
            report['baseline_verified'] = False; errors.append('baseline verification: '+str(error))
            report['cleanup']['verified'] = False
        save()
    if not report['cleanup']['verified']: raise RuntimeError('fixture cleanup incomplete: '+repr(errors))
    return root


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--execute',action='store_true'); parser.add_argument('--output',required=True); args=parser.parse_args()
    if not args.execute: parser.error('explicit --execute required')
    print(run(args.output))
