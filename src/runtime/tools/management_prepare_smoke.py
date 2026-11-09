#!/usr/bin/env python3
"""Local offline infrastructure gate; no service or physical multihost claim."""
import argparse
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shlex
import subprocess
import sys
import tempfile
import uuid

SOURCE=Path(__file__).resolve().parents[1]
sys.path[:0]=[str(SOURCE),str(SOURCE.parent/'multinode')]
from dnlab_multinode.controllers.management_prepare import ManagementPreparation
from dnlab_multinode.models.topology import DistributedTopology,InfraHost,MgmtConfig,JumphostConfig,JumphostNet
from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.models.state import DeploymentState
from dnlab_multinode.services import netsetup,management_barrier as barrier,state as states
from dnlab_multinode.services.custom_runtime import RuntimeClient
from dnlab_multinode.services.realnet_vni import Registry
from dnlab_multinode.services.runtime_operations import OperationStore
from dnlab_runtime.backend import Docker,Linux
from management_barrier_smoke import Local
from smoke import Service,command

PLUGIN=Path('/opt/dnlab-vrf-plugin/dnlab_vrf_plugin.py')
PLUGIN_STATE=Path('/var/lib/dnlab-vrf-plugin/state.json')


class Host:
    def __init__(self):self.lose=False;self.events=[]
    def run(self,cmd):return self.run_input(cmd,None)
    def run_input(self,cmd,payload,**kwargs):
        result=subprocess.run(shlex.split(cmd),input=payload,text=True,capture_output=True,
                              timeout=kwargs.get('timeout',180))
        try:action=json.loads(payload).get('action') if payload else 'inventory'
        except (ValueError,AttributeError):action='inventory'
        self.events.append({'action':action,'exit_code':result.returncode,'stderr':result.stderr})
        if result.returncode:raise RuntimeError('fixture worker rejected '+str(action)+': '+result.stderr.strip())
        if self.lose and action=='network-recover':self.lose=False;raise OSError('injected lost network reply')
        return result.stdout


def run(plugin_sha256):
    if hashlib.sha256(PLUGIN.read_bytes()).hexdigest()!=plugin_sha256:raise RuntimeError('installed plugin fingerprint differs')
    baseline=json.loads(PLUGIN_STATE.read_text());root=Path(tempfile.mkdtemp(prefix='dnlab-management-prepare-'));root.chmod(0o700)
    lab='drsp-'+uuid.uuid4().hex[:10];directory=root/'runtime';directory.mkdir(mode=0o700)
    report={'status':'running','scope':'single local host, empty lab, two management L2 segments; infrastructure only',
            'services_qualified':False,'physical_multihost_qualified':False,'checks':[]}
    service=Service('native',directory,None,lab);store=None;state=None;controller=None;registry=Registry(root/'vni');host=Host()
    original_paths=netsetup.PATHS
    netsetup.PATHS=replace(original_paths,management_journal_dir=str(root/'management'))
    (root/'plugin-baseline.json').write_text(json.dumps(baseline,indent=2)+'\n')
    def save():states.save_state(state,root)
    def infrastructure_ready(plan,targets):
        current=barrier.get(store,lab)
        if current['infrastructure']['phase']!='infrastructure-ready':raise RuntimeError('fixture infrastructure not verified')
        return {'plan_fingerprint':barrier.digest(plan),'hosts':netsetup.verify_management_ready(state,{'master':host})}
    try:
        service.start();local=Local();runtime=RuntimeClient(local,socket_path=service.client.socket_path)
        journal=runtime.qualify_node(inspection=True)['journal_id'];runtime=runtime.bound_to(journal)
        targets={'master':{'target':{'host':'master','socket_path':service.client.socket_path,'container_name':None},'journal_id':journal}}
        store=OperationStore(root/'coordinator');controller=ManagementPreparation(store,lambda target:runtime)
        occupied={v.get('linkinfo',{}).get('info_data',{}).get('table') for v in json.loads(command(['ip','-j','-d','link','show']))}
        occupied.update(v.get('table') for v in json.loads(command(['ip','-j','route','show','table','all'])))
        table=next(v for v in range(49000,50000) if v not in occupied)
        topo=DistributedTopology(name=lab,master=InfraHost(name='master',host='127.0.0.1',ssh_user='root',ssh_key='unused',is_master=True),workers={},underlay_iface='lo',nodes={},links=[],
            jumphost=JumphostConfig(),jumphost_net=JumphostNet(network='fixture-unallocated',bridge='fixture-unused',ipv4_subnet='198.19.230.0/24',ipv4_gw='198.19.230.1'),
            mgmt=MgmtConfig(network='fixture-unallocated',bridge='fixture-unused',ipv4_subnet='198.19.233.0/24',ipv4_gw='198.19.233.254'))
        topo.raw={'management_networks':{'default':{'ipv4-subnet':'198.19.233.0/24','ipv6-subnet':'2001:db8:233::/64'}}}
        schedule=SchedulePlan(lab_name=lab,assignments={},vrf_table_id=table)
        state=DeploymentState(lab_name=lab,topology_file=str(root/'fixture.yml'),runtime_mode='custom',vrf_table_id=table)
        first=controller.apply('initial',topo,schedule,{'master':'127.0.0.1'},targets,state,{'master':host},save,registry=registry)
        assert first['phase']=='provisioning' and first['infrastructure']['phase']=='infrastructure-ready'
        first_proof=deepcopy(first['infrastructure']['proofs']['master'])
        assert controller.driver.release(lab,'initial',infrastructure_ready)['phase']=='released'
        report['checks'].append('empty initial management prepared with real kernel, Docker, plugin and strict readonly proof')
        topo.raw['management_networks']['blue']={'ipv4-subnet':'198.19.234.0/24','ipv6-subnet':'2001:db8:234::/64'}
        host.lose=True
        try:controller.apply('add-blue',topo,schedule,{'master':'127.0.0.1'},targets,state,{'master':host},save,registry=registry)
        except OSError as error:
            if str(error)!='injected lost network reply':raise
        else:raise AssertionError('lost reply not injected')
        assert barrier.get(store,lab)['phase']=='provisioning'
        store.close();store=OperationStore(root/'coordinator');controller=ManagementPreparation(store,lambda target:runtime)
        result=controller.apply('add-blue',topo,schedule,{'master':'127.0.0.1'},targets,state,{'master':host},save,registry=registry)
        assert result['infrastructure']['phase']=='infrastructure-ready'
        final=result['infrastructure']['proofs']['master']
        for name,identity in first_proof['kernel']['proof']['resources'].items():
            assert final['kernel']['proof']['resources'][name]==identity
        assert final['networks']['proof']['networks']['default']==first_proof['networks']['proof']['networks']['default']
        assert set(final['networks']['proof']['networks'])=={'default','blue'}
        body={'schema_version':1,'lab_id':lab,'node_id':'vd','request_id':'denied-start','action':'start','expected_revision':0,
              'spec':{'kind':'linux','image':'sha256:'+'a'*64,'container_name':'drsp-'+lab+'-vd'}}
        try:runtime.submit_node(body)
        except RuntimeError:pass
        else:raise AssertionError('workload start crossed infrastructure-only barrier')
        report['checks'].append('tracked add preserves original resource identities and network ID/nonce; lost reply recovery reopens original journal')
        report['checks'].append('workload start remains fenced until explicit fixture-only infrastructure readiness attestation')
        # This empty fixture has no service intent. Production full deployment
        # still requires actual services; this release qualifies infrastructure only.
        controller.driver.release(lab,'add-blue',infrastructure_ready)
        report['proofs']={'initial':first_proof,'expanded':final};report['status']='passed'
    except Exception as error:
        report.update(status='failed',error_type=type(error).__name__,error=str(error));raise
    finally:
        errors=[];known_network_ids=[];known_links=[]
        if state and state.mgmt:
            try:
                record=netsetup.invoke(host,'read',state.mgmt.infrastructure['plans']['master'])['record']
                if record:
                    known_network_ids=[row['id'] for row in record.get('networks',{}).values() if row.get('id')]
                    known_links=list(record.get('resources',{}))
                netsetup.destroy_management(state,{'master':host},checkpoint=save,registry=registry)
            except Exception as error:errors.append(type(error).__name__+': '+str(error))
        try:service.stop()
        except Exception as error:errors.append(type(error).__name__+': '+str(error))
        if store is not None:store.close()
        netsetup.PATHS=original_paths
        api=Docker();linux=Linux()
        if any(api.request('GET','/networks/'+identity,missing_ok=True) is not None for identity in known_network_ids):errors.append('network residual')
        if any(linux.link(name) is not None for name in known_links):errors.append('kernel residual')
        if json.loads(PLUGIN_STATE.read_text())!=baseline or hashlib.sha256(PLUGIN.read_bytes()).hexdigest()!=plugin_sha256:errors.append('plugin baseline differs')
        report['cleanup']={'verified':not errors,'errors':errors,'network_ids':known_network_ids,'kernel_names':known_links,
                           'daemon_stopped':service.process is None,'plugin_source_and_state_unchanged':not any('plugin' in e for e in errors)}
        report['events']=host.events
        if errors:report['status']='failed'
        (root/'report.json').write_text(json.dumps(report,indent=2)+'\n');print(root/'report.json',flush=True)
    assert report['cleanup']['verified']
    return report


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__);parser.add_argument('--execute',action='store_true',required=True)
    parser.add_argument('--plugin-sha256',required=True);args=parser.parse_args();run(args.plugin_sha256)
