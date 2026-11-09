"""Fixture-only qualified helpers, CLI and public inventory/lifecycle stage."""
from copy import deepcopy
import json
import os
from pathlib import Path
import re
import shlex
import socket
import stat
import threading
import uuid

from management_service_diagnostics import private_json
from native_lifecycle_fixture import LifecycleWorkload
from jumphost_cli_assets import JumphostRoot,Assets
from jumphost_cli_execution import Execution
from jumphost_cli_program import build
from relay_console_smoke import console_command,process_proof
from management_barrier_smoke import Local
from dnlab_runtime.backend import Docker
from dnlab_multinode.controllers.node import NodeLifecycleController
from dnlab_multinode.models.state import RuntimeRelayState
from dnlab_multinode.services import runtime_relay as relays, state as states
from dnlab_multinode.services.jumphost_host import Worker as JumphostWorker
from dnlab_multinode.services import jumphost
from dnlab_multinode.utils.naming import runtime_relay_container_name


def read_intent(path,*,limit=65536):
    fd=os.open(path,os.O_RDONLY|os.O_NOFOLLOW)
    with os.fdopen(fd,'rb') as stream:
        info=os.fstat(stream.fileno())
        if (not stat.S_ISREG(info.st_mode) or info.st_uid!=os.getuid()
                or stat.S_IMODE(info.st_mode)!=0o600 or info.st_nlink!=1):
            raise RuntimeError('original stage intent ownership differs')
        raw=stream.read(limit+1)
        after=os.fstat(stream.fileno())
    signature=lambda s:(s.st_dev,s.st_ino,s.st_uid,s.st_gid,s.st_mode,s.st_nlink,s.st_size,s.st_mtime_ns,s.st_ctime_ns)
    if len(raw)>limit or signature(info)!=signature(after):
        raise RuntimeError('original stage intent read incomplete')
    return json.loads(raw)


class LocalClient:
    """Public-controller transport using the existing qualified fixture host."""
    def __init__(self, host):
        self.host = host
        self.runtime_transport = Local()

    def connect(self):
        pass

    def close(self):
        pass

    def run(self, command):
        return self.run_input(command, None)

    def run_input(self, command, payload, **kwargs):
        if shlex.split(command)[:1] == ['dnlab-runtime']:
            # The native fixture runs the checkout module, not an installed CLI.
            # Keep helper guard commands on their original diagnostic transport.
            return self.runtime_transport.run_input(command, payload, **kwargs)
        return self.host.run_input(command, payload, **kwargs)

    def __getattr__(self, name):
        return getattr(self.host, name)


class NativeJumphostStage:
    def __init__(self, root, topo, state, store, runtime, host, relay_image, bind_ip, *, node='http-vd'):
        self.root, self.topo, self.state = Path(root), topo, state
        self.store, self.runtime, self.host = store, runtime, host
        self.image, self.bind_ip = relay_image, bind_ip
        self.node = node
        self.lifecycle = None
        self.config = None
        self.proof = None
        self.cli = []

    def prepare(self):
        current=states.load_state(self.topo.name,self.root)
        if current is None:raise RuntimeError('original stage deployment state missing')
        self.state=current
        if set(self.state.node_runtime) != {self.node} or not self.state.jumphost:
            raise RuntimeError('stage requires original single VD and published jumphost')
        runtime = self.state.node_runtime[self.node]
        if ((self.root/'native-jumphost-initial-publication.json').exists()
                and not (self.root/'native-jumphost-lifecycle.json').exists()):
            raise RuntimeError('original stage lifecycle history missing')
        expected = {'lab': self.topo.name, 'host': 'master',
                       'name': runtime_relay_container_name(self.topo.name), 'image': self.image,
                       'bind_ip': self.bind_ip,
                       'allowed': [runtime.container], 'prefix': relays._allowed_prefix(self.topo.name),
                       'docker_socket': relays.PATHS.docker_socket.removeprefix('unix://')}
        path=self.root/'native-jumphost-stage-intent.json'
        try:config=read_intent(path)
        except FileNotFoundError:
            if self.state.runtime_relays or self.proof or self.lifecycle or (self.root/'native-jumphost-lifecycle.json').exists():
                raise RuntimeError('original relay stage intent missing; no adoption')
            with socket.socket() as probe:
                probe.bind((self.bind_ip,0));port=probe.getsockname()[1]
            config={**expected,'generation':uuid.uuid4().hex,'port':port,'api_key':uuid.uuid4().hex}
            private_json(path,config)
        if (not isinstance(config,dict) or set(config)!=set(expected)|{'generation','port','api_key'}
                or any(config.get(k)!=v for k,v in expected.items())
                or not re.fullmatch('[0-9a-f]{32}',str(config.get('generation','')))
                or not re.fullmatch('[0-9a-f]{32}',str(config.get('api_key','')))
                or type(config.get('port')) is not int or not 1<=config['port']<=65535):
            raise RuntimeError('original relay stage intent differs')
        self.config=deepcopy(config)
        observed=relays._guard(self.host,self.topo.name,'master','preflight',self.config)
        if observed['phase']=='cleaned':raise RuntimeError('original stage already cleaned')
        if self.state.runtime_relays:
            previous=RuntimeRelayState(host='master',**relays._metadata(observed,[runtime.container]))
            if self.state.runtime_relays!={'master':previous}:
                raise RuntimeError('original published relay binding differs')
        self.proof = relays._guard(self.host, self.topo.name, 'master', 'ensure', self.config)
        metadata = relays._metadata(self.proof, [runtime.container])
        published={'master':RuntimeRelayState(host='master',**metadata)}
        if not self.state.runtime_relays:
            self.state.runtime_relays=published
            states.save_state(self.state,self.root)
        controller = object.__new__(NodeLifecycleController)
        controller.topo, controller.state, controller.state_dir = self.topo, self.state, self.root
        controller.cancel_event, controller.phase_callback = threading.Event(), None
        controller._active_clients = {}
        controller._native_clients_factory = lambda hosts: {name: LocalClient(self.host) for name in hosts}
        self.lifecycle = LifecycleWorkload(self.root / 'native-jumphost-lifecycle.json', controller,
                                            self.node, self.runtime, self.store, Docker())
        key = 'initial-inventory-' + self.config['generation']
        path=self.root/'native-jumphost-initial-publication.json'
        publication={'request_id':key,'original_birth':self.lifecycle.record['births'][0]}
        try:original=read_intent(path)
        except FileNotFoundError:private_json(path,publication)
        else:
            if original!=publication:raise RuntimeError('original stage publication intent differs')
        # Already-running public start publishes inventory without a new birth.
        # Once lifecycle steps exist, resume those original steps separately.
        if not self.lifecycle.record['steps']:
            controller.start(self.node,request_id=key)
        self.lifecycle.receipt('start', key)
        if not self.lifecycle.record['steps'] and self.lifecycle.observe('running') != self.lifecycle.record['births'][-1]:
            raise RuntimeError('initial inventory publication changed original VD')
        self.state = controller.state
        return self.state

    def restart(self):
        self.lifecycle.step('restart', 'native-jh-restart-' + self.config['generation'])
        before = deepcopy(self.lifecycle.record)
        self.lifecycle.step('restart', 'native-jh-restart-' + self.config['generation'])
        if self.lifecycle.record != before:
            raise RuntimeError('restart replay changed fixture generation history')
        self.state = self.lifecycle.controller.state
        return self.state

    def relay_snapshot(self,label):
        if label not in ('before','after'):raise ValueError('original relay observation label required')
        current=relays._guard(self.host,self.topo.name,'master','preflight',self.config)
        if current!=self.proof:raise RuntimeError('original relay journal changed')
        api=Docker();value=api.inspect(self.proof['container_id'])
        if (not value or value['Id']!=self.proof['container_id'] or value['Image']!=self.image
                or value['State']['Running'] is not True or type(value['State']['Pid']) is not int
                or value['State']['Pid']<=0):raise RuntimeError('original relay process unavailable')
        proof=process_proof(value['State']['Pid'])
        after=api.inspect(value['Id'])
        if (after is None or after['State']!=value['State'] or after['RestartCount']!=value['RestartCount']
                or process_proof(value['State']['Pid'])!=proof):
            raise RuntimeError('original relay process changed during observation')
        proof.update(container_id=value['Id'],started_at=value['State']['StartedAt'],restart_count=value['RestartCount'])
        path=self.root/('native-relay-process-'+label+'.json')
        try:original=read_intent(path)
        except FileNotFoundError:private_json(path,proof)
        else:
            if original!=proof:raise RuntimeError('original relay observation differs')
        return proof

    def probe_cli(self, label, workload_nonce):
        if label not in ('before','after') or not isinstance(workload_nonce,str) or len(workload_nonce)!=32:
            raise ValueError('original CLI stage and workload nonce required')
        worker=JumphostWorker(self.topo.name,directory=jumphost.PATHS.jumphost_journal_dir,
                              management_directory=jumphost.PATHS.management_journal_dir)
        results={}
        for action in ('connect','log'):
            slot=len(self.cli);self.cli.append(None)
            path=self.root/('cli-'+label+'-'+action+'-assets.json')
            nonce=self.cli_slot('cli-'+label+'-'+action)
            root=JumphostRoot(worker)
            command,marker=console_command(nonce) if action=='connect' else (b'\n',b'READY:'+workload_nonce.encode())
            assets=Assets(path,root,nonce,action,self.node,command,marker)
            profile=assets.prepare()
            config={'User':'labuser','Cmd':['python3','-I','-c',build(profile),nonce],
                    **{key:False for key in ('AttachStdin','AttachStdout','AttachStderr','Tty','Privileged')}}
            execution=Execution(self.root/('cli-'+label+'-'+action+'-exec.json'),Docker(),
                                assets.record['owner'],config,nonce,assets.observe,assets.result)
            self.cli[slot]=execution
            results[action]=execution.run()
        return results

    def cli_plan(self):
        path=self.root/'native-jumphost-cli-plan.json'
        try:plan=read_intent(path)
        except FileNotFoundError:return None
        allowed={'cli-'+label+'-'+action for label in ('before','after') for action in ('connect','log')}
        if (not isinstance(plan,dict) or set(plan)!={'lab','generation','slots'}
                or plan['lab']!=self.topo.name or plan['generation']!=self.config['generation']
                or not isinstance(plan['slots'],dict) or set(plan['slots'])-allowed
                or any(not re.fullmatch('[0-9a-f]{32}',str(v)) for v in plan['slots'].values())
                or len(set(plan['slots'].values()))!=len(plan['slots'])):
            raise RuntimeError('original CLI plan differs; cleanup pending')
        return plan

    def cli_slot(self,stem):
        plan=self.cli_plan()
        if plan is None:
            if list(self.root.glob('cli-*')):raise RuntimeError('original CLI plan missing; cleanup pending')
            plan={'lab':self.topo.name,'generation':self.config['generation'],'slots':{}}
        if stem not in plan['slots']:
            if list(self.root.glob(stem+'-*')):raise RuntimeError('unbound CLI journals; cleanup pending')
            plan['slots'][stem]=uuid.uuid4().hex
            private_json(self.root/'native-jumphost-cli-plan.json',plan)
        return plan['slots'][stem]

    def preflight_cli(self):
        if any(execution is None for execution in self.cli):
            raise RuntimeError('CLI initialization unresolved; cleanup pending')
        slots={'cli-'+label+'-'+action:(label,action) for label in ('before','after') for action in ('connect','log')}
        suffixes=('-assets.json','-exec.json','-assets.output.json')
        expected={stem+suffix for stem in slots for suffix in suffixes}
        inventory={path.name for path in self.root.glob('cli-*')}
        try:
            if inventory-expected:raise RuntimeError('unknown CLI journal')
            plan=self.cli_plan()
            if plan is None:
                if inventory or self.cli:raise RuntimeError('original CLI plan missing')
            elif inventory!={stem+suffix for stem in plan['slots'] for suffix in suffixes}:
                raise RuntimeError('planned CLI journals missing or unbound')
            selected=[];snapshots=[]
            # Census all persisted records before inspecting any remote exec.
            for stem,(_,action) in slots.items():
                paths=[self.root/(stem+suffix) for suffix in suffixes]
                if not any(path.name in inventory for path in paths):continue
                if not all(path.name in inventory for path in paths):raise RuntimeError('partial CLI journals')
                asset=read_intent(paths[0]);execution=read_intent(paths[1],limit=1048576)
                captured=read_intent(paths[2],limit=4194304)
                snapshots.extend(((paths[0],asset,65536),(paths[1],execution,1048576),(paths[2],captured,4194304)))
                if (asset.get('action')!=action or asset.get('node')!=self.node or asset.get('identity') is None
                        or asset.get('nonce')!=plan['slots'][stem]
                        or execution.get('owner')!=asset.get('owner') or execution.get('nonce')!=asset.get('nonce')
                        or execution.get('phase')!='completed' or execution.get('exit_verified') is not True
                        or execution.get('create_attempted') is not True or execution.get('start_attempted') is not True):
                    raise RuntimeError('unresolved or conflicting CLI journals')
                selected.append((paths,asset))
            results=[]
            if selected:
                worker=JumphostWorker(self.topo.name,directory=jumphost.PATHS.jumphost_journal_dir,
                                      management_directory=jumphost.PATHS.management_journal_dir)
                root=JumphostRoot(worker)
                for paths,row in selected:
                    asset=Assets(paths[0],root,row['nonce'],row['action'],self.node,
                                 bytes.fromhex(row['command_hex']),bytes.fromhex(row['marker_hex']),readonly=True)
                    profile=asset.profile()
                    config={'User':'labuser','Cmd':['python3','-I','-c',build(profile),row['nonce']],
                            **{key:False for key in ('AttachStdin','AttachStdout','AttachStderr','Tty','Privileged')}}
                    actor=Execution(paths[1],Docker(),asset.record['owner'],config,row['nonce'],
                                    lambda asset=asset:asset.observe(readonly=True),
                                    lambda record,status,asset=asset:asset.result(record,status,readonly=True),readonly=True)
                    results.append(actor.verify_completed())
            if {path.name for path in self.root.glob('cli-*')}!=inventory:
                raise RuntimeError('CLI journal census changed')
            if self.cli_plan()!=plan or any(read_intent(path,limit=limit)!=value for path,value,limit in snapshots):
                raise RuntimeError('original CLI journal changed during preflight')
            return results
        except Exception as error:
            raise RuntimeError('CLI journal recovery pending; dependent cleanup refused') from error

    def cleanup(self):
        executions=self.preflight_cli()
        if self.lifecycle is None:
            raise RuntimeError('stage initialization incomplete; recovery required')
        self.lifecycle.cleanup('native-jh-stop-' + self.config['generation'])
        current = relays._guard(self.host, self.topo.name, 'master', 'read')
        if (current['container_id'] != self.proof['container_id'] or current['config'] != self.config
                or current['nonce'] != self.proof['nonce']):
            raise RuntimeError('stage original relay changed before cleanup')
        relays._guard(self.host, self.topo.name, 'master', 'preflight-delete',
                      generation=self.config['generation'])
        relays._guard(self.host, self.topo.name, 'master', 'delete', generation=self.config['generation'])
        cleaned = relays._guard(self.host, self.topo.name, 'master', 'read')
        if cleaned['phase'] != 'cleaned' or Docker().inspect(self.proof['container_id']) is not None:
            raise RuntimeError('stage original relay cleanup incomplete')
        return {'verified': True, 'lifecycle': deepcopy(self.lifecycle.record),
                'relay_container_id': self.proof['container_id'],
                'cli_exec_ids':[record['id'] for record in executions]}
