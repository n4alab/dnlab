"""Runtime relay sidecar management.

One relay runs on every host that owns VDs for a lab. It exposes only lab
allowlisted console/log operations to jumphost and GUI clients.
"""

from __future__ import annotations

import logging
import shlex
import secrets
import json
from pathlib import Path
import uuid

from .paths import PATHS
from .jumphost import _WORKER_BOOTSTRAP

from dnlab_multinode.models.schedule import SchedulePlan
from dnlab_multinode.models.topology import DistributedTopology
from dnlab_multinode.services.images import image_for
from dnlab_multinode.services.ssh import SSHClient
from dnlab_multinode.utils.ids import runtime_relay_port
from dnlab_multinode.utils.naming import (
    micro_vd_container_name,
    runtime_relay_container_name,
)

log = logging.getLogger(__name__)

_CAPABILITY_LABEL = "io.dnlab.runtime-relay.capabilities"
_PREFIX_CAPABILITY = "lab-prefix-console-port-v1"
_MULTISESSION_CAPABILITY = "multisession-console-v1"
_REQUIRED_CAPABILITIES = {_PREFIX_CAPABILITY, _MULTISESSION_CAPABILITY}


def _capabilities(value: str) -> set[str]:
    return {item.strip() for item in value.split(",") if item.strip()}


def generate_api_key() -> str:
    return secrets.token_urlsafe(32)


def _containers_for_host(
    lab_name: str, plan: SchedulePlan, host_name: str,
) -> list[str]:
    assignment = plan.assignments.get(host_name)
    if not assignment:
        return []
    return [micro_vd_container_name(lab_name, vd) for vd in assignment.vd_names]


def _allowed_prefix(lab_name: str) -> str:
    """Return the namespace shared by all per-VD containers in one lab."""
    return f"clab-dnlab-{lab_name}-"


def _guard(client,lab,host,action,config=None,generation=None):
    base=Path(__file__).with_name('jumphost_host.py').read_text()
    worker=Path(__file__).with_name('relay_host.py').read_text()
    source="_primitives={'__name__':'_relay_primitives'}\nexec("+repr(base)+",_primitives)\n"
    source+="_BaseWorker=_primitives['Worker']\nDockerExecHTTP=_primitives['DockerExecHTTP']\ncanonical=_primitives['canonical']\ndigest=_primitives['digest']\n"+worker
    request={'lab':lab,'host':host,'action':action,'config':config,'generation':generation,'directory':PATHS.relay_journal_dir,
             'socket_path':PATHS.docker_socket.removeprefix('unix://')}
    try:
        result=json.loads(client.run_input(shlex.join(['python3','-c',_WORKER_BOOTSTRAP]),
                         json.dumps({'source':source,'request':request}),timeout=60))
    except Exception as error:raise RuntimeError('relay operation rejected or recovery required; journal retained') from error
    if not isinstance(result,dict) or 'phase' not in result:raise RuntimeError('invalid relay acknowledgement')
    return result


def _config(topo,host,containers,bind_ip,api_key,previous):
    prior=previous.get('config',{}) if previous['phase']!='cleaned' else {}
    socket=PATHS.docker_socket.removeprefix('unix://')
    return {'lab':topo.name,'host':host,'generation':prior.get('generation') or uuid.uuid4().hex,
            'name':runtime_relay_container_name(topo.name),'image':image_for('runtime-relay'),
            'bind_ip':bind_ip,'port':runtime_relay_port(topo.name),'api_key':api_key,
            'allowed':prior.get('allowed',containers),'prefix':_allowed_prefix(topo.name),'docker_socket':socket}


def _metadata(record,containers):
    if record['phase']!='active' or not record.get('container_id'):raise RuntimeError('qualified active relay required')
    c=record['config']
    return {'container':c['name'],'bind_ip':c['bind_ip'],'port':c['port'],'api_key':c['api_key'],
            'allowed':containers,'generation':c['generation'],'container_id':record['container_id']}


def _deploy_runtime_relay(topo,host_name,containers,client,bind_ip,api_key):
    previous=_guard(client,topo.name,host_name,'preflight')
    config=_config(topo,host_name,containers,bind_ip,api_key,previous)
    _guard(client,topo.name,host_name,'preflight',config)
    return _metadata(_guard(client,topo.name,host_name,'provision' if previous['phase']=='cleaned' else 'ensure',config),containers)


def deploy_runtime_relays(topo,plan,clients,underlay_ips,api_key):
    return _reconcile(topo,plan,clients,underlay_ips,api_key,{})


def _reconcile(topo,plan,clients,underlay_ips,api_key,current):
    planned=[]
    # Complete every host's read-only preflight before the first allocation.
    for host,client in sorted(clients.items()):
        containers=_containers_for_host(topo.name,plan,host)
        previous=_guard(client,topo.name,host,'preflight')
        saved=current.get(host)
        if saved and (not getattr(saved,'generation','') or previous.get('config',{}).get('generation')!=saved.generation
                      or previous.get('container_id')!=getattr(saved,'container_id','')):
            raise RuntimeError('relay coordinator generation unqualified or replaced')
        if not containers:
            if previous['phase'] not in ('absent','cleaned'):
                if not saved:raise RuntimeError('unassigned relay requires qualified cleanup intent')
                _guard(client,topo.name,host,'preflight-delete',generation=saved.generation)
                planned.append((host,client,None,previous,containers))
            continue
        config=_config(topo,host,containers,underlay_ips[host],api_key,previous)
        _guard(client,topo.name,host,'preflight',config)
        planned.append((host,client,config,previous,containers))
    results={}
    for host,client,config,previous,containers in planned:
        if config is None:
            _guard(client,topo.name,host,'delete',generation=previous['config']['generation']);continue
        record=_guard(client,topo.name,host,'provision' if previous['phase']=='cleaned' else 'ensure',config)
        results[host]=_metadata(record,containers)
    return results


def reconcile_runtime_relays(topo,plan,clients,underlay_ips,api_key,current):
    """Re-observe the original generation; prefix capability admits new VD names."""
    return _reconcile(topo,plan,clients,underlay_ips,api_key,current)


def recover_runtime_relay(lab_name,host,client):
    return _guard(client,lab_name,host,'recover')


def preflight_relay_cleanup(lab_name,host,client,generation):
    if not generation:raise RuntimeError('qualified relay coordinator generation required')
    return _guard(client,lab_name,host,'preflight-delete',generation=generation)


def verify_relay_cleaned(lab_name,host,client,generation):
    if not generation:raise RuntimeError('qualified relay coordinator generation required')
    return _guard(client,lab_name,host,'verify-cleaned',generation=generation)


def destroy_runtime_relays(lab_name,clients,current=None):
    current=current or {}
    for host in current:
        if host not in clients:raise RuntimeError('relay host unavailable; cleanup retained')
    for host,client in sorted(clients.items()):
        previous=_guard(client,lab_name,host,'preflight')
        if previous['phase']=='absent':continue
        saved=current.get(host)
        if not saved or getattr(saved,'container_id','')!=previous.get('container_id'):
            raise RuntimeError('relay cleanup requires original coordinator proof')
        preflight_relay_cleanup(lab_name,host,client,getattr(saved,'generation',''))
    for host,saved in current.items():
        _guard(clients[host],lab_name,host,'delete',generation=saved.generation)
