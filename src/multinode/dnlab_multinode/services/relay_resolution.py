"""Read-only console/log routing from the original native workload binding."""
import re

from . import native_public as native, runtime_relay as relays
from .hosts_config import load_hosts_config
from .ssh import create_clients

CAPABILITY='qualified-container-id-v1'


def qualify_relay(ssh,state,host,relay):
    current=relays._guard(ssh,state.lab_name,host,'preflight')
    config=current.get('config',{})
    if (current.get('phase')!='active' or not re.fullmatch('[0-9a-f]{32}',relay.generation)
            or not re.fullmatch('[0-9a-f]{64}',relay.container_id)
            or current.get('container_id')!=relay.container_id
            or any(config.get(k)!=v for k,v in
                   {'generation':relay.generation,'name':relay.container,'bind_ip':relay.bind_ip,
                    'port':relay.port,'api_key':relay.api_key,'lab':state.lab_name,'host':host}.items())):
        raise RuntimeError('native relay original generation differs')
    caps=(current.get('image',{}).get('Config',{}).get('Labels') or {}).get('io.dnlab.runtime-relay.capabilities','').split(',')
    if CAPABILITY not in caps:raise RuntimeError('native relay requires qualified container ID capability')
    # Ensure-style preflight also checks the original relay is running.
    confirmed=relays._guard(ssh,state.lab_name,host,'preflight',config)
    if confirmed!=current:raise RuntimeError('native relay changed during observation')
    return current


def resolve(state,node,directory,hosts_file=None):
    runtime=state.node_runtime[node]
    relay=(state.runtime_relays or {}).get(runtime.host)
    if relay is None:raise RuntimeError('runtime relay missing for node host')
    if runtime.container not in set(relay.allowed or []):
        raise RuntimeError('container is not allowed on runtime relay')
    result={'container':runtime.container,'host':relay.bind_ip,'port':relay.port,
            'api_key':relay.api_key,'relay_host':runtime.host}
    mode=getattr(state,'runtime_mode','')
    bindings=[getattr(r,'runtime_binding',{}) for r in
              [*state.node_runtime.values(),*getattr(state,'retired_native_nodes',{}).values()]]
    if mode in ('','legacy','per-vd') and not any(bindings):return result
    native.backend(state,node)
    store=native.store_for(directory);clients={}
    try:
        with store.executing(state.lab_name,'public-lifecycle'):
            original=native.source(store,state,node)
            host=runtime.host;hosts=load_hosts_config(hosts_file).all_hosts
            if host not in hosts:raise RuntimeError('native relay host is unavailable')
            clients=create_clients({host:hosts[host]});ssh=clients[host];ssh.connect()
            view,candidate=native.inspect_owned(store,state,node,native.client_for(ssh,original))
            binding=runtime.runtime_binding
            if (view.get('operation') is not None or view.get('committed_state')!='running'
                    or view.get('container_state')!='running'
                    or view.get('container_id')!=binding['container_id']
                    or candidate['request_id']!=original['request_id']):
                raise RuntimeError('native console generation is not committed and running')
            qualify_relay(ssh,state,host,relay)
            return {**result,'runtime_backend':'custom','container_id':binding['container_id']}
    except RuntimeError:
        raise
    except Exception as error:
        raise RuntimeError('native relay identity or availability not verified') from error
    finally:
        for client in clients.values():client.close()
        store.close()
