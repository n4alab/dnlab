"""Centralized DNS container management (dnsmasq)."""

from __future__ import annotations

import logging
import hashlib
import json
from pathlib import Path
import shlex
import uuid

from dnlab_multinode.models.topology import DistributedTopology
from dnlab_multinode.services.hostsfile import (
    HostEntry, collect_hosts_entries, get_upstream_dns, render_hosts_file,
)
from dnlab_multinode.services.images import image_for
from dnlab_multinode.services.jumphost import (
    _WORKER_BOOTSTRAP,
    allocate_jumphost_ip,
    ensure_jumphost_network,
)
from dnlab_multinode.services.mgmt_ips import ipv4_reservations
from dnlab_multinode.services.paths import PATHS
from dnlab_multinode.services.ssh import SSHClient

log = logging.getLogger(__name__)


def dns_container_name(lab_name: str) -> str:
    return f"dnlab-{lab_name}-dns"


def hosts_file_path(lab_name: str, nonce: str | None = None) -> str:
    """Path on the master where the merged hosts file lives."""
    if nonce:
        key = hashlib.sha256(json.dumps(['dns-v1', lab_name], separators=(',', ':')).encode()).hexdigest()
        return str(Path(PATHS.dns_journal_dir) / (key + '-' + nonce) / 'hosts')
    return f"{PATHS.tmp_dir}/dnlab-{lab_name}-dns-hosts"


def compute_dns_mgmt_ip(subnet: str) -> str:
    """Penultimate reserved IP in the mgmt subnet."""
    return ipv4_reservations(subnet).dns


def deploy_dns(
    topo: DistributedTopology,
    master_client: SSHClient,
    clients: dict[str, SSHClient],
    extra_entries: list[HostEntry] | None = None,
    *, generation: str | None = None, receipt: dict | None = None,
) -> tuple[str, str, list[str], int]:
    """Deploy the DNS container on the master.

    Returns: (container_name, resolver_ip, upstream_servers, entry_count)
    """
    previous = _guard(master_client, topo.name, 'preflight')
    if previous['phase'] not in ('absent', 'active', 'cleaned'):
        raise RuntimeError('DNS explicit recovery required before deploy')
    entries = collect_hosts_entries(topo.name, clients)
    if extra_entries: entries = _merge_entries(entries, extra_entries)
    upstream = get_upstream_dns(master_client)
    ensure_jumphost_network(master_client, topo.jumphost_net)
    if previous['phase'] == 'active':
        resolver_ip = previous['config']['ip']
        generation = generation or previous['config']['generation']
    else:
        resolver_ip = allocate_jumphost_ip(master_client, topo.jumphost_net).split('/')[0]
        generation = generation or uuid.uuid4().hex
    net = topo.jumphost_net
    config = {'lab': topo.name, 'generation': generation, 'name': dns_container_name(topo.name),
              'image': image_for('dns'), 'network': {'name': net.network, 'bridge': net.bridge,
              'subnet': net.ipv4_subnet, 'gateway': net.ipv4_gw}, 'ip': resolver_ip, 'upstream': upstream}
    record = _guard(master_client, topo.name, 'provision' if previous['phase'] == 'cleaned' else 'ensure', config, render_hosts_file(entries))
    if receipt is not None: receipt.update(record)
    return config['name'], resolver_ip, upstream, len(entries)


def _guard(client, lab, action, config=None, content=None):
    base = Path(__file__).with_name('jumphost_host.py').read_text()
    worker = Path(__file__).with_name('dns_host.py').read_text()
    program = "_primitives={'__name__':'_dns_primitives'}\nexec(" + repr(base) + ",_primitives)\n"
    program += "_BaseWorker=_primitives['Worker']\nJumphostError=_primitives['JumphostError']\ncanonical=_primitives['canonical']\ndigest=_primitives['digest']\n" + worker
    request = {'lab': lab, 'action': action, 'config': config, 'content': content,
               'directory': PATHS.dns_journal_dir}
    try:
        value = json.loads(client.run_input(shlex.join(['python3', '-c', _WORKER_BOOTSTRAP]),
            json.dumps({'source':program,'request':request}), timeout=60))
    except Exception as error:
        raise RuntimeError('DNS operation rejected or recovery required; journal retained') from error
    if not isinstance(value, dict) or 'phase' not in value: raise RuntimeError('invalid DNS acknowledgement')
    return value


def recover_dns(lab_name, client):
    return _guard(client, lab_name, 'recover')


def preflight_dns_cleanup(lab_name, client, generation):
    if not generation: raise RuntimeError('DNS coordinator generation required')
    return _guard(client, lab_name, 'preflight-delete', {'generation': generation})


def verify_dns_cleaned(lab_name, client, generation):
    if not generation: raise RuntimeError('DNS coordinator generation required')
    return _guard(client, lab_name, 'verify-cleaned', {'generation': generation})


def allocate_dns_resolver_ip(topo: DistributedTopology, master_client: SSHClient) -> str:
    """Pick a resolver IP on the shared jumphost network."""
    ensure_jumphost_network(master_client, topo.jumphost_net)
    return allocate_jumphost_ip(master_client, topo.jumphost_net).split("/")[0]


def refresh_dns(
    lab_name: str,
    master_client: SSHClient,
    clients: dict[str, SSHClient],
    extra_entries: list[HostEntry] | None = None,
    *, generation: str | None = None,
) -> tuple[int, list[HostEntry]]:
    """Regenerate the hosts file and SIGHUP the DNS container.

    Returns: (entry_count, entries)
    """
    entries = collect_hosts_entries(lab_name, clients)
    if extra_entries: entries = _merge_entries(entries, extra_entries)
    if generation is not None and not generation:
        raise RuntimeError('DNS coordinator generation required')
    _guard(master_client, lab_name, 'reload', {'generation': generation} if generation else None,
           content=render_hosts_file(entries))
    return len(entries), entries


def _merge_entries(
    base: list[HostEntry],
    extra: list[HostEntry],
) -> list[HostEntry]:
    """Merge DNS entries, keeping the first IP seen for each name."""
    seen: dict[str, HostEntry] = {}
    for entry in [*base, *extra]:
        if entry.name in seen:
            existing = seen[entry.name]
            if existing.ip != entry.ip:
                log.warning(
                    "Duplicate DNS name '%s': %s kept, %s ignored",
                    entry.name, existing.ip, entry.ip,
                )
            continue
        seen[entry.name] = entry
    return list(seen.values())


def destroy_dns(lab_name: str, master_client: SSHClient, generation: str | None = None) -> None:
    """Delete only the journal-qualified generation and its proven assets."""
    if generation is not None and not generation:
        raise RuntimeError("DNS coordinator generation required")
    _guard(master_client, lab_name, 'delete', {'generation': generation} if generation else None)
