"""Publish original management helpers after qualified network-service release."""
from copy import deepcopy
from dataclasses import asdict
import ipaddress

from ..models.state import DnsState, JumphostState
from ..services import management_service_runtime as services, netsetup, dns
from ..services.runtime_cleanup import management_cleanup_check
from ..services.runtime_lab_closure import check
from ..services.runtime_operations import RuntimeOperationError, digest, encoded


def publish(controller, key, lab, state, clients, load_current, checkpoint):
    """Reobserve original helpers and persist their existing public descriptors.

    No allocation, packet execution, recovery or readiness inference occurs.
    Failed saves propagate; replay requires the same saved generations.
    """
    state = deepcopy(state)
    store = controller.store
    with store.executing(lab, 'management-barrier'):
        with store.executing(lab, 'public-lifecycle'):
            original = controller.driver.original(lab, key)
            if (state.lab_name != lab or state.runtime_mode != 'custom' or state.teardown_requested
                    or original['phase'] != 'released' or set(clients) != set(original['targets'])):
                raise RuntimeOperationError('original released management context required for publication')
            management_cleanup_check(store, lab)  # Verify all original terminal receipts.
            bundle = original['plan'].get('services')
            progress = original.get('services', {})
            infrastructure = original.get('infrastructure', {})
            if (not bundle or progress.get('phase') != 'materialized'
                    or bundle.get('fingerprint') != digest({k: v for k, v in bundle.items() if k != 'fingerprint'})
                    or progress.get('intent_fingerprint') != bundle['fingerprint']
                    or infrastructure.get('phase') != 'infrastructure-ready'
                    or digest(asdict(state.mgmt) if state.mgmt else None) != digest(infrastructure['snapshot'])
                    or state.management_plan != bundle['management_plan']):
                raise RuntimeOperationError('original management service checkpoints required for publication')
            saved = progress.get('observation', {})
            def observe():
                resources = netsetup.verify_management_ready(state, clients)
                observed = services.invoke(clients['master'], bundle, 'observe')
                if (resources != saved.get('infrastructure') or observed != saved.get('services')
                        or observed.get('mutations_performed') is not False
                        or any(observed.get(k) != progress['receipt'].get(k)
                               for k in ('external_network_id', 'jumphost', 'dns'))):
                    raise RuntimeOperationError('original management service generations differ during publication')
            observe()
            jump = bundle['jumphost']; resolver = bundle['dns']['config']
            result = deepcopy(state)
            result.jumphost = JumphostState(
                node='master', container=jump['name'],
                mgmt_ip=jump['attachment']['ipv4'].split('/')[0],
                host_ip=jump['ip'] + '/' + str(ipaddress.IPv4Network(jump['network']['subnet']).prefixlen),
                ext_network=jump['network']['name'], password=jump['env']['JUMPHOST_PASSWORD'],
                resolver=resolver['ip'], ssh_port=jump['port'], ssh_bind_ip=jump['bind_ip'],
                generation=jump['generation'],
            )
            result.dns = DnsState(
                node='master', container=resolver['name'], mgmt_ip=resolver['ip'],
                upstream=deepcopy(resolver['upstream']), generation=resolver['generation'],
                hosts_file=dns.hosts_file_path(lab, progress['receipt']['dns']['nonce']),
                entries=sum(bool(line.strip()) and not line.lstrip().startswith('#')
                            for line in bundle['dns']['content'].splitlines()),
            )
            for field in ('jumphost', 'dns'):
                if getattr(state, field) is not None and getattr(state, field) != getattr(result, field):
                    raise RuntimeOperationError('public service differs from its original generation')
            # Detect replacement across sequential observations before committing
            # the pair. The original operation remains the sole birth authority.
            observe()
            with store.transaction():
                if controller.driver.original(lab, key) != original:
                    raise RuntimeOperationError('management operation changed during publication')
                check(store, {'lab_id': lab, 'lab_generation': original['generation'],
                              'request_id': key, 'action': 'start'})
                current = load_current()
                if current is None or encoded(current.to_dict()) != encoded(state.to_dict()):
                    raise RuntimeOperationError('public deployment changed before service publication')
                checkpoint(result)
            return result
