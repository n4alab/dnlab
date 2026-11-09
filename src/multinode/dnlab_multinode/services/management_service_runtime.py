"""Existing SSH boundary for composed, journal-qualified management services."""
import json
from pathlib import Path
import shlex

from .jumphost import _WORKER_BOOTSTRAP
from .paths import PATHS
from .runtime_operations import RuntimeOperationError


def program():
    directory=Path(__file__).parent
    sources={name:(directory/name).read_text() for name in
        ('jumphost_host.py','dns_host.py','jumphost_network_host.py','management_service_host.py')}
    # Inject each dependency into an isolated module namespace, as the DNS
    # wrapper already does. No installed dnlab package is needed on a worker.
    base="jump={'__name__':'_jump'}\nexec("+repr(sources['jumphost_host.py'])+",jump)\n"
    base+="dns={'__name__':'_dns','_BaseWorker':jump['Worker'],'JumphostError':jump['JumphostError'],'canonical':jump['canonical'],'digest':jump['digest']}\nexec("+repr(sources['dns_host.py'])+",dns)\n"
    base+="network={'__name__':'_network'}\nexec("+repr(sources['jumphost_network_host.py'])+",network)\n"
    base+="JumpWorker=jump['Worker']\nDNSWorker=dns['Worker']\nNetworkWorker=network['Worker']\nJumphostError=jump['JumphostError']\ndigest=jump['digest']\nnames=jump['names']\nAttachmentWorker=jump['AttachmentWorker']\nDHCPHostService=jump['DHCPHostService']\nsignature=jump['signature']\n"
    base+='DNS_PROBE_SOURCE='+repr((directory/'management_dns_probe.py').read_text())+'\n'
    base+="routing={'__name__':'_routing'}\nexec("+repr((directory/'management_routing_observation.py').read_text())+",routing)\nvalidate_routing=routing['validate']\n"
    return base+sources['management_service_host.py']


def invoke(client,intent,action):
    if action not in ('preflight','apply','observe','probe','packet_profiles','routing_snapshot'):raise RuntimeOperationError('unsupported management service action')
    request={'action':action,'intent':intent,'directories':{
        'jump_directory':PATHS.jumphost_journal_dir,'dns_directory':PATHS.dns_journal_dir,
        'network_directory':PATHS.jumphost_network_journal_dir,'management_directory':PATHS.management_journal_dir}}
    try:
        value=json.loads(client.run_input(shlex.join(['python3','-c',_WORKER_BOOTSTRAP]),
            json.dumps({'source':program(),'request':request},sort_keys=True,separators=(',',':')),timeout=180))
    except Exception as error:
        raise RuntimeOperationError('management service operation rejected or recovery required; original journals retained') from error
    if (not isinstance(value,dict) or value.get('intent_fingerprint')!=intent['fingerprint']
            or value.get('phase')!={'preflight':'preflight','apply':'materialized','observe':'observed','probe':'probed','packet_profiles':'packet-profiles','routing_snapshot':'routing-snapshot'}[action]):
        raise RuntimeOperationError('management service acknowledgement differs')
    return value
