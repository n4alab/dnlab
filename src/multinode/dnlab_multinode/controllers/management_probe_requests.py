"""Deterministic original management-probe requests shared with readiness."""
from copy import deepcopy
from ..services.runtime_operations import digest


def compile_requests(original,infrastructure,server_profile,*,packets,dns=False):
    bundle=original['plan']['services'];lab=bundle['lab'];observed=infrastructure
    requests=[]
    for segment,identity in sorted(bundle['packet_probe_identities'].items()):
        if packets and not dns and not bundle['management_plan']['networks'][segment]['dhcp']:
            continue
        for host in sorted(original['targets']):
            network=observed[host]['networks']['proof']['networks'][segment]
            requests.append({'lab':lab,'segment':segment,'host':host,
                'operation_id':original['barrier_id'],
                'request_id':digest([original['barrier_id'],segment,host,'dns-client' if dns else 'dhcp-packets' if packets else 'endpoint-lifecycle'])[:32],
                'image':bundle['jumphost']['image'],'identity':deepcopy(identity),
                'attachment':deepcopy(bundle['attachments'][segment]['attachment']),
                'management_intent':original['plan']['hosts'][host]['segments'][segment]['network'],
                'management_generation':original['plan']['management_generation'],
                'network_id':network['id'],'network_nonce':network['nonce']})
            if packets:
                cfg=bundle['management_plan']['networks'][segment];server=server_profile['servers'][segment]
                request=requests[-1];transaction=digest([request['request_id'],'transactions'])
                if dns:
                    addresses={'4':identity['ipv4']};resolvers={'4':cfg['ipv4_gw']}
                    if identity['ipv6']:
                        addresses['6']=identity['ipv6']
                        resolvers['6']=cfg['ipv6_gw']
                    request['packet_profile']={'mode':'dns-client','interface':'probe0',
                        'client_mac':identity['mac'],'server_mac':server['mac'],'server_ip':cfg['ipv4_gw'],
                        'server_ipv6':cfg['ipv6_gw'] if identity['ipv6'] else None,
                        'server_link_local':server['link_local'] if identity['ipv6'] else None,
                        'addresses':addresses,'resolvers':resolvers,'records':deepcopy(bundle['dns_probe']['records']),
                        'token':transaction}
                    continue
                profile={'interface':'probe0','client_mac':identity['mac'],'client_ip':identity['ipv4'],
                    'server_mac':server['mac'],'server_ip':cfg['ipv4_gw'],'dns_ip':cfg['ipv4_gw'],
                    'subnet':cfg['ipv4_subnet'],'xid':int(transaction[:8],16) or 1,'ipv6':None}
                if identity['ipv6']:
                    profile['ipv6']={'server_ip':server['link_local'],'duid':identity['duid'],'iaid':identity['iaid'],
                        'address':identity['ipv6'],'dns':cfg['ipv6_gw'],'prefix':cfg['ipv6_subnet'],
                        'solicit_xid':transaction[8:14],'request_xid':transaction[14:20]}
                request['packet_profile']=profile
    return requests
