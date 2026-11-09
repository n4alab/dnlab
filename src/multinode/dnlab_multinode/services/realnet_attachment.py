"""Compatibility boundary for provisioned, data-only RealNet attachments."""
import json
import re
from pathlib import Path
import shlex

from .realnet_attachment_host import AttachmentError,validate

PROGRAM=Path(__file__).with_name('realnet_attachment_host.py').read_text()


def attachment(link,clients,action,*,set_carriers=True):
    proof=link.resource_identities.get('realnet_attachment_v1')
    validate(proof)
    if (proof['lab']!=link.lab_name or proof['node']!=link.endpoint_a.get('node')
            or proof['peer']['ifname']!=link.endpoint_a.get('iface')
            or proof['realnet']!=link.endpoint_b.get('real_net') or proof['link']!=link.id
            or proof['host']!=link.host_a or proof['source']['ifname']!=link.host_endpoint_a
            or proof['bridge']['ifname']!=link.host_endpoint_b or proof['container']['name']!=link.container_a):
        raise AttachmentError('data attachment proof differs from requested link')
    client=clients.get(link.host_a)
    if client is None:raise AttachmentError('data attachment host unavailable')
    request={'proof':proof,'action':action,'warm':link.warm_a,'set_carriers':set_carriers,'expected_attempt':link.resource_identities.get('realnet_attachment_operation',{}).get('attempt')}
    link.resource_identities['realnet_attachment_operation']={'phase':'applying' if action=='create' else 'cleanup_pending','attempt':request['expected_attempt']}
    try:
        value=json.loads(client.run(shlex.join(['python3','-c',PROGRAM,json.dumps(request,sort_keys=True,separators=(',',':'))])))
        if (value.get('phase')!=('active' if action=='create' else 'cleaned')
                or not re.fullmatch('[0-9a-f]{32}|legacy-[0-9a-f]{64}',value.get('attempt') or '')):
            raise AttachmentError('incomplete attachment acknowledgement')
    except Exception:
        link.resource_identities['realnet_attachment_operation']['phase']='recovery_required'
        raise AttachmentError('RealNet data attachment failed; explicit journalled recovery required') from None
    link.resource_identities['realnet_attachment_operation']=value
    return value
