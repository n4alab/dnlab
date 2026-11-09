"""Shared WAN guard over the existing host SSH boundary."""
import json
from pathlib import Path
import shlex

from .realnet_wan_host import WANError,config

PROGRAM=Path(__file__).with_name('realnet_wan_host.py').read_text()


def ensure_wan(client,cfg,*,action='ensure'):
    value=config({'network':cfg.network,'bridge':cfg.bridge,'subnet':cfg.ipv4_subnet,'gateway':cfg.ipv4_gw})
    try:ack=json.loads(client.run(shlex.join(['python3','-c',PROGRAM,action,json.dumps(value,sort_keys=True,separators=(',',':'))])))
    except Exception:raise WANError('shared RealNet WAN rejected or requires explicit infrastructure recovery') from None
    if ack.get('status')!=('verified' if action=='preflight' else 'active'):raise WANError('incomplete WAN acknowledgement')
    return ack
