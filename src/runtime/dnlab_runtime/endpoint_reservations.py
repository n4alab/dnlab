"""Shared source reservations derived from durable primitive intents.

Call under the shared bridge/VXLAN resource lock before creation or retry.
Only verified cleanup releases a reservation; no extra ownership database.
"""
import json

from .manifest import Conflict


def require_available(journal,names,*,owner_table,owner_id):
    names=set(names)
    with journal.lock:
        tables={row[0] for row in journal.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        for table in ('local_vxlans','local_bridges','realnet_attachments'):
            if table not in tables:continue
            for row in journal.db.execute(f"SELECT id,payload FROM {table} WHERE phase != 'cleaned'"):
                if (table,row['id'])==(owner_table,owner_id):continue
                try:
                    payload=json.loads(row['payload'])
                    sources=[payload['source']] if table!='local_bridges' else payload['config']['sources']
                    occupied={source['ifname'] for source in sources}
                    if not occupied or any(not isinstance(name,str) or not name for name in occupied):
                        raise ValueError('invalid source reservation')
                except (ValueError,KeyError,TypeError):
                    raise Conflict('local link reservation cannot be verified') from None
                if names & occupied:
                    raise Conflict('source reserved by another local link')
