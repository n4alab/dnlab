"""Current management assignment, separate from immutable workload birth spec.

Call reserve/finish under the journal transaction and the shared execution gate.
No topology placement or distributed scheduling lives in this local view.
"""
import ipaddress
import json
from pathlib import Path

from .manifest import Conflict,canonical,fingerprint

DONE={'completed','cancelled','failed'}


def bind_backend(backend,journal):
    path=str(Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).resolve())
    previous=getattr(backend,'management_journal',None)
    if previous is not None and previous is not journal:
        previous_path=getattr(backend,'management_journal_path',None)
        if previous_path is None and not getattr(previous,'closed',False):
            previous_path=str(Path(previous.db.execute('PRAGMA database_list').fetchone()[2]).resolve())
        if previous_path!=path:raise Conflict('backend already belongs to another management authority journal')
        if not getattr(previous,'closed',False):return
    backend.management_journal=journal;backend.management_journal_path=path


def assignment(journal,lab,node):
    with journal.lock:
        row=journal.db.execute('SELECT payload FROM management_assignments WHERE lab=? AND node=?',(lab,node)).fetchone()
    return json.loads(row[0]) if row else None


def put(journal,lab,node,value):
    journal.db.execute('INSERT INTO management_assignments VALUES(?,?,?) ON CONFLICT(lab,node) DO UPDATE SET payload=excluded.payload',
                       (lab,node,canonical(value)))


def available(journal,lab,node):
    value=assignment(journal,lab,node)
    if value and value['phase']=='pending':raise Conflict('node management requires completion or recovery')


def reserve(handoff,request_id,container,source,expected_revision):
    journal=handoff.journal;lab=handoff.request['lab_id'];node=handoff.request['node_id']
    from .stop_protocol import unreserved
    unreserved(journal,lab,node)
    if expected_revision is not None and (type(expected_revision) is not int or expected_revision<1):raise Conflict('valid management node revision required')
    current=journal.node(lab,node)
    if current is None:
        if expected_revision is not None:raise Conflict('management node revision missing')
        return None  # Standalone probes remain supported; no node adoption.
    if (current['state']!='running' or fingerprint(current['spec'])!=fingerprint(handoff.spec)
            or expected_revision is not None and current['revision']!=expected_revision):
        raise Conflict('management node revision or birth specification differs')
    owned=handoff.backend.inspect(handoff.request,current['spec'])
    if not owned or owned['Id']!=container['Id']:raise Conflict('management container generation differs')
    available(journal,lab,node)
    rows=journal.db.execute('SELECT phase FROM operations WHERE lab=? AND node=?',(lab,node)).fetchall()
    if any(row[0] not in DONE for row in rows):raise Conflict('node lifecycle is pending or requires recovery')
    tables={r[0] for r in journal.db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
    if 'link_operations' in tables:
        from .bridge_request import endpoints
        for row in journal.db.execute('SELECT payload,phase FROM link_operations WHERE lab=?',(lab,)):
            if row[1] not in DONE and any(edge['node_id']==node for edge in endpoints(json.loads(row[0]))):
                raise Conflict('node link operation is pending or requires recovery')
    prior=assignment(journal,lab,node)
    if prior and (prior['container_id']!=container['Id'] or prior['birth_fingerprint']!=fingerprint(current['spec']) or prior['connection']!=source):
        raise Conflict('current management assignment differs from observed source')
    binding={'lab':lab,'node':node,'revision':current['revision'],'birth_fingerprint':fingerprint(current['spec']),'container_id':container['Id']}
    put(journal,lab,node,{**binding,'connection':source,'phase':'pending','move_id':request_id})
    return binding


def finish(journal,move,payload,phase):
    binding=payload.get('node_binding')
    if not binding:return
    lab,node=binding['lab'],binding['node'];current=journal.node(lab,node)
    value=assignment(journal,lab,node)
    if (not current or current['state']!='running' or current['revision']!=binding['revision']
            or fingerprint(current['spec'])!=binding['birth_fingerprint'] or not value
            or value['phase']!='pending' or value['move_id']!=move or value['container_id']!=binding['container_id']):
        raise Conflict('management authority changed before commit')
    connection=payload['target'] if phase=='completed' else payload['source']
    revision=current['revision']+(phase!='rejected')
    put(journal,lab,node,{**binding,'revision':revision,'phase':'stable','connection':connection,'move_id':move})
    journal.db.execute('UPDATE nodes SET revision=? WHERE lab=? AND node=?',(revision,lab,node))


def effective(journal,request,spec,container=None):
    value=assignment(journal,request['lab_id'],request['node_id']) if journal else None
    if not value:return spec.get('management')
    candidate=value.get('restart')
    if candidate and candidate['birth_fingerprint']==fingerprint(spec):
        operation=journal.get(candidate['operation_id'])
        if operation['phase'] in ('completed','cancelled','failed'):raise Conflict('management restart operation is terminal')
        if container is not None and candidate['container_id']!=container['Id']:raise Conflict('management restart container differs')
        if candidate['clear']:return spec.get('management')
        value={**value,**candidate,'phase':'stable'}
    if value['birth_fingerprint']!=fingerprint(spec):
        current=journal.node(request['lab_id'],request['node_id'])
        if not current or current['state']!='stopped' or value['phase']!='stopped' or fingerprint(current['spec'])!=value['birth_fingerprint']:
            raise Conflict('management birth identity differs')
        if spec.get('management')!=current['spec'].get('management'):return spec.get('management')
    if value['phase']=='pending':raise Conflict('node management requires completion or recovery')
    if container is not None and value['container_id']!=container['Id']:raise Conflict('management container generation differs')
    connection=value['connection'];address=ipaddress.ip_interface(connection['cidr'])
    result={'network':connection['network_name'],'ipv4':str(address.ip),'network_id':connection['network_id'],'gateway':connection['gateway']}
    if (spec.get('management') or {}).get('mac'):result['mac']=spec['management']['mac']
    return result


def rebind(journal,request,spec,container,operation_id):
    value=assignment(journal,request['lab_id'],request['node_id'])
    if not value:return
    if value['phase']=='stopped':
        from .backend import LABEL
        current=journal.node(request['lab_id'],request['node_id'])
        if (not current or current['state']!='stopped' or fingerprint(current['spec'])!=value['birth_fingerprint']
                or container.get('Config',{}).get('Labels',{}).get(LABEL+'.creator')!=operation_id):
            raise Conflict('management restart generation is not owned by this operation')
        with journal.transaction():
            value['restart']={'container_id':container['Id'],'birth_fingerprint':fingerprint(spec),'operation_id':operation_id,
                              'clear':spec.get('management')!=current['spec'].get('management')}
            put(journal,request['lab_id'],request['node_id'],value)


def check(handoff,payload,move_id):
    binding=payload.get('node_binding')
    if not binding:return
    current=handoff.journal.node(binding['lab'],binding['node'])
    value=assignment(handoff.journal,binding['lab'],binding['node'])
    owned=handoff.backend.inspect(handoff.request,handoff.spec)
    if (not current or current['revision']!=binding['revision'] or current['state']!='running'
            or fingerprint(current['spec'])!=binding['birth_fingerprint'] or fingerprint(handoff.spec)!=binding['birth_fingerprint']
            or not owned or owned['Id']!=binding['container_id'] or not value or value['phase']!='pending'
            or value['move_id']!=move_id or value['container_id']!=binding['container_id']):
        raise Conflict('management operation lost its node/container generation')


def stop_allowed(journal,request,spec,container):
    value=assignment(journal,request['lab_id'],request['node_id'])
    if not value or container is None:return
    if (value['phase']!='stable' or value['birth_fingerprint']!=fingerprint(spec)
            or value['container_id']!=container['Id']):
        raise Conflict('refusing lifecycle stop of a changed management workload generation')
