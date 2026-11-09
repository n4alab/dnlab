"""Durable Docker birth proofs, independent of data ports and management moves.

A create response must bind an immutable Docker ID before use. A lost create
response with an extant unbound container requires explicit recovery; labels
alone cannot establish that it is still the original Docker generation.
"""
import uuid

from .manifest import Conflict, fingerprint


class GenerationConflict(Conflict):
    pass


def latest(journal, request):
    with journal.lock:
        row=journal.db.execute('SELECT * FROM workload_generations WHERE lab=? AND node=? ORDER BY generation DESC LIMIT 1',
                               (request['lab_id'],request['node_id'])).fetchone()
    return dict(row) if row else None


def reserve(journal, request, spec, operation_id):
    with journal.transaction():
        current=journal.node(request['lab_id'],request['node_id'])
        if current and current['state']!='stopped':
            raise GenerationConflict('workload generation cannot be recreated before verified stop')
        prior=latest(journal,request)
        if (prior and prior['phase']=='reserved' and prior['creator']==operation_id
                and prior['spec']==fingerprint(spec) and prior['container_id'] is None):
            return prior
        if prior and prior['phase']!='cleaned':
            raise GenerationConflict('workload generation requires recovery before another create')
        generation=prior['generation']+1 if prior else 1
        nonce=uuid.uuid4().hex
        journal.db.execute('INSERT INTO workload_generations VALUES(?,?,?,?,?,?,?,?,?,?)',
            (request['lab_id'],request['node_id'],generation,operation_id,nonce,fingerprint(spec),None,'reserved',None,spec['container_name']))
    return latest(journal,request)


def bind(journal,request,spec,operation_id,container_id):
    if not isinstance(container_id,str) or not container_id:
        raise GenerationConflict('Docker create returned no workload generation')
    with journal.transaction():
        value=latest(journal,request)
        if (not value or value['creator']!=operation_id or value['spec']!=fingerprint(spec)
                or value['phase']!='reserved' or value['container_id'] is not None):
            raise GenerationConflict('workload birth intent changed before Docker ID binding')
        journal.db.execute("UPDATE workload_generations SET container_id=?,phase='bound' WHERE lab=? AND node=? AND generation=?",
                           (container_id,value['lab'],value['node'],value['generation']))


def verify(journal,request,spec,container,label):
    value=latest(journal,request)
    actual=container.get('Config',{}).get('Labels') or {}
    if (not value or not value['container_id'] or value['phase']=='cleaned'
            or value['spec']!=fingerprint(spec) or value['container_name']!=spec['container_name']
            or value['container_id']!=container.get('Id')
            or actual.get(label+'.creator')!=value['creator'] or actual.get(label+'.birth')!=value['nonce']):
        raise GenerationConflict('workload generation identity missing or changed; recovery required')
    return value


def cleaned(journal,request,spec):
    with journal.transaction():
        value=latest(journal,request)
        if value:
            if value['spec']!=fingerprint(spec):raise GenerationConflict('cleanup workload generation spec changed')
            journal.db.execute("UPDATE workload_generations SET phase='cleaned' WHERE lab=? AND node=? AND generation=?",
                               (value['lab'],value['node'],value['generation']))


def committed(journal,operation,spec,state,revision):
    # Called inside Journal.finish's transaction. Unqualified legacy node rows
    # remain unqualified; never construct a birth proof from their labels.
    value=latest(journal,{'lab_id':operation['lab'],'node_id':operation['node']})
    if not value:return
    expected=('bound','running') if state=='running' else ('cleaned',)
    if value['spec']!=fingerprint(spec) or value['phase'] not in expected:
        raise GenerationConflict('workload generation is not ready for node commit')
    journal.db.execute('UPDATE workload_generations SET phase=?,committed_revision=? WHERE lab=? AND node=? AND generation=?',
                       ('running' if state=='running' else 'cleaned',revision,value['lab'],value['node'],value['generation']))
