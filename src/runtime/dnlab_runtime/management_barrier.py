"""Local workload fence for an offline management operation owned by multinode.

Readiness of distributed services belongs to the coordinator. This fence only
attests local quiescence and retains the original stopped workload inventory.
"""
import json
import os
from pathlib import Path
import re

from .manifest import Conflict, canonical, fingerprint, identifier

CONTRACT='offline workload fence v2; read-only preflight; acquisition cancellation tombstones; provisioning seal'


def initialize(db):
    db.execute('CREATE TABLE IF NOT EXISTS management_barriers (lab TEXT PRIMARY KEY,payload TEXT NOT NULL)')
    db.execute('CREATE TABLE IF NOT EXISTS management_barrier_history (lab TEXT NOT NULL,barrier_id TEXT NOT NULL,payload TEXT NOT NULL,PRIMARY KEY(lab,barrier_id))')


def get(journal,lab):
    with journal.lock:
        row=journal.db.execute('SELECT payload FROM management_barriers WHERE lab=?',(lab,)).fetchone()
    return json.loads(row[0]) if row else None


def check(journal,lab):
    value=get(journal,lab)
    if value and value['phase'] not in ('released','cancelled'):
        raise Conflict('offline management operation fences workload mutations')


def stopped(engine,lab):
    from .lab_closure import clean
    clean(engine,lab)
    nodes={}
    for row in engine.journal.db.execute('SELECT node FROM nodes WHERE lab=? ORDER BY node',(lab,)).fetchall():
        view=engine.inspect(lab,row[0])
        if view['committed_state']!='stopped' or view['container_state']!='absent' or view['operation'] is not None:
            raise Conflict('offline management requires verified stopped workloads')
        nodes[row[0]]={k:view[k] for k in ('revision','committed_spec_fingerprint','workload')}
    return nodes


def put(journal,lab,value):
    journal.db.execute('INSERT INTO management_barriers VALUES(?,?) ON CONFLICT(lab) DO UPDATE SET payload=excluded.payload',(lab,canonical(value)))


def public(journal,lab,value):
    return {'lab_id':lab,'journal_id':journal.identity,
            **{k:value[k] for k in ('barrier_id','generation','plan_fingerprint','phase','workload_fingerprint')},
            'readiness_fingerprint':value.get('readiness_fingerprint'),
            'acquisition_observed':value.get('workloads') is not None}


def sync(journal):
    # Persist the names of a newly created SQLite journal before acknowledging
    # a fence. A failed sync never produces a successful control response.
    directory=Path(journal.db.execute('PRAGMA database_list').fetchone()[2]).parent
    for path in (directory.parent,directory):
        fd=os.open(path,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW)
        try:os.fsync(fd)
        finally:os.close(fd)


def control(engine,lab,action,raw):
    lab=identifier(lab,'lab_id');journal=engine.journal
    fields={'barrier_id','generation','plan_fingerprint'}
    if action!='plan':fields.add('workload_fingerprint')
    if action=='release':fields.add('readiness_fingerprint')
    if action not in ('plan','acquire','activate','cancel','release') or not isinstance(raw,dict) or set(raw)!=fields:
        raise Conflict('invalid offline management barrier fields')
    hashes=[('barrier_id',32),('plan_fingerprint',64)]
    if action!='plan':hashes.append(('workload_fingerprint',64))
    if action=='release':hashes.append(('readiness_fingerprint',64))
    if (type(raw['generation']) is not int or raw['generation']<1
            or any(not isinstance(raw[k],str) or not re.fullmatch('[0-9a-f]{'+str(n)+'}',raw[k]) for k,n in hashes)):
        raise Conflict('invalid offline management barrier identity')
    with journal.execution_lock:
        if action!='plan':sync(journal)
        with journal.transaction():
            from .lab_closure import generation,get as closure
            fence=closure(journal,lab)
            if raw['generation']!=generation(journal,lab) or fence and fence['phase']!='open':
                raise Conflict('lab generation or teardown closure differs')
            value=get(journal,lab)
            identity={k:raw[k] for k in ('barrier_id','generation','plan_fingerprint')}
            same=value and value['barrier_id']==raw['barrier_id']
            if same:
                if any(value[k]!=v for k,v in identity.items()):raise Conflict('offline management intent changed')
                if action!='plan' and value['workload_fingerprint']!=raw['workload_fingerprint']:
                    raise Conflict('offline workload preflight differs')
            else:
                if action in ('release','activate'):raise Conflict('offline management barrier missing or replaced')
                if value and value['phase'] not in ('released','cancelled'):
                    raise Conflict('another offline management operation is pending')
                if journal.db.execute('SELECT 1 FROM management_barrier_history WHERE lab=? AND barrier_id=?',(lab,raw['barrier_id'])).fetchone():
                    raise Conflict('offline management barrier identity already retired')
            if action=='plan':
                if same and value['phase'] in ('cancelled','released'):
                    raise Conflict('offline management operation already concluded')
                nodes=stopped(engine,lab)
                return {**public(journal,lab,{**identity,'phase':'planned','workload_fingerprint':fingerprint(nodes)}),'mutations_performed':False}
            if not same:
                nodes=None if action=='cancel' else stopped(engine,lab)
                if nodes is not None and fingerprint(nodes)!=raw['workload_fingerprint']:
                    raise Conflict('offline workload changed after preflight')
                if value:
                    journal.db.execute('INSERT INTO management_barrier_history VALUES(?,?,?)',(lab,value['barrier_id'],canonical(value)))
                value={**identity,'phase':'cancelled' if action=='cancel' else 'held',
                       'workloads':nodes,'workload_fingerprint':raw['workload_fingerprint']}
                put(journal,lab,value)
            if action=='cancel':
                if value['phase'] not in ('held','cancelled'):
                    raise Conflict('only acquisition before provisioning can be cancelled')
                if value['phase']=='held':
                    if stopped(engine,lab)!=value['workloads']:raise Conflict('offline workload inventory changed')
                    value={**value,'phase':'cancelled'};put(journal,lab,value)
            elif value['phase']=='cancelled':
                raise Conflict('offline management acquisition was cancelled')
            elif value['phase'] in ('held','applying'):
                if stopped(engine,lab)!=value['workloads']:raise Conflict('offline workload inventory changed')
                if action=='activate':
                    value={**value,'phase':'applying'};put(journal,lab,value)
                elif action=='acquire' and value['phase']!='held':
                    raise Conflict('offline management provisioning already begun')
                elif action=='release':
                    value={**value,'phase':'released','readiness_fingerprint':raw['readiness_fingerprint']}
                    put(journal,lab,value)
            elif action=='release' and value.get('readiness_fingerprint')!=raw['readiness_fingerprint']:
                raise Conflict('offline management readiness attestation changed')
            elif action=='activate':raise Conflict('offline management operation already concluded')
        sync(journal)
        return public(journal,lab,value)
