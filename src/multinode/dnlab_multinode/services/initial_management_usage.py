"""Durable management usage handoff before any managed initial workload birth."""
from copy import deepcopy

from . import netsetup
from .runtime_operations import RuntimeOperationError, digest, encoded


class InitialManagementUsage:
    def __init__(self, batch):
        self.batch, self.store = batch, batch.store

    def get(self, lab, key):
        import json
        row = self.store.db.execute('SELECT * FROM initial_management_usage WHERE lab=? AND request_id=?', (lab,key)).fetchone()
        if row is None: return None
        value = dict(row); value['intent'] = json.loads(value['intent']); value['progress'] = json.loads(value['progress'])
        if digest(value['intent']) != value['fingerprint']:
            raise RuntimeOperationError('initial management usage intent integrity differs')
        return value

    def definition(self, lab, key):
        payload = self.batch.get(lab,key,private=True)['payload']
        if not payload.get('management_parent'): return None
        parent, original = self.batch.released_parent(lab,payload['management_parent']['request_id'])
        if parent != payload['management_parent']:
            raise RuntimeOperationError('initial deployment management parent changed')
        infra = original.get('infrastructure',{})
        metadata = (infra.get('snapshot') or {}).get('infrastructure',{})
        hosts = set(original['targets'])
        if (infra.get('phase') != 'infrastructure-ready' or not hosts
                or any(set(metadata.get(k,{})) != hosts for k in ('plans','networks'))
                or set(infra.get('proofs',{})) != hosts):
            raise RuntimeOperationError('original all-host management usage proofs required')
        selected = {}
        for member in payload['members']:
            host = member['target']['host']; network = member['request']['spec'].get('management',{}).get('network')
            matches = [k for k,v in metadata['networks'][host].items() if v['network']==network]
            if len(matches)!=1: raise RuntimeOperationError('initial management usage segment differs')
            selected.setdefault(host,set()).add(matches[0])
        return {'lab':lab,'batch':key,'parent':parent,'members_fingerprint':digest(payload['members']),
                'targets':deepcopy(original['targets']),'plans':deepcopy(metadata['plans']),
                'networks':deepcopy(metadata['networks']),'proofs':deepcopy(infra['proofs']),
                'selected':{h:sorted(v) for h,v in selected.items()}}

    def client(self, intent, host):
        owner = intent['targets'][host]
        if self.batch.management_clients is not None:
            if set(self.batch.management_clients) != set(intent['targets']):
                raise RuntimeOperationError('all original management usage clients required')
            return self.batch.management_clients[host]
        client = self.batch.factory(owner['target']).bound_to(owner['journal_id'])
        ssh = getattr(client,'ssh',None)
        if ssh is None or not callable(getattr(ssh,'run_input',None)):
            raise RuntimeOperationError('management usage requires original host transport')
        return ssh

    def observe(self, intent):
        result = {}
        # Every host is qualified before any host is marked, including hosts
        # with no VD in this batch. Re-observe on recovery and between writes.
        for host in sorted(intent['targets']):
            client = self.client(intent,host); plan = intent['plans'][host]; definitions = intent['networks'][host]
            kernel = netsetup.invoke(client,'verify-ready',plan)
            networks = netsetup.invoke(client,'network-verify-ready',plan,networks=definitions)
            if {'kernel':kernel,'networks':networks} != intent['proofs'][host]:
                raise RuntimeOperationError('original management usage generation changed')
            record = netsetup.invoke(client,'read',plan)['record']
            used = {}
            for segment, proof in networks['proof']['networks'].items():
                row = record.get('networks',{}).get(segment,{})
                if (row.get('id')!=proof['id'] or row.get('nonce')!=proof['nonce']
                        or row.get('expected')!=proof['expected'] or type(row.get('used')) is not bool):
                    raise RuntimeOperationError('management usage network birth differs')
                used[segment]=row['used']
            result[host]=used
        return result

    def save(self, lab, key, progress, phase):
        with self.store.transaction():
            self.store.db.execute('UPDATE initial_management_usage SET progress=?,phase=? WHERE lab=? AND request_id=?',
                                  (encoded(progress),phase,lab,key))

    def ensure(self, lab, key):
        intent = self.definition(lab,key)
        if intent is None: return
        saved = self.get(lab,key)
        if saved is None:
            if any(m['operation_id'] for m in self.batch.members(lab,key)):
                raise RuntimeOperationError('missing pre-birth management usage intent; explicit recovery required')
            self.observe(intent)  # Global preflight before durable intent/mutation.
            with self.store.transaction():
                self.store.db.execute('INSERT INTO initial_management_usage VALUES(?,?,?,?,?,?)',
                    (lab,key,encoded(intent),digest(intent),encoded({'attempted':[],'completed':[]}),'pending'))
            saved = self.get(lab,key)
        if saved['intent'] != intent:
            raise RuntimeOperationError('original management usage intent changed')
        progress = saved['progress']
        if (set(progress)!={'attempted','completed'} or any(not isinstance(progress[k],list)
                or len(progress[k])!=len(set(progress[k])) or not set(progress[k])<=intent['selected'].keys()
                for k in progress) or not set(progress['completed'])<=set(progress['attempted'])):
            raise RuntimeOperationError('management usage progress differs')
        for host,segments in sorted(intent['selected'].items()):
            observed = self.observe(intent)
            ready = all(observed[host][s] for s in segments)
            if host in progress['completed']:
                if not ready: raise RuntimeOperationError('completed management usage was lost')
                continue
            if host not in progress['attempted']:
                progress['attempted'].append(host); self.save(lab,key,progress,'pending')
            if not ready:
                # Persist before the remote mutation, then repeat the complete
                # preflight. A lost acknowledgement is recovered by observation.
                self.observe(intent)
                netsetup.invoke(self.client(intent,host),'network-mark-used',intent['plans'][host],
                    networks={s:intent['networks'][host][s] for s in segments},
                    operation_id=digest(['initial-management-usage',lab,key,host,intent])[:32])
            observed = self.observe(intent)
            if not all(observed[host][s] for s in segments):
                raise RuntimeOperationError('management usage acknowledgement incomplete')
            progress['completed'].append(host); self.save(lab,key,progress,'pending')
        self.observe(intent)
        self.save(lab,key,progress,'completed')

    def verify(self, lab, key):
        intent = self.definition(lab,key)
        if intent is None: return
        saved = self.get(lab,key)
        if (not saved or saved['intent']!=intent or saved['phase']!='completed'
                or set(saved['progress']['completed'])!=set(intent['selected'])):
            raise RuntimeOperationError('completed pre-birth management usage required')
        observed = self.observe(intent)
        if any(not observed[h][s] for h,segments in intent['selected'].items() for s in segments):
            raise RuntimeOperationError('qualified management usage was lost')
