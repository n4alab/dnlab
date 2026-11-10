"""Read a completed unit exchange while qualified activation services are alive.

No staging, rename, sync, recovery or schema initialization occurs here. Original
mutation guards stay in ConfigurationSwap; this reader requires independent
resource preflight and the activation's qualified progressive service census.
"""
from copy import deepcopy

from .libvirt_configuration import ConfigurationRevision,project_revision
from .libvirt_configuration_adapter import ConfigurationFileAdapter
from .manifest import Conflict,fingerprint,identifier


class CompletedExchangeObserver:
    def __init__(self,swap,reference,*,activation_id,resources,services,state):
        identifier(activation_id,'original exchange observer activation_id')
        if not callable(resources) or not callable(state):raise Conflict('explicit activation exchange preflight required')
        self.swap,self.reference=swap,deepcopy(reference)
        self.source=project_revision(reference)
        if services.installation!=self.source:raise Conflict('original activation census installation differs')
        self.activation_id,self.resources,self.services,self.state=activation_id,resources,services,state
        self.request=ConfigurationFileAdapter.request(reference)
        if swap.window.sha256!=reference['window_sha256']:
            raise Conflict('original completed exchange window binding differs')

    def _preflight(self):
        value=self.reference
        expected=dict(revision_sha256=fingerprint(value),unchanged_sha256=value['plan']['unchanged_sha256'],
            context=deepcopy(self.source['context']))
        if self.resources(deepcopy(value))!=expected:
            raise Conflict('complete activation exchange resource preflight differs')
        state=self.state()
        if (not isinstance(state,dict) or set(state)!={'activation','inventory','receipts'}
                or state['activation'].get('id')!=self.activation_id):
            raise Conflict('original activation exchange census state required')
        census=self.services.validate(state['activation'],state['inventory'],state['receipts'])
        return dict(resources=expected,services=census,activation_id=self.activation_id)

    def observe(self):
        with self.swap.journal.execution_lock:
            before=self._preflight()
            record=self.swap._read(self.request)
            if record is None or record['phase']!='completed':raise Conflict('original exchange completion pending')
            old,new=self.swap._locations(self.request,'backed_up')
            receipt=dict(operation_id=self.reference['id'],nonce=self.reference['nonce'],source_proof=old,
                backup=dict(path=self.reference['backup'],identity=old['identity']),
                replacement=dict(intent_id=self.reference['id'],nonce=self.reference['nonce'],
                    spec_sha256=fingerprint(self.reference['plan']['target_spec']),identity=new['identity']))
            ConfigurationRevision._receipt(self.reference,receipt)
            if receipt!=self.reference['proof']:raise Conflict('original completed exchange receipt differs')
            if (self.swap._read(self.request)!=record or self.swap._locations(self.request,'backed_up')!=(old,new)
                    or self._preflight()!=before):
                raise Conflict('activation exchange observation changed')
            return deepcopy(receipt)
