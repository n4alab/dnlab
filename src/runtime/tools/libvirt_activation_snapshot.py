"""Activation-specific snapshot; installation inactivity guards stay unchanged."""
from copy import deepcopy

from dnlab_runtime.libvirt_service_profile import require_activatable
from dnlab_runtime.manifest import Conflict
from tools.libvirt_install_snapshot import InstallationSnapshot


class ActivationSnapshot(InstallationSnapshot):
    def __init__(self,*args,activation_id,census,state_reader,**kwargs):
        super().__init__(*args,**kwargs);require_activatable(self.profile)
        if not callable(state_reader) or census.installation['profile']!=self.profile:
            raise Conflict('bound activation snapshot census required')
        self.activation_id,self.census,self.state_reader=activation_id,census,state_reader

    def _state(self):
        value=self.state_reader()
        if (not isinstance(value,dict) or set(value)!={'activation','receipts'}
                or value['activation'].get('id')!=self.activation_id):
            raise Conflict('original activation snapshot state required')
        return deepcopy(value)

    def _services(self,value):
        state=self._state()
        self.census.validate(state['activation'],value,state['receipts'])
        return deepcopy(value)

    def __call__(self):
        before=self._state();result=super().__call__()
        if self._state()!=before:raise Conflict('activation state changed during snapshot')
        return result
