"""Compose installation primitives; host inventory/account execution stay injected.

No command, daemon start or discovery fallback is supplied here. A production
caller must qualify the snapshot, dependency reader and durable account helper.
"""
from copy import deepcopy

from .manifest import Conflict


class ProvisioningAdapter:
    def __init__(self, *, window, accounts, files, snapshot, directory_dependency):
        self.window,self.accounts,self.files=window,accounts,files
        self.snapshot,self.directory_dependency=snapshot,directory_dependency
        if accounts.journal is not files.journal:
            raise Conflict('one original provisioning journal required')

    def _window(self, value):
        if (value['id']!=self.window.receipt['operation_id']
                or value['context']!=self.window.receipt['context']
                or value['prerequisites'].get('provisioning_window_sha256')!=self.window.sha256
                or {i['spec']['key'] for i in value['items']}!=set(self.window.receipt['targets'])):
            raise Conflict('original installation provisioning window differs')
        for item in value['items']:self.window.verify(item,value['id'])

    def observe(self, value):
        return self._observe(value)

    def account_preflight(self,value,current_request_sha256):
        return self._observe(value,current_request_sha256=current_request_sha256)

    def _observe(self,value,current_request_sha256=None):
        self._window(value)
        snapshot=self.snapshot()
        if (not isinstance(snapshot,dict) or set(snapshot)!={'context','prerequisites'}
                or snapshot['context']!=value['context']
                or snapshot['prerequisites']!=value['prerequisites']):
            raise Conflict('complete host provisioning prerequisites differ')
        result={}
        for item in value['items']:
            spec=item['spec']
            if item['phase']=='dependency':
                if spec['kind']!='directory':raise Conflict('directory dependency required')
                result[spec['key']]=self.directory_dependency(deepcopy(spec))
            elif spec['kind'] in ('group','account'):
                if current_request_sha256 is None:
                    result[spec['key']]=self.accounts.observe(item,value['id'])
                else:
                    result[spec['key']]=self.accounts.preflight_observe(item,value['id'],
                        current_request_sha256=current_request_sha256,window_sha256=self.window.sha256)
            elif spec['kind'] in ('directory','file'):
                result[spec['key']]=self.files.observe(item,value['id'])
            else:raise Conflict('unknown provisioning target kind')
        # The snapshot and window may change while account/filesystem reads run.
        self._window(value)
        if self.snapshot()!=snapshot:raise Conflict('host provisioning prerequisites changed during observation')
        return dict(context=deepcopy(snapshot['context']),prerequisites=deepcopy(snapshot['prerequisites']),targets=result)

    def create(self,item,operation):
        self.window.verify(item,operation)
        if item['spec']['kind'] in ('group','account'):
            result=self.accounts.create(item,operation,window=self.window)
        elif item['spec']['kind'] in ('directory','file'):
            result=self.files.create(item,operation,window=self.window)
        else:raise Conflict('unknown provisioning target kind')
        self.window.verify(item,operation)
        return result

    def recover(self,item,operation):
        self.window.verify(item,operation)
        if item['spec']['kind'] in ('group','account'):
            result=self.accounts.recover(item,operation,window=self.window)
        elif item['spec']['kind'] in ('directory','file'):
            result=self.files.recover(item,operation,window=self.window)
        else:raise Conflict('unknown provisioning target kind')
        self.window.verify(item,operation)
        return result
