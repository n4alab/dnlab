"""Compose revision journals with tracked staging/exchange; no service commands.

The provider must qualify the unchanged installation resources and inactive
session in the current context. No native provider or operational entrypoint is
supplied here. Filesystem integration tests use private temporary files only.
"""
from copy import deepcopy
import os

from .libvirt_configuration import UNIT,compile_revision
from .libvirt_configuration_staging import ConfigurationStaging
from .libvirt_configuration_swap import ConfigurationSwap
from .manifest import Conflict,fingerprint


class ConfigurationFileAdapter:
    def __init__(self,files,*,window,preflight):
        if not callable(preflight):raise Conflict('complete configuration provider required')
        self.files,self.window,self.preflight=files,window,preflight
        self.journal=files.journal
        self.staging=ConfigurationStaging(self.journal,files,window=window,preflight=self._stage_preflight)
        self.swap=ConfigurationSwap(self.staging,preflight=self._swap_preflight)

    @staticmethod
    def request(value):
        if (value['plan']!=compile_revision(value['installation'])
                or value['source_sha256']!=fingerprint(value['installation'])
                or value['phase'] not in ('prepared','replace_requested','completed')):
            raise Conflict('original configuration adapter binding differs')
        nonce=value['nonce']
        if (not isinstance(nonce,str) or len(nonce)!=32
                or any(c not in '0123456789abcdef' for c in nonce)):
            raise Conflict('original configuration adapter nonce differs')
        prefix='/etc/systemd/system/.dnlab-libvirtd.'+nonce
        if value['staging']!=prefix+'.candidate' or value['backup']!=prefix+'.previous':
            raise Conflict('original configuration adapter paths differ')
        result=deepcopy(value)
        result.update(phase='replace_requested',proof=None)
        return result

    def _complete(self,value):
        if (self.window.sha256!=value['window_sha256']
                or self.window.receipt['operation_id']!=value['id']
                or self.window.receipt['context']!=value['installation']['context']):
            raise Conflict('original configuration adapter window binding differs')
        expected=dict(context=value['installation']['context'],source_sha256=value['source_sha256'],
            unchanged_sha256=value['plan']['unchanged_sha256'],services_inactive=True)
        result=self.preflight(deepcopy(value))
        if result!=expected or result.get('services_inactive') is not True:
            raise Conflict('complete original inactive session preflight differs')

    def _stage_preflight(self,value):
        self._complete(value)
        return dict(revision_sha256=fingerprint(value),source_proof=value['plan']['source_item']['proof'])

    def _swap_preflight(self,value):
        self._complete(value)
        return dict(revision_sha256=fingerprint(value),unchanged_sha256=value['plan']['unchanged_sha256'],services_inactive=True)

    def _backup_absent(self,value):
        with self.files._parent(value['backup']) as (parent,name):
            try:os.stat(name,dir_fd=parent,follow_symlinks=False)
            except FileNotFoundError:return
            raise Conflict('original backup destination occupied')

    def observe(self,value):
        request=self.request(value)
        with self.journal.execution_lock:
            self._complete(request)
            swap=self.swap._read(request)
            receipt=None
            if swap is not None:
                if swap['phase']=='completed':receipt=self.swap.observe(request)
                else:
                    # Qualify either original arrangement at an uncertain rename
                    # boundary without completing, syncing or repeating it.
                    layouts={'exchange_requested':('original','exchanged'),
                        'exchanged':('exchanged',),'backup_requested':('exchanged','backed_up')}
                    errors=[]
                    for layout in layouts[swap['phase']]:
                        try:self.swap._locations(request,layout)
                        except Conflict as error:errors.append(error)
                        else:break
                    else:raise Conflict('uncertain exchange resources not qualified') from errors[-1]
            else:
                source=self.files.observe(request['plan']['source_item'],request['installation']['id'])
                if source!=request['plan']['source_item']['proof']:raise Conflict('original unit generation differs')
                self._backup_absent(request)
                stage=self.staging._read(request)
                if stage is None:
                    if self.files.observe(self.staging.item(request),request['id']) is not None:
                        raise Conflict('untracked staging resource')
                else:self.staging.observe(request)
            self._complete(request)
            return dict(context=deepcopy(request['installation']['context']),source_sha256=request['source_sha256'],
                unchanged_sha256=request['plan']['unchanged_sha256'],receipt=receipt)

    def replace(self,value):
        if value['phase']!='replace_requested':raise Conflict('committed replacement request required')
        request=self.request(value)
        with self.journal.execution_lock:
            self._complete(request)
            if self.swap._read(request) is not None:raise Conflict('original exchange held; explicit recovery required')
            self.staging.stage(request)
            return self.swap.execute(request)

    def recover(self,value):
        if value['phase']!='replace_requested':raise Conflict('original replacement request required for recovery')
        request=self.request(value)
        with self.journal.execution_lock:
            self._complete(request)
            self.window.verify(dict(spec=request['plan']['target_spec']),request['id'],request['window_sha256'])
            swap=self.swap._read(request)
            if swap is not None:return self.swap.recover(request)
            # No new candidate is permitted in recovery. A recorded staging birth
            # must already exist before the first exchange can be requested.
            self.staging.recover(request)
            return self.swap.execute(request)

    def observe_revised_file(self,item,creator,request):
        """Resolve the effective unit through its original transition, not name."""
        original=self.request(request)
        if (creator!=original['id'] or item['spec']!=original['plan']['target_spec']
                or item['nonce']!=original['nonce'] or item['spec']['path']!=UNIT):
            raise Conflict('effective configuration creator/specification differs')
        receipt=self.swap.observe(original)['replacement']
        if receipt!=item['proof']:raise Conflict('effective configuration birth differs')
        return receipt
