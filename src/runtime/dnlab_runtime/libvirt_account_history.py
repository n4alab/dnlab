"""Read committed account creation history, never current process liveness.

The original worker's saved exit is historical evidence. No procfs, pidfd, NSS,
account tool or helper recovery is invoked, including after a different boot.
Current account identity must be observed independently by the qualification.
"""
from copy import deepcopy
import json
import sqlite3

from .libvirt_account_commands import command_plan,reference_proof
from .libvirt_provisioning import account_request
from .manifest import Conflict,fingerprint


class HistoricalAccountCreation:
    def __init__(self,journal,*,installation,worker_profile,binaries,source_reader):
        self.journal=journal
        self.installation,self.profile,self.binaries=deepcopy(installation),deepcopy(worker_profile),deepcopy(binaries)
        if not callable(source_reader):raise Conflict('original installation reader required')
        self.source_reader=source_reader

    def _row(self,table,column,key):
        # Table/column pairs are fixed by this implementation, never caller SQL.
        allowed={'libvirt_install_account_births':'operation_id=? AND nonce=?',
            'libvirt_account_commands':'request_sha256=?','libvirt_account_workers':'token=?',
            'libvirt_account_processes':'token=?'}
        if allowed.get(table)!=column:raise Conflict('fixed account history query required')
        try:row=self.journal.db.execute('SELECT payload,fingerprint FROM '+table+' WHERE '+column,key).fetchone()
        except sqlite3.Error as error:raise Conflict('original account history unavailable') from error
        if row is None:raise Conflict('original committed account history missing')
        value=json.loads(row['payload'])
        if fingerprint(value)!=row['fingerprint']:raise Conflict('original account history integrity differs')
        return value

    def __call__(self,item):
        original=self.installation;operation=original['id']
        if item not in original['items'] or item['spec']['kind'] not in ('group','account') or item['phase']!='created':
            raise Conflict('original installed account item required')
        with self.journal.execution_lock:
            if self.source_reader(operation)!=original:raise Conflict('original historical installation changed')
            request=account_request(item,operation);command=command_plan(request,self.binaries)
            birth=self._row('libvirt_install_account_births','operation_id=? AND nonce=?',(operation,item['nonce']))
            expected=dict(request_sha256=fingerprint(request),exit_code=0,identity=request['expected'])
            if (birth.get('request')!=request or birth.get('phase')!='created' or birth.get('completion')!=expected
                    or birth.get('window_sha256')!=original['prerequisites'].get('provisioning_window_sha256')
                    or item['proof']['identity']!=request['expected']):
                raise Conflict('original account birth/completion binding differs')
            executed=self._row('libvirt_account_commands','request_sha256=?',(fingerprint(request),))
            if executed.get('request')!=request or executed.get('command')!=command or executed.get('phase')!='completed':
                raise Conflict('original account command not completed')
            reference=executed.get('reference');reference_proof(reference,command)
            context=original['context'];process=reference['process_record']
            prerequisites=deepcopy(original['prerequisites']);prerequisites.pop('provisioning_window_sha256',None)
            preflight=dict(qualified=True,command_sha256=fingerprint(command),context_sha256=fingerprint(context),
                inputs_sha256=fingerprint(prerequisites))
            if (executed.get('preflight')!=preflight or executed['preflight']['qualified'] is not True
                    or process['boot_id']!=context['boot_id']
                    or process['namespace_sha256']!=fingerprint(context['namespaces'])
                    or process['executable_sha256']!=self.profile['python']['sha256']):
                raise Conflict('original account command creation context differs')
            worker=self._row('libvirt_account_workers','token=?',(reference['token'],))
            outcome=executed.get('outcome')
            if (not isinstance(outcome,dict) or set(outcome)!={'reference','exit_code','stdout','stderr'}
                    or outcome['reference']!=reference or type(outcome['exit_code']) is not int or outcome['exit_code']!=0
                    or any(not isinstance(outcome[k],str) or len(outcome[k].encode())>65536 for k in ('stdout','stderr'))
                    or worker.get('phase')!='completed' or worker.get('reference')!=reference
                    or worker.get('token')!=reference['token'] or worker.get('command')!=command
                    or worker.get('profile')!=self.profile or worker.get('outcome')!=outcome):
                raise Conflict('original account worker completion differs')
            observed=self._row('libvirt_account_processes','token=?',(reference['token'],))
            snapshot=observed.get('snapshot',{})
            if (observed.get('reference')!=reference or observed.get('command_sha256')!=fingerprint(command)
                    or snapshot.get('record')!=process or snapshot.get('namespaces')!=context['namespaces']
                    or observed.get('exit')!=dict(exit_code=0,process_record=process)
                    or type(observed['exit']['exit_code']) is not int):
                raise Conflict('original durable account worker exit differs')
            if self.source_reader(operation)!=original:raise Conflict('historical installation changed during read')
            return dict(kind='historical-account-creation-v1',installation_sha256=fingerprint(original),
                original_proof=deepcopy(item['proof']),creation_context_sha256=fingerprint(context),
                evidence_sha256=fingerprint(dict(birth=birth,command=executed,worker=worker,process=observed)))
