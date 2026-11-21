"""Boot/exit/undefine/census composition with simulated lower file removal."""
from copy import deepcopy

from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_storage_retirement import VMStorageRetirement
from test_vm_stopped_retirement import stopped, shutdown, boot, pipeline, event_boot, creation, process, observer, definition, template, instance


def test_stopped_boot_history_survives_storage_cleanup_with_real_writer_census(stopped,monkeypatch):
    e = stopped;storage = e.storage;operation = e.p.events.operation;journal = storage.journal
    e.retire.prepare('retire-stopped',operation);receipt = e.retire.apply('retire-stopped')
    ready = storage.read(operation)
    agreement = dict(operation_id=operation,context={'host_id':'synthetic'},
        targets=['file:'+item['spec']['path'] for item in ready['items']],nonce='e'*32)
    window = ProvisioningWindow(agreement,lambda:deepcopy(agreement))

    class Lower:
        def __init__(self,files,*,window,preflight):
            self.files,self.journal,self.window,self.preflight = files,journal,window,preflight
            self.values = {}
            with journal.transaction():
                journal.db.execute('CREATE TABLE vm_overlay_retirements (operation_id TEXT,nonce TEXT)')
        def _key(self,item):return dict(spec=dict(key='file:'+item['spec']['path']))
        def read(self,item,owner):return deepcopy(self.values[item['nonce']])
        def _layout(self,value):
            actual = self.files.observe(value['item'],operation)
            assert actual == (None if value['phase'] == 'removed' else value['item']['proof'])
        def prepare(self,item,owner,*,definition_retirement_sha256):
            if item['nonce'] not in self.values:
                value = dict(operation_id=owner,item=deepcopy(item),phase='prepared',
                    definition_retirement_sha256=definition_retirement_sha256)
                self.preflight(value)
                self.values[item['nonce']] = value
                with journal.transaction():journal.db.execute('INSERT INTO vm_overlay_retirements VALUES(?,?)',(owner,item['nonce']))
            return self.read(item,owner)
        def apply(self,item,owner):
            value = self.values[item['nonce']];self.preflight(value)
            if value['phase'] != 'removed':
                e.files['files'].pop(item['spec']['path']);value['phase'] = 'removed'
            self.preflight(value)
            return deepcopy(value)

    monkeypatch.setattr('dnlab_runtime.vm_storage_retirement.OverlayRetirement',Lower)
    def remaining(value):
        assert e.taps.observe(operation)['phase'] == 'retained'
        return dict(definition_sha256=e.running['request_fingerprint'],retirement_sha256=fingerprint(receipt),
                    endpoints_verified=True,directory_verified=True)
    driver = VMStorageRetirement(storage,e.retire,window=window,preflight=remaining)
    driver.prepare('retire-storage',operation,'retire-stopped')
    assert driver.apply('retire-storage')['phase'] == 'removed'
    assert storage.definitions.read(operation)['boot'] == e.running['boot']
    assert storage.writers(ready) == [] and storage.read(operation) == ready
    assert e.files['files'] == {} and e.control['calls'] == e.control['undefines'] == 1
