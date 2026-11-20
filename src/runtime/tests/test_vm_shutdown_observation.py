"""Boot/QMP/proc pipeline with inert SDK and pidfd; no real VM or signals."""
import select

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.vm_shutdown_observation import VMShutdownObservation
from test_vm_creation_event_binding import pipeline, event_boot, creation, process, observer, boot, definition, template, instance


@pytest.mark.parametrize('reason',[1,0,2,3,4])
@pytest.mark.parametrize('shape',[list,tuple])
def test_only_original_pidfd_exit_and_guest_shutdown_reason_complete(pipeline,monkeypatch,reason,shape):
    p=pipeline;e=p.events;value=p.driver.apply(e.operation)
    process=p.driver._observer(value).process
    observed=VMShutdownObservation(p.driver)
    domain=e.state['domains'][value['birth']['uuid']]
    before=p.driver.definitions.read(e.operation)
    with process.exit_witness(value['birth']) as witness:
        assert observed(value,witness) is None
        domain.active=0
        monkeypatch.setattr(type(domain),'state',lambda self,flags:shape((5,reason)))
        p.kernel.state['events']=[(witness._fd,select.POLLIN|select.POLLHUP)]
        if reason==1:
            result=observed(value,witness)
            assert result['exit']['exited'] is True and result['birth']==value['birth']
            assert result['inactive_ack']==value['ack'] and result['reason']=='guest-shutdown'
        else:
            with pytest.raises(RuntimeErrorBase,match='ordinary guest shutdown'):observed(value,witness)
    assert p.driver.definitions.read(e.operation)==before
    assert e.state['starts']==e.state['resumes']==1 and p.control==dict(queries=1,correlations=1)


def test_libvirt_inactive_state_without_pidfd_exit_is_not_completion(pipeline,monkeypatch):
    p=pipeline;e=p.events;value=p.driver.apply(e.operation);process=p.driver._observer(value).process
    with process.exit_witness(value['birth']) as witness:
        domain=e.state['domains'][value['birth']['uuid']];domain.active=0
        monkeypatch.setattr(type(domain),'state',lambda self,flags:(5,1))
        with pytest.raises(RuntimeErrorBase):VMShutdownObservation(p.driver)(value,witness)
    assert e.state['starts']==1
