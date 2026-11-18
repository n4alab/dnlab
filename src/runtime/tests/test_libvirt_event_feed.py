"""Actual SDK callback shapes on synthetic connections; no daemon or loop."""
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase
from test_libvirt_sdk import case, UUID


@pytest.fixture
def events(case):
    callbacks, removed = {}, []
    state = dict(loop='a'*64, close=None, fail_registration=None, fail_removal=False)
    def register(domain, event_id, callback, opaque):
        assert domain is None
        if state['fail_registration'] == event_id:raise OSError('registration reply lost')
        token = 10 + event_id
        callbacks[event_id] = callback, opaque
        return token
    def register_close(callback, opaque):
        state['close'] = callback, opaque
        return 0
    def remove(token):
        removed.append(token)
        if state['fail_removal']:raise OSError('deregister failed')
    case.raw.domainEventRegisterAny = register
    case.raw.domainEventDeregisterAny = remove
    case.raw.registerCloseCallback = register_close
    case.raw.unregisterCloseCallback = lambda: removed.append('close')
    def emit(event_id, event=2, detail=0, *, raw=None, domain=None):
        callback, opaque = callbacks[event_id]
        args = (case.raw if raw is None else raw, case.domain if domain is None else domain)
        if event_id == 0:callback(*args, event, detail, opaque)
        else:callback(*args, opaque)
    return SimpleNamespace(case=case, callbacks=callbacks, removed=removed, state=state,
                           check_loop=lambda:state['loop'], emit=emit)


def test_retained_ordered_events_and_explicit_ack(events):
    e = events
    with e.case.connect() as connection:
        feed = connection.events(check_loop=e.check_loop, limit=2)
        e.emit(0);e.emit(1)
        result = feed.read(0)
        assert result['events'] == [dict(sequence=1,uuid=UUID,kind='lifecycle',event=2,detail=0),
                                    dict(sequence=2,uuid=UUID,kind='reboot',event=None,detail=None)]
        result['events'][0]['uuid'] = 'foreign'
        assert feed.read(0)['events'][0]['uuid'] == UUID
        assert feed.read(1)['events'][0]['sequence'] == 2
        feed.acknowledge(1)
        e.emit(0,5,0)
        assert [item['sequence'] for item in feed.read(1)['events']] == [2,3]
        feed.acknowledge(3)
        assert feed.read(3)['events'] == []
    assert e.removed == [10,11,'close']
    assert [call[0] for call in e.case.calls] == ['open','close']


def test_overflow_latches_loss_and_prevents_domain_mutation(events):
    e = events
    with e.case.connect(False) as connection:
        feed = connection.events(check_loop=e.check_loop,limit=1)
        e.emit(0);e.emit(1)
        assert 'overflow' in feed.failure
        with pytest.raises(RuntimeErrorBase):feed.read(0)
        with pytest.raises(RuntimeErrorBase):connection.lookupByUUIDString(UUID)
        assert not any(call[0] == 'start' for call in e.case.calls)


@pytest.mark.parametrize('fault', ['foreign_connection','foreign_uuid','malformed_detail','boolean_event'])
def test_callback_errors_latch_instead_of_being_swallowed(events,fault):
    e = events
    with e.case.connect() as connection:
        feed = connection.events(check_loop=e.check_loop)
        if fault == 'foreign_connection':e.emit(0,raw=object())
        elif fault == 'foreign_uuid':e.emit(0,domain=SimpleNamespace(UUIDString=lambda:'invalid'))
        elif fault == 'malformed_detail':e.emit(0,detail='0')
        else:e.emit(0,event=True)
        assert feed.failure
        with pytest.raises(RuntimeErrorBase):feed.read(0)


def test_disconnect_cannot_be_replaced_by_fresh_subscription(events):
    e = events
    with e.case.connect() as connection:
        feed = connection.events(check_loop=e.check_loop)
        callback, opaque = e.state['close']
        callback(e.case.raw,1,opaque)
        with pytest.raises(RuntimeErrorBase):feed.read(0)
        with pytest.raises(RuntimeErrorBase):connection.events(check_loop=e.check_loop)


def test_original_loop_change_cannot_be_undone(events):
    e = events
    with e.case.connect() as connection:
        feed = connection.events(check_loop=e.check_loop)
        e.state['loop'] = 'b'*64
        with pytest.raises(RuntimeErrorBase):feed.read(0)
        e.state['loop'] = 'a'*64
        with pytest.raises(RuntimeErrorBase):feed.read(0)


def test_partial_registration_is_not_repeated_and_known_callbacks_are_removed(events):
    e = events;e.state['fail_registration'] = 1
    with e.case.connect() as connection:
        with pytest.raises(OSError,match='reply lost'):connection.events(check_loop=e.check_loop)
        with pytest.raises(RuntimeErrorBase):connection.events(check_loop=e.check_loop)
    assert e.removed == [10,'close']


def test_registration_receipt_is_retained_before_postcheck(events):
    e = events
    original = e.case.raw.domainEventRegisterAny
    def changed_session(*args):
        token = original(*args)
        e.case.proof['daemon']['start_ticks'] += 1
        return token
    e.case.raw.domainEventRegisterAny = changed_session
    with e.case.connect() as connection:
        with pytest.raises(RuntimeErrorBase):connection.events(check_loop=e.check_loop)
    assert e.removed == [10,'close']


def test_invalid_loop_witness_does_not_register_callbacks(events):
    e = events;e.state['loop'] = True
    with e.case.connect() as connection:
        with pytest.raises(RuntimeErrorBase):connection.events(check_loop=e.check_loop)
    assert not e.callbacks and e.state['close'] is None


def test_deregistration_errors_do_not_skip_connection_close(events):
    e = events;e.state['fail_removal'] = True
    with pytest.raises(OSError,match='deregister'):
        with e.case.connect() as connection:connection.events(check_loop=e.check_loop)
    assert e.removed == [10,11,'close']
    assert e.case.calls[-1] == ('close',)


@pytest.mark.parametrize('cursor', [-1,1,True])
def test_cursor_cannot_skip_unreceived_events(events,cursor):
    e = events
    with e.case.connect() as connection:
        feed = connection.events(check_loop=e.check_loop)
        with pytest.raises(RuntimeErrorBase):feed.read(cursor)
        with pytest.raises(RuntimeErrorBase):feed.acknowledge(cursor)


def test_acknowledged_history_and_closed_feed_cannot_be_reopened(events):
    e = events
    with e.case.connect() as connection:
        feed = connection.events(check_loop=e.check_loop)
        e.emit(1);feed.acknowledge(1)
        with pytest.raises(RuntimeErrorBase):feed.read(0)
        feed.close();feed.close()
        with pytest.raises(RuntimeErrorBase):feed.read(1)
    assert e.removed == [10,11,'close']
