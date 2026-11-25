"""Host admission wired to real directory controllers and inert observers."""
from copy import deepcopy
from types import SimpleNamespace

import pytest

from dnlab_runtime.manifest import RuntimeErrorBase, fingerprint
from dnlab_runtime.vm_host_preflight import VMHostPreflight, UNITS
from test_vm_directories import directories
from test_vm_definition import definition, template, instance


@pytest.fixture
def host(directories, template):
    directory, definitions, birth, allocation, _, _ = directories
    operation = birth['creator_operation_id']
    context = deepcopy(allocation['context'])
    state = dict(context=deepcopy(context), parent=deepcopy(directory.parent), scope='f'*64,
                 assets=True, writers=[], hook=None)
    state['services'] = {unit:dict(pid=index+200, start_ticks=index+300, pidfd_alive=True,
        boot_id=context['boot_id'], namespaces=deepcopy(context['namespaces']),
        uids=[1001]*4, gids=[1001]*4) for index, unit in enumerate(UNITS)}
    class Assets:
        def verify(self, **request):
            assert request == dict(birth=birth, template=template, bundle_root='/templates/synthetic')
            if state['hook']:state['hook']()
            return dict(template_sha256=birth['template_sha256'], assets_verified=state['assets'])
    driver = VMHostPreflight(definitions, context=context, read_context=lambda:deepcopy(state['context']),
        root=directory.root, parent_identity=directory.parent, observe_parent=lambda:deepcopy(state['parent']),
        assets=Assets(), template=template, bundle_root='/templates/synthetic',
        services=lambda:deepcopy(state['services']), writers=lambda value:deepcopy(state['writers']),
        scope_sha256='f'*64, verify_scope=lambda:state['scope'])
    directory.preflight = driver.directory
    tap_request = dict(id=operation, birth=deepcopy(birth),
        definition_sha256=definitions.read(operation)['request_fingerprint'],
        context=dict(boot_id=context['boot_id'], **context['namespaces']['net']))
    return SimpleNamespace(driver=driver, directory=directory, operation=operation,
                           state=state, allocation=allocation, taps=tap_request)


def test_current_capabilities_admit_one_directory_and_the_original_tap_namespace(host):
    e = host
    e.directory.prepare(e.operation);ready = e.directory.apply(e.operation)
    proof = e.driver.directory(ready, mutating=False)
    assert proof['parent_sha256'] == fingerprint(dict(root=e.directory.root, identity=e.directory.parent))
    assert 'exclusive_writer' not in proof and e.allocation['creates'] == 1
    taps = e.driver.taps(e.taps)
    assert taps['session_namespace_verified'] and taps['guest_writers_absent']
    assert taps['context_sha256'] == fingerprint(e.taps['context'])


@pytest.mark.parametrize('fault', ['context','parent','scope','assets','daemon-pid',
                                  'daemon-namespace','daemon-credentials','daemon-exit','writer'])
def test_changed_prerequisites_refuse_directory_creation(host, fault):
    e = host
    if fault == 'context':e.state['context']['namespaces']['net']['inode'] += 1
    elif fault == 'parent':e.state['parent']['inode'] += 1
    elif fault == 'scope':e.state['scope'] = 'e'*64
    elif fault == 'assets':e.state['assets'] = False
    elif fault == 'writer':e.state['writers'] = [{'foreign':True}]
    else:
        daemon = e.state['services'][UNITS[0]]
        if fault == 'daemon-pid':daemon['pid'] = e.state['services'][UNITS[1]]['pid']
        elif fault == 'daemon-namespace':daemon['namespaces']['net']['inode'] += 1
        elif fault == 'daemon-credentials':daemon['uids'][0] = 0
        else:daemon['pidfd_alive'] = False
    with pytest.raises(RuntimeErrorBase):e.directory.prepare(e.operation)
    assert e.allocation['creates'] == 0 and not e.allocation['requests']


def test_parent_change_during_asset_observation_stops_before_allocation(host):
    e = host;e.state['hook'] = lambda:e.state['parent'].update(inode=e.state['parent']['inode']+1)
    with pytest.raises(RuntimeErrorBase,match='parent changed'):e.directory.prepare(e.operation)
    assert e.allocation['creates'] == 0


@pytest.mark.parametrize('fault', ['owner','namespace','writer','provider','template'])
def test_tap_preflight_rejects_other_generations_or_replaced_capabilities(host,fault):
    e = host;request = deepcopy(e.taps)
    if fault == 'owner':request['birth']['node_id'] = 'foreign'
    elif fault == 'namespace':request['context']['inode'] += 1
    elif fault == 'writer':e.state['writers'] = [{'foreign':True}]
    elif fault == 'provider':e.driver.services = lambda:deepcopy(e.state['services'])
    else:e.driver.template['hardware']['memory_mib'] += 1
    with pytest.raises(RuntimeErrorBase):e.driver.taps(request)
    assert e.allocation['creates'] == 0
