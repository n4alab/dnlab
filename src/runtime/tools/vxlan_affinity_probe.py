"""Local fixture gates for underlay replacement and namespace mount reuse."""
import json
import os
from pathlib import Path
import uuid

from dnlab_runtime.manifest import Conflict
from dnlab_runtime.vxlan import link_signature


def probe(root, report, names, created, managers, identities, create, other_payload, ip, command, namespace_linux):
    create('a')
    payload = managers['a'].row(identities['a'].digest)['payload']
    ip(names['a'], 'link', 'set', 'dev', 'underlay0', 'name', 'old-underlay')
    ip(names['a'], 'link', 'add', 'underlay0', 'type', 'dummy')
    ip(names['a'], 'link', 'set', 'dev', 'underlay0', 'up')
    inventory = managers['a'].linux.links()
    replacement = next(x for x in inventory if x['ifname'] == 'underlay0')
    original = next(x for x in inventory if x['ifname'] == 'old-underlay')
    assert original['ifindex'] == payload['underlay_identity']['ifindex']
    assert replacement['ifindex'] != original['ifindex']
    try:
        managers['a'].verify(identities['a'], payload)
    except Conflict as error:
        assert str(error) == 'VXLAN underlay identity changed'
    else:
        raise AssertionError('replaced underlay accepted')
    managers['a'].delete(identities['a'])
    inventory = managers['a'].linux.links()
    assert link_signature(next(x for x in inventory if x['ifname'] == 'underlay0')) == link_signature(replacement)
    assert link_signature(next(x for x in inventory if x['ifname'] == 'old-underlay')) == link_signature(original)
    assert identities['a'].resolve(inventory) is None
    managers['b'].verify(identities['b'], other_payload)
    report['underlay_replacement'] = {'rejected': True, 'owned_cleanup': True,
                                     'replacement_preserved': link_signature(replacement),
                                     'original_preserved': link_signature(original)}
    # Only this fixture-created dummy is removed; restore the original name.
    ip(names['a'], 'link', 'delete', 'dev', 'underlay0')
    ip(names['a'], 'link', 'set', 'dev', 'old-underlay', 'name', 'underlay0')
    name = 'drsp-guard-' + uuid.uuid4().hex[:8]
    command(['ip', 'netns', 'add', name])
    created.append(name)
    names['guard'] = name
    executor = namespace_linux(name)
    held = os.open('/var/run/netns/' + name, os.O_RDONLY)
    try:
        old = executor.network_identity()
        command(['ip', 'netns', 'delete', name])
        command(['ip', 'netns', 'add', name])
        actual = executor.network_identity()
        assert actual != old
        try:
            executor.run(['ip', 'link', 'add', 'forbidden0', 'type', 'dummy'])
        except Conflict as error:
            assert str(error) == 'fixture namespace mount was replaced'
        else:
            raise AssertionError('replaced namespace accepted')
        inventory = json.loads(ip(name, '-j', '-d', 'link', 'show'))
        assert not any(x['ifname'] == 'forbidden0' for x in inventory)
        report['namespace_replacement'] = {'old': old, 'new': actual, 'mutation_rejected': True,
                                           'replacement_namespace_untouched': True}
    finally:
        os.close(held)
