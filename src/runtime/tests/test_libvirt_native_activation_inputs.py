"""Exercise native input wiring with the original journal and temporary files."""

from contextlib import contextmanager
from copy import deepcopy
import os
from pathlib import Path

import pytest

from dnlab_runtime.libvirt_activation_controller import resource_digest
from dnlab_runtime.libvirt_activation_services import ActivationServices
from dnlab_runtime.manifest import Conflict, fingerprint
from test_libvirt_activation_exchange import active_exchange, activation_files, successor, configured, install, request_profile, service
from tools import libvirt_native_activation_inputs as native
from tools.libvirt_service_units import observe_service_files


@pytest.fixture
def inputs(active_exchange, monkeypatch):
    files, _, state, row, _, adapter, _, source = active_exchange
    lineage = files.lineage
    expected = deepcopy(source['prerequisites'])
    expected.pop('services', None)

    class Snapshot:
        def __init__(self, root, request, packages, accounts, **kwargs):
            assert root == lineage.view.files.root and request == source['request']

        def observe_static(self):
            return dict(context=deepcopy(source['context']), prerequisites=deepcopy(expected))

    def forbidden(*args, **kwargs):
        pytest.fail('unexpected native host observation')

    def targets(current, accounts, dependency):
        assert current is lineage
        return dict(observed=True)

    monkeypatch.setattr(native, 'InstallationSnapshot', Snapshot)
    monkeypatch.setattr(native, 'observe_activation_targets', targets)
    provider = native.ActivationHostInputs(lineage, swap=adapter.swap, expected_packages={},
                                           approved_account_inputs={}, query=forbidden, nss_query=forbidden)
    return provider, state, row, expected


def test_progressive_census_can_read_unit_birth_without_recursive_census(inputs):
    provider, state, row, _ = inputs

    def generation(*args):
        def read():
            return dict(row, files=observe_service_files(provider.files, provider.source))

        return read

    services = ActivationServices(provider.source, generation_observer=generation)
    before = provider.lineage.view.journal.db.total_changes
    assert services.validate(state['activation'], state['inventory'], state['receipts'])['installation_sha256'] == fingerprint(provider.source)
    assert provider.resources(state['activation'], state['receipts'])['resources_sha256'] == resource_digest(provider.source)
    assert provider.lineage.view.journal.db.total_changes == before


def test_changed_prerequisites_and_original_backup_block(inputs):
    provider, state, _, expected = inputs
    old = deepcopy(expected)
    expected['profile_sha256'] = 'foreign'
    with pytest.raises(Conflict, match='host prerequisites differ'):
        provider.resources(state['activation'], state['receipts'])
    expected.update(old)
    backup = Path(provider.root) / provider.lineage.reference['backup'].lstrip('/')
    backup.write_text('preserve this foreign backup')
    with pytest.raises(Conflict):
        provider.resources(state['activation'], state['receipts'])
    assert backup.read_text() == 'preserve this foreign backup'


def test_entry_uses_original_journal_and_qualified_inputs(inputs, monkeypatch):
    provider, _, _, _ = inputs
    descriptors = []

    @contextmanager
    def open_native(journal, installation, *, root, **kwargs):
        descriptors.append(root)
        assert journal is provider.lineage.view.journal and installation == provider.source
        assert kwargs['inventory'] is provider.inventory and kwargs['files'] is provider.files
        assert kwargs['resources'] == provider.resources and kwargs['source_reader'] == provider.lineage.read
        assert os.fstat(root).st_ino == os.stat(provider.root).st_ino
        yield 'original supervisor'

    monkeypatch.setattr(native, 'open_native_activation', open_native)
    with native.open_lineage_activation(provider, unit_query=lambda *a: None) as session:
        assert session == 'original supervisor'
    with pytest.raises(OSError):
        os.fstat(descriptors[0])
