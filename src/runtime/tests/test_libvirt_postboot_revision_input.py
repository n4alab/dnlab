"""Reopen the completed revision and backup through the readonly recipe."""

from copy import deepcopy

import pytest

from dnlab_runtime.manifest import Conflict
from test_libvirt_successor_unit_files import successor, configured, install, request_profile
from tools.libvirt_postboot_revision_input import completed_revision_input


@pytest.fixture
def binding(successor):
    driver, adapter, prepared, root, _, historical = successor
    source = driver.apply(prepared['id'])
    current = deepcopy(source['context'])
    current['boot_id'] = 'boot-after-unit-exchange'
    return driver, dict(source=source, window=adapter.window.receipt), historical['installation'], current, root


def test_frozen_revision_reopens_query_only_and_preserves_original_files(binding):
    driver, value, installation, current, root = binding
    journal = driver.journal
    journal.db.execute('PRAGMA query_only=ON')
    before = journal.db.total_changes
    completed = completed_revision_input(journal, value, installation, current, root=root)
    assert completed.observe(installation, current) == completed.reference['proof']
    assert completed.exchange.swap.files.readonly is True
    with pytest.raises(Conflict, match='readonly'):
        completed.revision.apply(completed.reference['id'])
    with pytest.raises(Conflict, match='readonly'):
        completed.exchange.swap.execute(completed.exchange.request)
    assert journal.db.total_changes == before


@pytest.mark.parametrize('fault', ['source', 'boot', 'backup'])
def test_foreign_source_boot_or_backup_is_rejected(binding, fault):
    driver, value, installation, current, root = binding
    if fault == 'source':
        value['source']['configuration_revision']['receipt_sha256'] = 'foreign'
    elif fault == 'boot':
        current = value['source']['context']
    else:
        reference = driver.read(value['window']['operation_id'])
        (root / reference['backup'].lstrip('/')).write_text('foreign backup')
    with pytest.raises(Conflict):
        completed_revision_input(driver.journal, value, installation, current, root=root).observe(installation, current)
