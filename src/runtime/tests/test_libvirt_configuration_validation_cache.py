"""Fresh row/dependency checks around cached pure revision validation."""
from copy import deepcopy
import pytest
from dnlab_runtime.manifest import Conflict,canonical,fingerprint
from test_libvirt_configuration import revision,install,request_profile


def test_returned_values_cannot_poison_future_reads(revision):
    driver,_,value,_,_=revision
    observed=driver.read(value['id'])
    observed['plan']['target_spec']['content']='foreign'
    assert driver.read(value['id'])==value


@pytest.mark.parametrize('column',['payload','fingerprint','installation_id','coherent_payload'])
def test_changed_row_is_revalidated_after_successful_read(revision,column):
    driver,_,value,_,_=revision
    assert driver.read(value['id'])==value
    changed=deepcopy(value);changed['nonce']='f'*32
    with driver.journal.transaction():
        if column=='coherent_payload':
            driver.journal.db.execute('UPDATE libvirt_configuration_revisions SET payload=?,fingerprint=? WHERE id=?',(canonical(changed),fingerprint(changed),value['id']))
        else:
            replacement={'payload':canonical(changed),'fingerprint':'0'*64,'installation_id':'foreign'}[column]
            driver.journal.db.execute('UPDATE libvirt_configuration_revisions SET '+column+'=? WHERE id=?',(replacement,value['id']))
    before=driver.journal.db.total_changes
    with pytest.raises(Conflict):driver.read(value['id'])
    assert driver.journal.db.total_changes==before


def test_ambiguity_is_not_hidden_by_previous_valid_row(revision):
    driver,_,value,_,_=revision
    driver.read(value['id'])
    with driver.journal.transaction():
        driver.journal.db.execute('INSERT INTO libvirt_configuration_generations SELECT * FROM libvirt_configuration_revisions WHERE id=?',(value['id'],))
    with pytest.raises(Conflict,match='ambiguous'):driver.read(value['id'])
