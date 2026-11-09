import json

import pytest

from dnlab_runtime.endpoint_reservations import require_available
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict


@pytest.mark.parametrize('phase',['applying','active','cleanup_pending','recovery_required','cleaned'])
def test_realnet_reserves_endpoint_until_verified_cleanup(tmp_path,phase):
    journal=Journal(tmp_path)
    try:
        with journal.transaction():
            journal.db.execute('CREATE TABLE realnet_attachments(id TEXT PRIMARY KEY,payload TEXT,phase TEXT)')
            journal.db.execute('INSERT INTO realnet_attachments VALUES(?,?,?)',('rn0',json.dumps({'source':{'ifname':'port0'}}),phase))
        for table in ('local_vxlans','local_bridges'):
            if phase=='cleaned':require_available(journal,['port0'],owner_table=table,owner_id='new')
            else:
                with pytest.raises(Conflict,match='reserved'):require_available(journal,['port0'],owner_table=table,owner_id='new')
        require_available(journal,['other'],owner_table='local_bridges',owner_id='new')
    finally:journal.close()
