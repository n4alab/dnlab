"""Early journal rejection must remain a typed, mutation-free transport error."""
import threading

import pytest
from dnlab_runtime.manifest import RuntimeErrorBase
from dnlab_runtime.transport import Client,Server
from test_request_controls import runtime


def test_early_rejection_of_a_large_body_reports_original_journal_error(runtime,tmp_path):
    engine,journal,docker,_=runtime;server=Server(str(tmp_path/'socket'),engine)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        client=Client(str(tmp_path/'socket'),expected_journal_id='0'*32)
        with pytest.raises(RuntimeErrorBase,match='journal identity'):
            client.request('POST','/v1/operations',{'diagnostic_padding':'x'*400000})
    finally:
        server.shutdown();server.server_close();thread.join(5)
        assert journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]==0
        assert not docker.calls
