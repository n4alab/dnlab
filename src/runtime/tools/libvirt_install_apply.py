"""Apply the original prepared session only; never prepare or adopt on retry.

The caller supplies an assembled, qualified session and the immutable reference
from its successful prepare. Host authorization and worker supervision belong to
the explicit operational recipe, not module import or construction.
"""
from dnlab_runtime.manifest import Conflict


def apply_original(session, reference, *, journal_identity):
    journal = session.installer.journal
    with journal.execution_lock:
        if not isinstance(journal_identity,str) or journal.identity != journal_identity:
            raise Conflict('original prepared installation journal differs')
        if (not isinstance(reference,dict) or reference.get('phase')!='prepared'
                or reference.get('id')!=session.window.receipt['operation_id']):
            raise Conflict('original prepared installation reference required')
        current=session.installer.read(reference['id'])
        keys=('id','request','profile','context','prerequisites','dependencies')
        if (any(current[key]!=reference.get(key) for key in keys)
                or [(item['spec'],item['nonce']) for item in current['items']]
                    !=[(item['spec'],item['nonce']) for item in reference.get('items',[])]):
            raise Conflict('original prepared installation binding differs')
        return session.apply()
