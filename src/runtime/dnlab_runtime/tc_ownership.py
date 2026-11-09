"""Per-attempt TC action proofs, committed before installation and after readback."""
import uuid

from .manifest import Conflict


def signature(link):
    return {key: link.get(key) for key in ('ifname','ifindex','ifalias','address','link_index')}


def reserve(source,target):
    return {'cookie':uuid.uuid4().hex,'source':signature(source),'target':signature(target),'index':None}


def qualified(values,target,predicate,proof,links,*,capture=False):
    # Legacy rules can be removed only while their original target is bound.
    if proof is None:
        return predicate(values,target)
    if not values:return False
    actions=values[-1].get('options',{}).get('actions',[])
    if len(actions)!=1:return False
    action=actions[0];index=action.get('index')
    if (action.get('cookie')!=proof['cookie'] or type(index) is not int or index<=0
            or action.get('ref')!=1 or action.get('bind')!=1):return False
    if proof['index'] is not None and index!=proof['index']:return False
    source=next((v for v in links if v.get('ifname')==proof['source']['ifname']),None)
    if source is None or signature(source)!=proof['source']:return False
    original=proof['target']
    matches=[v for v in links if v.get('ifname')==original['ifname'] or v.get('ifindex')==original['ifindex']]
    if matches:
        if len(matches)!=1 or signature(matches[0])!=original:return False
        valid=predicate(values,target)
    else:
        # A cookie intent without successful kernel readback cannot authorize
        # an unbound action after a crash during creation.
        valid=proof['index'] is not None and predicate(values,'*')
    if valid and capture and proof['index'] is None:proof['index']=index
    return valid


def require_capture(values,target,predicate,proof,links):
    if not qualified(values,target,predicate,proof,links,capture=True):
        raise Conflict('TC action ownership readback failed')
