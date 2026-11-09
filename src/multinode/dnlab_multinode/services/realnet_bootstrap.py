"""Send the owned router bootstrap through the existing local SSH boundary."""
import copy
import json
from pathlib import Path
import shlex

from .realnet_cleanup import scope,PROGRAM as CLEANUP_PROGRAM
from .realnet_cleanup_host import OwnershipError

DIRECTORY=Path(__file__).parent
PROGRAM=CLEANUP_PROGRAM.rsplit("if __name__=='__main__':main()",1)[0]+'\n'+(DIRECTORY/'realnet_bootstrap_host.py').read_text().replace('from .realnet_cleanup_host import OwnershipError,Worker,context,digest,link_identity\n','')


def bootstrap_router(topo,rn,state,master,image,network):
    proof=state.resource_identities.get('realnet_cleanup_v1',{}).get('master')
    if not isinstance(proof,dict) or proof.get('scope')!=scope(topo.name,rn.name,'master'):
        raise OwnershipError('RealNet infrastructure requires persistent ownership proof before router bootstrap')
    infrastructure=copy.deepcopy(proof)
    infrastructure['links'].pop(state.router_veth,None)
    infrastructure['router']=None
    request={'infrastructure':infrastructure,'bridge':state.bridge,'endpoint':state.router_veth,
             'container':state.router_container,'image':image,'network':network,
             'environment':{'REALNET_IPV4':rn.ipv4,'NAT_ENABLED':'false' if rn.bgp else 'true',
                            'BGP_ENABLED':'true' if rn.bgp else 'false','BGP_ROUTER_ID':rn.bgp_router_ip},
             'ip':rn.bgp_router_ip if rn.bgp else None}
    try:value=json.loads(master.run(shlex.join(['python3','-c',PROGRAM,json.dumps(request,sort_keys=True,separators=(',',':'))])))
    except Exception:raise OwnershipError('RealNet router bootstrap failed; journalled recovery required') from None
    if value.get('phase')!='active':raise OwnershipError('RealNet bootstrap acknowledgement is incomplete')
    proof['links'][state.router_veth]=value['host_link'];proof['router']=value['router']
    state.resource_identities['realnet_router_bootstrap_v1']=value
    return value
