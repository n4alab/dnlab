"""Coordinate complete RealNet preflight and durable per-host cleanup."""
import hashlib
import json
from pathlib import Path
import shlex

from .realnet_cleanup_host import OwnershipError,validate

ATTACHMENT_SOURCE=Path(__file__).with_name('realnet_attachment_host.py').read_text()
PROGRAM="_attachment_scope={'__name__':'dnlab_attachment_worker'}\nexec("+repr(ATTACHMENT_SOURCE)+",_attachment_scope)\n_InfrastructureAttachments=_attachment_scope['InfrastructureAttachments']\n"+Path(__file__).with_name('realnet_cleanup_host.py').read_text()


def scope(lab_name,realnet_name,host):
    return hashlib.sha256(json.dumps(['realnet-cleanup-v1',lab_name,realnet_name,host],separators=(',',':')).encode()).hexdigest()


def plans(lab_name,clients,states):
    result=[]
    for state in states:
        proof=state.resource_identities.get('realnet_cleanup_v1')
        required=set(state.hosts)
        if state.router_container:required.add('master')
        if not isinstance(proof,dict) or set(proof)!=required:
            raise OwnershipError('RealNet legacy resources require explicit qualification')
        for host in sorted(required):
            if host not in clients:raise OwnershipError('RealNet preflight host unavailable: '+host)
            plan=proof[host];validate(plan)
            if plan['scope']!=scope(lab_name,state.name,host):raise OwnershipError('RealNet ownership scope differs')
            expected={state.bridge,*state.vxlan_ifaces.get(host,[])}
            if host=='master' and state.router_veth:expected.add(state.router_veth)
            if set(plan['links'])!=expected:raise OwnershipError('RealNet persisted link inventory differs')
            if plan['links'][state.bridge]['kind']!='bridge':raise OwnershipError('RealNet bridge kind differs')
            if any(plan['links'][name]['kind']!='vxlan' for name in state.vxlan_ifaces.get(host,[])):
                raise OwnershipError('RealNet VXLAN kind differs')
            if host=='master' and state.router_veth and plan['links'][state.router_veth]['kind']!='veth':
                raise OwnershipError('RealNet router endpoint kind differs')
            router=plan['router']
            if host=='master' and state.router_container:
                if router is None or router['name']!=state.router_container:raise OwnershipError('RealNet router proof missing or mismatched')
            elif router is not None:raise OwnershipError('unexpected RealNet router ownership')
            result.append((state,host,plan))
    return result


def invoke(client,action,plan):
    command=shlex.join(['python3','-c',PROGRAM,action,json.dumps(plan,sort_keys=True,separators=(',',':'))])
    try:value=json.loads(client.run(command))
    except Exception:raise OwnershipError('RealNet '+action+' failed; recovery required') from None
    expected={'preflight':'verified','detach_attachments':'detached'}.get(action,'cleaned')
    if value.get('status')!=expected:raise OwnershipError('invalid RealNet cleanup acknowledgement')
    return value


def preflight_realnets(lab_name,clients,states):
    work=plans(lab_name,clients,states)
    # Complete every read-only preflight before the first host journal/mutation.
    for _,host,plan in work:invoke(clients[host],'preflight',plan)
    return work


def detach_realnet_attachments(lab_name,clients,states,*,checkpoint=None,runtime_links=None):
    work=preflight_realnets(lab_name,clients,states)
    for state,host,plan in work:
        operation=state.resource_identities.setdefault('realnet_attachment_teardown',{'phase':'cleanup_pending','hosts':{}})
        operation['phase']='cleanup_pending';operation['hosts'][host]='cleanup_pending'
        if checkpoint:checkpoint()
        receipt=invoke(clients[host],'detach_attachments',plan)
        operation.setdefault('receipts',{})[host]=receipt
        if runtime_links is not None:
            from .realnet_attachment_host import Worker as AttachmentWorker
            for link in runtime_links:
                if link.link_type!='real_net' or link.host_a!=host or link.endpoint_b.get('real_net')!=state.name:continue
                proof=link.resource_identities.get('realnet_attachment_v1')
                if not proof:continue
                owner=AttachmentWorker(proof);ack=receipt.get('attempts',{}).get(owner.key)
                if ack and ack.get('phase')=='cleaned' and ack.get('proof_hash')==owner.proof_hash(proof,link.warm_a):
                    link.resource_identities['realnet_attachment_operation']={'phase':'cleaned','key':owner.key,'attempt':ack['attempt']}
                    link.state='down';link.last_error=''
        operation['hosts'][host]='detached'
        operation['phase']='detached' if all(operation['hosts'].get(h)=='detached' for h in state.hosts) else 'cleanup_pending'
        if checkpoint:checkpoint()
    return work


def destroy_realnets(lab_name,clients,states,*,checkpoint=None):
    work=detach_realnet_attachments(lab_name,clients,states,checkpoint=checkpoint)
    for state,host,plan in work:
        operation=state.resource_identities.setdefault('realnet_cleanup_operation',{'phase':'cleanup_pending','hosts':{}})
        operation['phase']='cleanup_pending';operation['hosts'][host]='cleanup_pending'
        if checkpoint:checkpoint()
        try:
            invoke(clients[host],'cleanup',plan)
        except Exception:
            if checkpoint:checkpoint()
            raise
        operation['hosts'][host]='cleaned'
        operation['phase']='cleaned' if all(operation['hosts'].get(name)=='cleaned' for name in state.resource_identities['realnet_cleanup_v1']) else 'cleanup_pending'
        if checkpoint:checkpoint()
    from .realnet_vni import release_realnets
    release_realnets(lab_name,clients,states)


def verify_realnets_cleaned(lab_name,clients,states):
    for _,host,plan in plans(lab_name,clients,states):
        invoke(clients[host],'verify_cleaned',plan)
