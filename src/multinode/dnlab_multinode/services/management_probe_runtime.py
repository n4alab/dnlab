"""Original SSH/stdin boundary for sealed infrastructure probe attempts."""
import json
from pathlib import Path
import shlex
import re
from .jumphost import _WORKER_BOOTSTRAP
from .paths import PATHS
from .runtime_operations import RuntimeOperationError,digest


def validate_birth(request,proof):
    if (not isinstance(proof,dict) or not re.fullmatch('[0-9a-f]{64}',proof.get('container_id',''))
            or not re.fullmatch('[0-9a-f]{32}',proof.get('nonce',''))
            or not isinstance(proof.get('namespace'),dict)
            or any(type(proof['namespace'].get(k)) is not int or proof['namespace'][k]<=0 for k in ('device','inode'))
            or not isinstance(proof.get('started_at'),str) or not proof['started_at']):
        raise RuntimeOperationError('complete original probe namespace/birth proof required')
    key=digest(['management-probe-v1',request]);nonce=proof['nonce']
    host_mac='02:'+':'.join(digest([key,nonce])[i:i+2] for i in range(0,10,2))
    for side,name,mac in (('host','dmp'+key[:12],host_mac),('peer','probe0',request['identity']['mac'])):
        row=proof.get(side)
        if (not isinstance(row,dict) or row.get('ifname')!=name or row.get('address')!=mac
                or row.get('ifalias')!='dnlab-management-probe:'+nonce or row.get('kind')!='veth'
                or any(type(row.get(k)) is not int or row[k]<=0 for k in ('ifindex','link_index'))):
            raise RuntimeOperationError('qualified probe endpoint identity required')
    if proof['host']['link_index']!=proof['peer']['ifindex'] or proof['peer']['link_index']!=proof['host']['ifindex']:
        raise RuntimeOperationError('probe endpoint peer proof differs')


def validate_execution(request,birth,proof):
    if (not isinstance(proof,dict) or set(proof)!={'id','nonce','container_id','command_sha256'}
            or not re.fullmatch('[0-9a-f]{64}',proof.get('id','')) or not re.fullmatch('[0-9a-f]{64}',proof.get('command_sha256',''))
            or proof.get('container_id')!=birth['container_id']
            or proof.get('nonce')!=digest(['probe-exec-v1',digest(['management-probe-v1',request]),birth['nonce']])[:32]):
        raise RuntimeOperationError('complete original packet exec proof required')


def validate_packets(request,result):
    from .management_packet_receipt import validate
    try:validate(request['packet_profile'],result)
    except (ValueError,KeyError,TypeError,AttributeError) as error:
        raise RuntimeOperationError('original packet acknowledgement differs') from error


def packet_program():
    directory=Path(__file__).parent
    source="v4={'__name__':'_v4'}\nexec("+repr((directory/'management_dhcpv4_probe.py').read_text())+",v4)\n"
    source+="v6={'__name__':'_v6'}\nexec("+repr((directory/'management_dhcpv6_probe.py').read_text())+",v6)\n"
    source+="DHCPv4Probe=v4['Probe']\nrun_v6=v6['run']\n"
    source+="routing={'__name__':'_routing'}\nexec("+repr((directory/'management_routing_probe.py').read_text())+",routing)\nrun_routing=routing['run']\n"
    source+="dnswire={'__name__':'_dnswire'}\nexec("+repr((directory/'management_dns_probe.py').read_text())+",dnswire)\n"
    source+="dnsclient={'__name__':'_dnsclient','Endpoint':routing['Endpoint'],'checksum':routing['checksum'],'pseudo':routing['pseudo'],'ip_packet':routing['ip_packet'],'wire_name':dnswire['wire_name'],'validate_response':dnswire['validate_response'],'ProbeError':dnswire['ProbeError']}\nexec("+repr((directory/'management_dns_client_probe.py').read_text())+",dnsclient)\nrun_dns_client=dnsclient['run']\n"
    return source+(directory/'management_packet_probe.py').read_text().rsplit("if __name__=='__main__':",1)[0]


def program():
    directory=Path(__file__).parent
    base="jump={'__name__':'_jump'}\nexec("+repr((directory/'jumphost_host.py').read_text())+",jump)\n"
    for name,value in (('BaseWorker',"jump['Worker']"),('JumphostError',"jump['JumphostError']"),
        ('canonical',"jump['canonical']"),('digest',"jump['digest']"),('signature',"jump['signature']"),
        ('MUTATE_PROGRAM',"jump['MUTATE_PROGRAM']"),('DockerExecHTTP',"jump['DockerExecHTTP']")):
        base+=name+'='+value+'\n'
    base+="receipt={'__name__':'_receipt'}\nexec("+repr((directory/'management_packet_receipt.py').read_text())+",receipt)\nvalidate_packet_result=receipt['validate']\nvalidate_routing_profile=receipt['routing_profile']\nvalidate_dns_profile=receipt['dns_profile']\n"
    base+="owned={'__name__':'_owned','JumphostError':jump['JumphostError'],'canonical':jump['canonical'],'digest':jump['digest'],'validate_packet_result':receipt['validate'],'validate_progress':receipt['validate_progress'],'expected_progress':receipt['expected_progress']}\nexec("+repr((directory/'management_probe_exec.py').read_text())+",owned)\nExecution=owned['Execution']\nprepare_assets=owned['prepare_assets']\nprobe_binds=owned['probe_binds']\n"
    base+='PACKET_SOURCE='+repr(packet_program())+'\n'
    return base+(directory/'management_probe_host.py').read_text()


def invoke(client,request,action,*,expected_birth=None,expected_execution=None):
    if action not in ('preflight','ensure','inspect','prepare-packets','start-packets','cleanup','verify-cleaned','packets'):raise RuntimeOperationError('unsupported probe attempt action')
    if expected_birth is not None:validate_birth(request,expected_birth)
    if action in ('prepare-packets','start-packets','packets') and expected_birth is None:raise RuntimeOperationError('expected original probe birth required')
    if action in ('start-packets','packets') and expected_execution is None:raise RuntimeOperationError('expected original packet exec required')
    payload={'source':program(),'request':{'action':action,'request':request,'directories':{
        'directory':PATHS.management_probe_journal_dir,'management_directory':PATHS.management_journal_dir}}}
    if expected_birth is not None:payload['request']['expected_birth']=expected_birth
    if expected_execution is not None:payload['request']['expected_execution']=expected_execution
    try:value=json.loads(client.run_input(shlex.join(['python3','-c',_WORKER_BOOTSTRAP]),json.dumps(payload),timeout=180))
    except Exception as error:raise RuntimeOperationError('probe attempt rejected or uncertain; original journal retained') from error
    expected={'preflight':'preflight','ensure':'active','inspect':'active','prepare-packets':'active','start-packets':'active','cleanup':'cleaned','verify-cleaned':'cleaned','packets':'active'}[action]
    if (not isinstance(value,dict) or value.get('request_fingerprint')!=digest(request) or value.get('phase')!=expected
            or action in ('cleanup','verify-cleaned') and value.get('cleanup_verified') is not True):
        raise RuntimeOperationError('probe attempt acknowledgement differs')
    if action in ('ensure','inspect','prepare-packets','start-packets','packets'):validate_birth(request,value.get('resource_proof'))
    if expected_birth is not None and value.get('resource_proof')!=expected_birth:
        raise RuntimeOperationError('expected original probe birth differs')
    if expected_execution is not None and value.get('execution')!=expected_execution:raise RuntimeOperationError('expected original packet exec differs')
    if action=='prepare-packets':validate_execution(request,value.get('resource_proof'),value.get('execution'))
    if action=='packets':
        if value.get('execution_status',{}).get('exit_verified') is not True or value['execution_status'].get('exit_code')!=0:
            raise RuntimeOperationError('packet exec exit not verified')
        validate_packets(request,value.get('packet_result'))
    return value
