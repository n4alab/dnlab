"""Bounded readonly unit-property transport; explicit original file observer.

No default subprocess, systemd connection, file read or host discovery occurs.
Inactive/transitional states are observations, not readiness acknowledgements.
"""
from copy import deepcopy
import re

from dnlab_runtime.manifest import Conflict, fingerprint

PROPERTIES=('Id','LoadState','ActiveState','SubState','MainPID','InvocationID',
            'FragmentPath','DropInPaths','Restart','Job')
ENVIRONMENT=dict(PATH='/usr/sbin:/usr/bin:/sbin:/bin',HOME='/',LC_ALL='C',LANG='C',
    SYSTEMD_PAGER='cat',SYSTEMD_COLORS='0',SYSTEMD_LOG_COLOR='0')


def observe_service_files(files,installation):
    """Observe each file through its original creator, including a bound revision.

    A revised descriptor must come from ConfigurationRevision.effective(), whose
    adapter qualifies the complete lineage and backup. Never infer a revision
    from a file name or substitute the base installation ID for its creator.
    """
    result={};revision=installation.get('configuration_revision')
    for item in installation['items']:
        spec=item['spec']
        if spec['kind']!='file':continue
        creator=installation['id']
        if revision is not None and spec['path']=='/etc/systemd/system/dnlab-libvirtd.service':
            creator=revision['operation_id']
        expected=dict(key='file:'+spec['path'],kind='file',path=spec['path'],**installation['profile']['files'][spec['path']])
        if (item['phase']!='created' or spec!=expected or item['proof']['intent_id']!=creator
                or item['proof']['spec_sha256']!=fingerprint(spec)):
            raise Conflict('original service file creator or specification differs')
        proof=files.observe(deepcopy(item),creator)
        if proof!=item['proof']:raise Conflict('original service file birth differs')
        result[spec['path']]=proof
    if set(result)!=set(installation['profile']['files']):raise Conflict('installed service file inventory incomplete')
    return result


def parse(raw,names):
    if not isinstance(raw,str) or not raw or len(raw.encode())>65536:
        raise Conflict('bounded complete service unit response required')
    result={}
    for block in raw.strip().split('\n\n'):
        values={}
        for line in block.splitlines():
            key,sep,value=line.partition('=')
            if not sep or key not in PROPERTIES or key in values:
                raise Conflict('service property malformed, duplicate or unexpected')
            values[key]=value
        if set(values)!=set(PROPERTIES) or values['Id'] not in names or values['Id'] in result:
            raise Conflict('service unit inventory missing, foreign or duplicated')
        pid=values['MainPID'];job=values['Job'];invocation=values['InvocationID']
        if (not re.fullmatch('0|[1-9][0-9]{0,9}',pid) or int(pid)>=2**31
                or job and (not re.fullmatch('[1-9][0-9]{0,9}',job) or int(job)>=2**32)
                or invocation and not re.fullmatch('[0-9a-f]{32}',invocation)
                or values['LoadState'] not in ('loaded','masked','not-found')
                or not values['ActiveState'] or not values['SubState']):
            raise Conflict('service state or generation properties malformed')
        result[values['Id']]=dict(values,MainPID=int(pid),Job=int(job) if job else 0)
    if set(result)!=set(names):raise Conflict('service unit inventory incomplete')
    return result


class ServiceUnitReader:
    def __init__(self,installation,*,query,files):
        if not callable(query) or not callable(files):raise Conflict('explicit service query and file observers required')
        self.installation=deepcopy(installation);self.query,self.files=query,files
        self.expected={item['spec']['path']:item['proof'] for item in installation['items'] if item['spec']['kind']=='file'}
        self.diagnostics=[]

    def __call__(self):
        before=self.files()
        if before!=self.expected:raise Conflict('original installed unit/configuration files differ')
        profile=self.installation['profile'];names=profile['service_order']
        argv=['/usr/bin/systemctl','show','--all','--no-pager','--property='+','.join(PROPERTIES),'--',*names]
        diagnostic=dict(argv=argv,status='requested');self.diagnostics.append(diagnostic)
        try:response=self.query(argv,env=deepcopy(ENVIRONMENT),timeout=5)
        except Exception as error:
            diagnostic.update(status='failed',error=dict(type=type(error).__name__,message=str(error)))
            raise
        diagnostic.update(status='responded',response=deepcopy(response))
        if (not isinstance(response,dict) or set(response)!={'exit_code','stdout','stderr'}
                or type(response['exit_code']) is not int or response['exit_code']!=0
                or not isinstance(response['stdout'],str) or not isinstance(response['stderr'],str)
                or response['stderr']!=''):
            raise Conflict('readonly service query failed or returned unqualified diagnostics')
        rows=parse(response['stdout'],names);result={}
        for name,values in rows.items():
            path='/etc/systemd/system/'+name
            if values['FragmentPath'] not in ('',path) or values['DropInPaths']:
                raise Conflict('service fragment replaced or unqualified drop-ins present')
            result[name]=dict(load_state=values['LoadState'],sub_state=values['SubState'],
                unit=dict(name=name,fragment_path=values['FragmentPath'],
                    fragment_sha256=profile['files'][path]['sha256'],dropins=[],restart=values['Restart'],
                    active=values['ActiveState'],job=values['Job'],pid=values['MainPID'],invocation_id=values['InvocationID']),
                files=deepcopy(before))
        if self.files()!=before:raise Conflict('installed service files changed during query')
        diagnostic.update(status='collected',observation=deepcopy(result))
        return result
