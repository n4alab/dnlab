"""Installation prerequisite provider; namespace/service observation is explicit.

Account rows and installation targets are verified by their ownership adapters,
not frozen as immutable prerequisites. No account/service command or namespace
lookup is supplied here. Tests use only a fixture root and injected observers.
"""
from copy import deepcopy
from pathlib import Path
import stat

from dnlab_runtime.libvirt_service_profile import render_profile,require_installable
from dnlab_runtime.libvirt_account_worker import validate_command
from dnlab_runtime.manifest import Conflict,fingerprint
from tools.libvirt_install_preflight import collect as collect_prerequisites
from tools.libvirt_account_tool_inventory import BINARIES,CONFIGS,HOOKS,collect as collect_account_tools
from tools.libvirt_install_parents import collect as collect_parents

ACCOUNT_INPUTS=BINARIES+CONFIGS+HOOKS


class InstallationSnapshot:
    def __init__(self,root,request,expected_packages,approved_account_inputs,*,namespaces,services):
        self.root=Path(root);self.request=deepcopy(request);self.profile=render_profile(**request)
        self.packages=deepcopy(expected_packages);self.approved=deepcopy(approved_account_inputs)
        self.namespaces,self.services=namespaces,services
        required=self.profile['package_request']['roots']
        if (not self.root.is_absolute() or not callable(namespaces) or not callable(services)
                or not isinstance(self.packages,dict) or any(self.packages.get(k)!=v for k,v in required.items())
                or set(self.approved)!=set(ACCOUNT_INPUTS)):
            raise Conflict('explicit complete installation prerequisite profiles required')

    @staticmethod
    def _regular(value,*,executable=False):
        if (not isinstance(value,dict) or value.get('status')!='present' or value.get('kind')!='regular'
                or not isinstance(value.get('metadata'),list) or len(value['metadata'])!=8
                or not isinstance(value.get('sha256'),str) or len(value['sha256'])!=64):
            raise Conflict('root-controlled prerequisite file proof required')
        mode=value['metadata'][2]
        if (value['metadata'][3]!=0 or not stat.S_ISREG(mode) or mode&0o022
                or executable and not mode&0o111):
            raise Conflict('prerequisite file ownership or permissions differ')

    @staticmethod
    def _namespaces(value):
        if (not isinstance(value,dict) or set(value)!={'pid','mnt','net','user'}
                or any(not isinstance(v,dict) or set(v)!={'device','inode'}
                    or any(type(n) is not int or n<=0 for n in v.values()) for v in value.values())):
            raise Conflict('complete installation namespace observation required')
        return deepcopy(value)

    def _services(self,value):
        units=set(self.profile['service_order']+self.profile['forbidden_vendor_activation'])
        if (not isinstance(value,dict) or set(value)!={'units','dedicated_uid','processes'}
                or value['dedicated_uid']!=self.profile['session']['uid'] or type(value['dedicated_uid']) is not int
                or value['processes']!=[] or not isinstance(value['units'],dict) or set(value['units'])!=units):
            raise Conflict('complete inactive installation service/process observation required')
        for state in value['units'].values():
            if (not isinstance(state,dict) or set(state)!={'active_state','job_id'}
                    or state['active_state']!='inactive' or type(state['job_id']) is not int or state['job_id']!=0):
                raise Conflict('installation service active, pending or ambiguous')
        return deepcopy(value)

    def __call__(self):
        spaces=self._namespaces(self.namespaces());services=self._services(self.services())
        parents=collect_parents(self.root,self.profile)
        host=collect_prerequisites(self.root,self.request,self.packages)['observed']
        tools=collect_account_tools(self.root)['observed']
        if host['boot_id']!=tools['boot_id']:raise Conflict('installation boot changed between inventories')
        for name,version in self.packages.items():
            package=host['packages'].get(name,{})
            if package.get('Version')!=version or package.get('Status')!='install ok installed':
                raise Conflict('original installed package differs: '+name)
        binaries={}
        for role,binary in self.profile['binaries'].items():
            value=host['paths'][binary['path']];self._regular(value,executable=True)
            if value['sha256']!=binary['sha256']:raise Conflict('original daemon executable differs: '+role)
            binaries[role]=value
        masks={}
        for unit in self.profile['forbidden_vendor_activation']:
            value=host['paths']['/etc/systemd/system/'+unit]
            if (value.get('kind')!='symlink' or value.get('target')!='/dev/null'
                    or value.get('metadata',[None]*4)[3]!=0):
                raise Conflict('original vendor administrative mask differs')
            masks[unit]=value
        account_inputs={path:tools['paths'][path] for path in ACCOUNT_INPUTS}
        if account_inputs!=self.approved:raise Conflict('reviewed account tool/config/hook inputs differ')
        for path in BINARIES+CONFIGS:self._regular(account_inputs[path],executable=path in BINARIES)
        # Hook contents are never executed or implicitly qualified by this provider.
        if any(account_inputs[path].get('status')!='absent' for path in HOOKS):
            raise Conflict('account hooks require separate qualification before provisioning')
        groups=[row for row in host['local_groups'] if row['name']=='kvm' or row['gid']==self.request['kvm_gid']]
        if groups!=[dict(name='kvm',gid=self.request['kvm_gid'])]:raise Conflict('original KVM group differs or is ambiguous')
        if self._namespaces(self.namespaces())!=spaces or self._services(self.services())!=services:
            raise Conflict('installation namespace/service observation changed')
        if collect_parents(self.root,self.profile)!=parents:
            raise Conflict('installation OS parent identity changed')
        return dict(context=dict(host_id=self.profile['session']['host_id'],boot_id=host['boot_id'],namespaces=spaces),
            prerequisites=dict(profile_sha256=self.profile['profile_sha256'],packages=host['packages'],
                dpkg_status_sha256=host['source_sha256']['var/lib/dpkg/status'],binaries=binaries,vendor_masks=masks,
                account_inputs=account_inputs,kvm_group=groups[0],services=services,os_parents=parents))

    def command_preflight(self,command,*,original):
        require_installable(self.profile)
        validate_command(command)
        current=self()
        if current!=original:raise Conflict('original complete host prerequisites changed')
        binary=command.get('binary')
        if (not isinstance(binary,dict) or set(binary)!={'path','sha256'}
                or binary['path'].lstrip('/') not in BINARIES
                or current['prerequisites']['account_inputs'][binary['path'].lstrip('/')]['sha256']!=binary['sha256']):
            raise Conflict('original qualified account executable differs')
        return dict(qualified=True,command_sha256=fingerprint(command),context_sha256=fingerprint(current['context']),
            inputs_sha256=fingerprint(current['prerequisites']))
