"""Physical directory/overlays with synthetic TUN, libvirt and formatter.

This exercises never-booted define/retire through every resource controller.
It does not start QEMU or qualify NOS readiness/shutdown.
"""
from copy import deepcopy
from pathlib import Path
from xml.etree import ElementTree as ET

from dnlab_runtime.libvirt_install_files import InstallationFiles
from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
from dnlab_runtime.libvirt_session import DedicatedSession
from dnlab_runtime.libvirt_xml import render_domain
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_definition import VMDefinitionDriver
from dnlab_runtime.vm_definition_retirement import UnstartedDefinitionRetirement
from dnlab_runtime.vm_directories import VMDirectories
from dnlab_runtime.vm_directory_storage import DirectoryVMStorage
from dnlab_runtime.vm_directory_retirement import VMDirectoryRetirement
from dnlab_runtime.vm_overlay_files import directory_identity
from dnlab_runtime.vm_resources import VMResourcePreflight
from dnlab_runtime.vm_retired_resources import VMRetiredResources
from dnlab_runtime.vm_storage_retirement import VMStorageRetirement
from dnlab_runtime.vm_tap_local import LocalTapEndpoints, worker_command
from dnlab_runtime.vm_tap_retention import RetainedTapDevice
from dnlab_runtime.vm_tap_retirement import VMTapRetirement
from dnlab_runtime.vm_taps import VMTaps
from dnlab_runtime.vm_template import template_digest
from test_vm_overlay_files import files as overlay_fixture
from test_vm_tap_device import kernel
from test_vm_definition import definition, template, instance


def test_original_resources_compose_from_creation_through_directory_removal(definition,template,instance,tmp_path,kernel):
    import os
    fixture_root = tmp_path/'formatter';fixture_root.mkdir()
    fixture = overlay_fixture.__wrapped__(fixture_root)
    overlay,base_item,operation,formatter,_,_,base = next(fixture)
    devices = []
    try:
        template = deepcopy(template);instance = deepcopy(instance)
        template['assets']['base'].update(path=base.name,format='raw',size=base.stat().st_size,sha256=base_item['spec']['base_sha256'])
        root = tmp_path/'vm-root';root.mkdir(mode=0o755);root.chmod(0o755)
        instance['domain']['creator_operation_id'] = operation
        path = root/instance['domain']['uuid']
        instance.update(bundle_root=str(base.parent),overlays={'boot':str(path/'boot.qcow2')},console_path=str(path/'console.sock'))
        _,scope,state,factory = kernel
        proof = deepcopy(definition[4]);proof['daemon']['boot_id'] = scope['boot_id']
        session = DedicatedSession(definition[0].session.profile,lambda:deepcopy(proof))
        definitions = VMDefinitionDriver(overlay.journal,definition[0].connection,session,definition[0].preflight,no_domain_code=42)
        birth = {key:instance['domain'][key] for key in ('uuid','lab_id','node_id','host_id','generation','creator_operation_id','nonce')}
        birth['template_sha256'] = template_digest(template)
        definitions.prepare('create-resources',birth,render_domain(template,**instance))
        context = dict(host_id='worker',boot_id=scope['boot_id'],namespaces={name:dict(device=4,inode=i+1)
            for i,name in enumerate(('pid','mnt','net','user'))})
        agreement = dict(operation_id=operation,context=context,targets=['directory:'+str(path)],nonce='e'*32)
        window = ProvisioningWindow(agreement,lambda:deepcopy(agreement))
        parent_fd = os.open(root,os.O_RDONLY|os.O_DIRECTORY)
        try:parent = directory_identity(parent_fd)
        finally:os.close(parent_fd)
        def directory_preflight(value,*,mutating):
            result = dict(definition_sha256=value['definition_sha256'],birth_sha256=fingerprint(birth),
                parent_sha256=fingerprint(dict(root=str(root),identity=parent)),template_sha256=birth['template_sha256'],assets_verified=True)
            if mutating:result['exclusive_writer'] = True
            return result
        directories = VMDirectories(definitions,root=str(root),parent_identity=parent,
            files=InstallationFiles(journal=overlay.journal),window=window,read_context=lambda:deepcopy(context),preflight=directory_preflight)
        directories.prepare(operation);directory = directories.apply(operation)
        storage = DirectoryVMStorage(directories,operation,assets=lambda value:dict(template_sha256=birth['template_sha256'],assets_verified=True),
            writers=lambda value:[],binary=overlay.binary,runner_factory=overlay.runner_factory)
        storage.prepare(operation,template,str(base.parent));storage.apply(operation)
        def device(spec,namespace,record):
            result = factory(RetainedTapDevice);result.spec=deepcopy(spec);result.context=deepcopy(namespace);result.record=record
            devices.append(result);return result
        actor = {}
        endpoints = LocalTapEndpoints(overlay.journal,read_context=lambda:deepcopy(state['scope']),
            inventory=lambda:deepcopy(list(state['links'].values())),verify_worker=lambda reference,command:reference==actor['reference'] and command==actor['command'],
            device_factory=device,process_id=lambda:1234)
        def tap_preflight(value):
            return dict(definition_sha256=value['definition_sha256'],session_sha256=definitions.read(operation)['session_sha256'],
                context_sha256=fingerprint(scope),session_namespace_verified=True,guest_writers_absent=True)
        taps = VMTaps(definitions,endpoints=endpoints,read_context=lambda:deepcopy(state['scope']),preflight=tap_preflight)
        endpoints.attach(taps)
        requests = [dict(name=node.get('dev'),ifindex=12001+i,nonce=str(i+1)*32,vnet_header=True)
            for i,node in enumerate(ET.fromstring(definitions.read(operation)['xml']).findall('devices/interface/target'))]
        ready = taps.prepare(operation,scope,requests);command = worker_command(ready)
        reference = dict(token='a'*32,command_sha256=fingerprint(command),process_record=dict(
            boot_id=scope['boot_id'],pid=1234,start_ticks=12345,uid=0,gid=0,executable_sha256='b'*64,namespace_sha256='c'*64))
        actor.update(reference=reference,command=command);endpoints.bind(operation,reference);taps.apply(operation)
        definitions.preflight = VMResourcePreflight(storage,taps);definitions.apply(operation)
        domain = definitions.connection.lookupByUUIDString(birth['uuid'])
        domain.autostart=lambda:0;domain.hasManagedSaveImage=lambda flags:0;domain.snapshotNum=lambda flags:0;domain.checkpointCount=lambda:0
        def undefine(flags):definition[3]['domains'].pop(birth['uuid']);return 0
        domain.undefineFlags=undefine
        def retirement_preflight(value):
            return dict(definition_sha256=value.get('retirement',{}).get('definition_sha256',fingerprint(value)),
                session_sha256=value['session_sha256'],never_started=True,writers_absent=True,resources_unchanged=True)
        retirement = UnstartedDefinitionRetirement(definitions,preflight=retirement_preflight)
        retirement.prepare('remove-domain',operation);retired = retirement.apply('remove-domain')
        disk_agreement = dict(operation_id=operation,context=context,targets=['file:'+str(path/'boot.qcow2')],nonce='f'*32)
        disk_window = ProvisioningWindow(disk_agreement,lambda:deepcopy(disk_agreement))
        def disk_preflight(value):
            directories.observe(operation);taps.observe(operation)
            return dict(definition_sha256=directory['definition_sha256'],retirement_sha256=fingerprint(retired),endpoints_verified=True,directory_verified=True)
        disks = VMStorageRetirement(storage,retirement,window=disk_window,preflight=disk_preflight)
        disks.prepare('remove-disks',operation,'remove-domain');disks.apply('remove-disks')
        def tap_cleanup_preflight(value):
            assert disks.read('remove-disks')['phase'] == 'removed'
            for item in storage.read(operation)['items']:
                child=disks.files.read(item,operation);assert child['phase']=='removed';disks.files._layout(child)
            directories.observe(operation)
            return dict(definition_sha256=directory['definition_sha256'],retirement_sha256=fingerprint(retired),storage_verified=True,directory_verified=True)
        tap_cleanup = VMTapRetirement(taps,retirement,preflight=tap_cleanup_preflight)
        tap_cleanup.prepare('remove-taps',operation,'remove-domain');tap_cleanup.apply('remove-taps')
        remaining = VMRetiredResources(disks,tap_cleanup,storage_operation='remove-disks',tap_operation='remove-taps')
        cleanup = VMDirectoryRetirement(directories,retirement,window=window,preflight=remaining)
        cleanup.prepare('remove-directory',operation,'remove-domain',
            storage_retirement_sha256=remaining.storage_sha256,tap_retirement_sha256=remaining.tap_sha256)
        result = cleanup.apply('remove-directory')
        assert result['phase']=='removed' and not path.exists() and root.is_dir()
        assert state['links']=={} and all(device._fd is None for device in devices)
        assert cleanup.apply('remove-directory')==result
        assert directories.read(operation)==directory and storage.read(operation)['phase']=='ready'
        assert formatter['arms']==formatter['releases']==1
    finally:
        for device in devices:device.close()
        fixture.close()
