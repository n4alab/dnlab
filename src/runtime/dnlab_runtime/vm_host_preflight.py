"""Readonly host prerequisites shared by VM directory and TAP controllers.

Providers retain the original session, store, storage-parent and gate leases.
This adapter does not discover owners, open devices, allocate resources or
turn saved reports into live capabilities. Child controllers own mutations.
"""
from copy import deepcopy

from .libvirt_xml import absolute
from .manifest import fingerprint
from .vm_template import digest, fields, require, template_digest, validate_template

UNITS = ('dnlab-virtlogd.service', 'dnlab-virtlockd.service', 'dnlab-libvirtd.service')


class VMHostPreflight:
    def __init__(self, definitions, *, context, read_context, root, parent_identity,
                 observe_parent, assets, template, bundle_root, services, writers,
                 scope_sha256, verify_scope):
        fields(context, ('host_id', 'boot_id', 'namespaces'), 'VM host context')
        fields(context['namespaces'], ('pid', 'mnt', 'net', 'user'), 'VM host namespaces')
        for value in context['namespaces'].values():
            fields(value, ('device', 'inode'), 'VM host namespace')
            require(all(type(item) is int and item > 0 for item in value.values()),
                    'qualified VM host namespaces required')
        fields(parent_identity, ('device', 'inode', 'uid', 'gid', 'mode'), 'VM administrative parent')
        require(all(type(item) is int and item >= 0 for item in parent_identity.values())
                and parent_identity['inode'] > 0 and parent_identity['uid'] == parent_identity['gid'] == 0
                and parent_identity['mode'] == 0o755, 'qualified root:root0755 VM parent required')
        require(all(callable(fn) for fn in (read_context, observe_parent, services, writers, verify_scope))
                and callable(getattr(assets, 'verify', None)) and digest(scope_sha256),
                'live original VM prerequisite providers required')
        self.definitions = definitions
        self._definitions = definitions
        self.context, self.parent = deepcopy(context), deepcopy(parent_identity)
        self.root, self.bundle_root = absolute(root), absolute(bundle_root)
        self.template, self.scope_sha256 = validate_template(template), scope_sha256
        self.read_context, self.observe_parent = read_context, observe_parent
        self.assets, self.services, self.writers, self.verify_scope = assets, services, writers, verify_scope
        self._providers = (read_context, observe_parent, assets, services, writers, verify_scope)
        self._configuration_sha256 = self._configuration()

    def _configuration(self):
        return fingerprint(dict(context=self.context, parent=self.parent, root=self.root,
            template=self.template, bundle_root=self.bundle_root, scope_sha256=self.scope_sha256))

    def _scope(self):
        current = (self.read_context, self.observe_parent, self.assets, self.services, self.writers, self.verify_scope)
        require(self.definitions is self._definitions
                and all(first is second for first, second in zip(current, self._providers))
                and self._configuration() == self._configuration_sha256,
                'original VM host prerequisite capabilities changed')
        require(self.verify_scope() == self.scope_sha256 and self.read_context() == self.context,
                'original VM gate scope or host context changed')
        require(self.observe_parent() == self.parent, 'original VM administrative parent changed')

    def _source(self, value):
        self._scope()
        definition = self.definitions.read(value['id'])
        require(definition['birth'] == value['birth']
                and definition['request_fingerprint'] == value['definition_sha256']
                and value['birth']['creator_operation_id'] == value['id']
                and value['birth']['host_id'] == self.context['host_id']
                and value['birth']['template_sha256'] == template_digest(self.template),
                'original VM prerequisite owner or template differs')
        self.definitions._session(definition)
        session = self.definitions.session.profile
        require(session['host_id'] == self.context['host_id']
                and self.definitions.session.proof()['daemon']['boot_id'] == self.context['boot_id'],
                'original dedicated session host/boot differs')
        processes = self.services()
        fields(processes, UNITS, 'original dedicated service census')
        pids = set()
        for process in processes.values():
            require(isinstance(process, dict) and {'pid', 'start_ticks', 'pidfd_alive', 'boot_id',
                    'namespaces', 'uids', 'gids'} <= process.keys(), 'complete original VM service observation required')
            require(type(process['pid']) is int and process['pid'] > 0 and process['pid'] not in pids
                    and type(process['start_ticks']) is int and process['start_ticks'] > 0
                    and process['pidfd_alive'] is True and process['boot_id'] == self.context['boot_id']
                    and process['namespaces'] == self.context['namespaces']
                    and process['uids'] == [session['uid']] * 4 and process['gids'] == [session['gid']] * 4,
                    'original VM service generation or namespace differs')
            pids.add(process['pid'])
        require(self.assets.verify(birth=deepcopy(value['birth']), template=deepcopy(self.template),
                bundle_root=self.bundle_root) == dict(template_sha256=value['birth']['template_sha256'],
                                                     assets_verified=True),
                'original published VM assets differ')
        self._scope()
        require(self.definitions.read(value['id']) == definition, 'VM changed during host preflight')
        return definition

    def directory(self, value, *, mutating):
        require(type(mutating) is bool, 'explicit VM directory preflight mode required')
        definition = self._source(value)
        require(value['root'] == self.root and value['parent'] == self.parent,
                'original VM directory parent binding differs')
        result = dict(definition_sha256=definition['request_fingerprint'],
            birth_sha256=fingerprint(value['birth']), parent_sha256=fingerprint(dict(root=self.root, identity=self.parent)),
            template_sha256=value['birth']['template_sha256'], assets_verified=True)
        if mutating:
            require(self.writers(deepcopy(value)) == [], 'VM directory allocation has a guest writer')
            result['exclusive_writer'] = True
        self._scope()
        require(self.definitions.read(value['id']) == definition, 'VM changed before directory admission')
        return result

    def taps(self, value):
        definition = self._source(value)
        require(value['context'] == dict(boot_id=self.context['boot_id'], **self.context['namespaces']['net']),
                'original VM TAP network namespace differs')
        writers = self.writers(deepcopy(value))
        require(type(writers) is list and len(writers) <= 1, 'complete VM guest writer census required')
        if writers:
            require(writers == [definition.get('boot', {}).get('process_record')],
                    'VM TAP writer is not the original QEMU generation')
        self._scope()
        require(self.definitions.read(value['id']) == definition, 'VM changed before TAP admission')
        return dict(definition_sha256=definition['request_fingerprint'], session_sha256=definition['session_sha256'],
            context_sha256=fingerprint(value['context']), session_namespace_verified=True,
            guest_writers_absent=not bool(writers))
