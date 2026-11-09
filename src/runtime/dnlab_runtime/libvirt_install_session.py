"""Explicit assembly of the session installer, without automatic host actions.

Construction only creates journal tables. Prepare observes the supplied original
snapshot and dependencies; apply remains a separate explicit operation. No default
NSS provider, worker launcher, provisioning window or directory adoption exists.
"""
from copy import deepcopy

from .libvirt_account_commands import AccountCommandHelper, command_plan
from .libvirt_account_identity import LocalAccountIdentity
from .libvirt_install import SessionInstaller, targets
from .libvirt_install_adapter import ProvisioningAdapter
from .libvirt_install_dependencies import InstallationDirectoryDependencies
from .libvirt_install_files import InstallationFiles
from .libvirt_provisioning import InstallationAccounts, account_request
from .libvirt_service_profile import render_profile, require_installable
from .manifest import Conflict, fingerprint


class SessionProvisioning:
    def __init__(self, journal, *, root, request, snapshot_provider, original_snapshot,
                 window, runner, nss_query, directory_receipts):
        profile = render_profile(**request)
        require_installable(profile)
        original = deepcopy(original_snapshot)
        if (not isinstance(original, dict) or set(original) != {'context', 'prerequisites'}
                or not isinstance(original['prerequisites'], dict)
                or original['prerequisites'].get('profile_sha256') != profile['profile_sha256']
                or not callable(snapshot_provider)
                or not callable(getattr(snapshot_provider, 'command_preflight', None))
                or window.receipt['context'] != original['context']
                or set(window.receipt['targets']) != {item['key'] for item in targets(profile)}
                or 'provisioning_window_sha256' in original['prerequisites']
                or not isinstance(directory_receipts, dict)):
            raise Conflict('original complete session snapshot and matching window required')
        specs = {item['path']:item for item in targets(profile) if item['kind'] == 'directory'}
        if set(directory_receipts) - set(specs):
            raise Conflict('only explicit profile directory dependencies allowed')
        selected = [specs[path] for path in directory_receipts]
        reader = InstallationDirectoryDependencies(root, selected) if selected else None
        inputs = original['prerequisites'].get('account_inputs', {})
        binaries = {}
        for role in ('useradd', 'groupadd'):
            path = 'usr/sbin/' + role
            observed = inputs.get(path, {})
            if (observed.get('status') != 'present' or observed.get('kind') != 'regular'
                    or not isinstance(observed.get('sha256'), str) or len(observed['sha256']) != 64):
                raise Conflict('original account executable profile required')
            binaries[role] = dict(path='/' + path, sha256=observed['sha256'])

        self.request = deepcopy(request)
        self.dependencies = deepcopy(directory_receipts)
        self.window = window
        self.original = original

        def snapshot():
            current = snapshot_provider()
            if current != original:raise Conflict('original installation snapshot changed')
            current = deepcopy(current)
            current['prerequisites']['provisioning_window_sha256'] = window.sha256
            return current

        def dependency(spec):
            if reader is None:raise Conflict('no directory dependency selected')
            return reader(spec)

        identity = LocalAccountIdentity(root, nss_query=nss_query)
        def command_preflight(command):
            # Read the committed installer intent, not the caller's stale item.
            # Account observations use committed worker evidence and never call
            # this helper preflight recursively.
            with journal.execution_lock:
                value=self.installer.read(window.receipt['operation_id'])
                matches=[account_request(item,value['id']) for item in value['items']
                    if item['spec']['kind'] in ('group','account')
                    and fingerprint(account_request(item,value['id']))==command.get('request_sha256')]
                if len(matches)!=1 or command!=command_plan(matches[0],binaries):
                    raise Conflict('account command is not bound to original installation item')
                result=snapshot_provider.command_preflight(command,original=original)
                self.installer._observe(value,account_request_sha256=command['request_sha256'])
                return result
        self.helper = AccountCommandHelper(journal, binaries=binaries, runner=runner, inspect=identity,
            preflight=command_preflight)
        self.adapter = ProvisioningAdapter(window=window, accounts=InstallationAccounts(journal, self.helper),
            files=InstallationFiles(root, journal=journal), snapshot=snapshot, directory_dependency=dependency)
        self.installer = SessionInstaller(journal, self.adapter)

    def prepare(self):
        prerequisites = deepcopy(self.original['prerequisites'])
        prerequisites['provisioning_window_sha256'] = self.window.sha256
        return self.installer.prepare(self.window.receipt['operation_id'], self.request,
            context=self.original['context'], prerequisites=prerequisites,
            existing_directories=self.dependencies)

    def apply(self):
        return self.installer.apply(self.window.receipt['operation_id'])
