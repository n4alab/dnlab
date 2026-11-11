"""Run one explicitly selected activation of the dedicated master session."""

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys

RUNTIME = Path('/opt/dnlab/src/runtime')
OUTPUT_PARENT = Path('/var/lib/dnlab-runtime-spikes')
INPUTS = (
    'installed.json', 'journal-reference.json', 'journal-binding.json', 'postboot.json',
    'prepared-reference.json', 'effective-source.json', 'unit-window.json', 'unit-reference.json',
    'activation-source.json', 'activation-window.json', 'expected-packages.json', 'approved-account-inputs.json',
    'worker-profile.json', 'bus-inventory.json', 'activation-binaries.json',
)
REVISED_INPUTS = tuple(name for name in INPUTS if name not in ('effective-source.json', 'unit-window.json', 'unit-reference.json')) + (
    'completed-revision.json',)


def sha(data):
    return hashlib.sha256(data).hexdigest()


def runtime_sources():
    files = {}
    for folder in ('dnlab_runtime', 'tools'):
        for path in (RUNTIME / folder).glob('*.py'):
            if path.is_symlink():
                raise ValueError('activation recipe source symlink refused')
            files[str(path.relative_to(RUNTIME))] = sha(path.read_bytes())
    if not files or sha(Path(__file__).read_bytes()) != files.get('tools/libvirt_activation_host.py'):
        raise ValueError('original runtime activation entry required')
    return files


def prepare_recipe(recipe, inputs):
    """Freeze explicit reviewed inputs without reading host state."""
    if set(inputs) not in (set(INPUTS), set(REVISED_INPUTS)):
        raise ValueError('complete activation recipe inputs required')
    sources = runtime_sources()
    recipe.mkdir(mode=0o700)
    digests = {}
    for name in sorted(inputs):
        raw = json.dumps(inputs[name], sort_keys=True).encode() + b'\n'
        (recipe / name).write_bytes(raw)
        digests[name] = sha(raw)
    receipt = dict(kind='libvirt-native-activation-v1', runtime_root=str(RUNTIME),
                   source_sha256=sources, input_sha256=digests)
    (recipe / 'receipt.json').write_text(json.dumps(receipt, sort_keys=True) + '\n')
    return receipt


def verify_recipe(recipe):
    files = runtime_sources()
    receipt = json.loads((recipe / 'receipt.json').read_bytes())
    if (set(receipt) != {'kind', 'runtime_root', 'source_sha256', 'input_sha256'}
            or receipt['kind'] != 'libvirt-native-activation-v1' or receipt['runtime_root'] != str(RUNTIME)
            or receipt['source_sha256'] != files
            or set(receipt['input_sha256']) not in (set(INPUTS), set(REVISED_INPUTS))):
        raise ValueError('frozen native activation recipe differs')
    inputs = {}
    for name in receipt['input_sha256']:
        raw = (recipe / name).read_bytes()
        if sha(raw) != receipt['input_sha256'][name]:
            raise ValueError('native activation input differs: ' + name)
        inputs[name] = json.loads(raw)
    source_inventory = json.dumps(files, sort_keys=True, separators=(',', ':')).encode()
    return inputs, sha(source_inventory)


def activate(inputs, sources_sha256, *, verify, persist):
    from dnlab_runtime.libvirt_account_identity import host_query
    from dnlab_runtime.libvirt_account_runner import open_resource, source_proof
    from dnlab_runtime.libvirt_account_worker import binary_proof
    from dnlab_runtime.libvirt_activation import steps
    from dnlab_runtime.libvirt_activation_lineage import ActivationLineage
    from dnlab_runtime.libvirt_configuration import project_revision
    from dnlab_runtime.libvirt_provisioning import ProvisioningWindow
    from tools.libvirt_bus_inventory_host import host_context
    from tools.libvirt_native_activation_inputs import ActivationHostInputs, open_lineage_activation
    from tools.libvirt_postboot_directories import PostBootDirectoryAssembly
    from tools.libvirt_postboot_journal import open_postboot_journal
    from tools.libvirt_postboot_unit_revision import PostBootUnitRevision
    from tools.libvirt_service_units import PROPERTIES

    installed = inputs['installed.json']
    original = inputs['journal-reference.json']
    postboot = inputs['postboot.json']
    agreement = inputs['activation-window.json']
    source = inputs['activation-source.json']
    expected = source['context']
    bus = inputs['bus-inventory.json']
    if (expected != agreement['context'] or expected != bus['context']
            or agreement['targets'] != [step['key'] for step in steps(source['profile'])]):
        raise ValueError('original activation context or targets differ')
    binaries = inputs['activation-binaries.json']
    paths = dict(systemctl='/usr/bin/systemctl', virsh='/usr/bin/virsh', python='/usr/bin/python3.13',
                 reload=str(RUNTIME / 'tools/libvirt_activation_worker_main.py'),
                 start=str(RUNTIME / 'tools/libvirt_bus_worker_main.py'))
    if set(binaries) != set(paths) or any(set(binaries[key]) != {'path', 'sha256'}
            or binaries[key]['path'] != path for key, path in paths.items()):
        raise ValueError('original activation binary profiles differ')

    def context():
        return host_context(source['profile']['session']['host_id'])

    def check():
        verify()
        observed = context()
        if observed != expected:
            persist('context-conflict.json', dict(expected=expected, observed=observed))
            raise ValueError('original native activation context changed')

    def no_binding(value):
        raise ValueError('activation requires the existing original journal binding')

    check()
    with ExitStack() as stack:
        for key, path in paths.items():
            fd = stack.enter_context(open_resource(path))
            proof = source_proof if key in ('start', 'reload') else binary_proof
            proof(fd, binaries[key]['sha256'])
            if key == 'systemctl':
                systemctl = fd
        journal, _ = stack.enter_context(open_postboot_journal(
            original['directory'], installed, identity=original['identity'], initial_sha256=original['database_sha256'],
            retain=no_binding, verify=check, original_binding=inputs['journal-binding.json']))
        names = source['profile']['service_order']
        prefix = ['/usr/bin/systemctl', 'show', '--all', '--no-pager']
        allowed = (
            prefix + ['--property=Id,LoadState,ActiveState,Job', '--', *names, *source['profile']['forbidden_vendor_activation']],
            prefix + ['--property=' + ','.join(PROPERTIES), '--', *names],
        )

        def query(argv, *, env, timeout):
            if argv not in allowed or timeout != 5:
                raise ValueError('fixed readonly activation unit query required')
            binary_proof(systemctl, binaries['systemctl']['sha256'])
            response = subprocess.run(argv, executable=f'/proc/self/fd/{systemctl}', pass_fds=(systemctl,),
                                      stdin=subprocess.DEVNULL, capture_output=True, env=env,
                                      cwd='/', timeout=timeout, check=False)
            return dict(exit_code=response.returncode, stdout=response.stdout.decode('utf-8'),
                        stderr=response.stderr.decode('utf-8'))

        options = {}
        if 'completed-revision.json' in inputs:
            from tools.libvirt_postboot_revision_input import completed_revision_input
            options['completed_revision'] = completed_revision_input(journal, inputs['completed-revision.json'], installed, expected)
        directories = PostBootDirectoryAssembly(
            journal, installed, expected, prepared_reference=inputs['prepared-reference.json'],
            qualification_id=postboot['qualification_id'], recovery_id=postboot['recovery_id'],
            run_parent=postboot['run_parent'], window=ProvisioningWindow(postboot['window'], lambda: None),
            expected_packages=inputs['expected-packages.json'], approved_account_inputs=inputs['approved-account-inputs.json'],
            worker_profile=inputs['worker-profile.json'], query=query, nss_query=host_query, **options)
        if options:
            from dnlab_runtime.libvirt_current_session import CurrentSessionView
            qualified = options['completed_revision']
            view = CurrentSessionView(directories.session.recovery, postboot['recovery_id'])
            revision, completed, swap = qualified.revision, qualified.reference, qualified.exchange.swap
        else:
            unit = PostBootUnitRevision(
                directories, effective_source=inputs['effective-source.json'],
                window=ProvisioningWindow(inputs['unit-window.json'], lambda: None),
                unit_reference=inputs['unit-reference.json'])
            revision = unit.revision.driver
            completed = revision.read(inputs['unit-reference.json']['id'])
            if project_revision(completed) != source:
                raise ValueError('original completed unit projection differs')
            view, swap = unit.view, unit.revision.adapter.swap
        lineage = ActivationLineage(view, revision, reference=completed, effective_source=source)
        providers = ActivationHostInputs(
            lineage, swap=swap, expected_packages=inputs['expected-packages.json'],
            approved_account_inputs=inputs['approved-account-inputs.json'], query=query, nss_query=host_query)

        def active_window():
            check()
            return agreement

        with open_lineage_activation(
            providers, unit_query=query, operation=agreement['operation_id'],
            window=ProvisioningWindow(agreement, active_window), binary=binaries['systemctl'],
            reload_profile=dict(python=binaries['python'], worker=binaries['reload']),
            start_profile=dict(python=binaries['python'], worker=binaries['start']),
            sources_sha256=sources_sha256, bus_inventory=bus, read_context=context, virsh=binaries['virsh'],
        ) as (controller, reference):
            persist('prepared.json', reference)
            try:
                result = controller.apply_original(reference)
            finally:
                persist('journal-state.json', controller.driver.read(reference['id']))
        check()
        if result['phase'] != 'ready_empty':
            raise ValueError('original dedicated activation is not ready')
        return result


def run(recipe):
    from tools.libvirt_bus_inventory_host import private_report

    inputs, sources = verify_recipe(recipe)
    agreement = inputs['activation-window.json']
    nonce = agreement['nonce']
    if not isinstance(nonce, str) or not re.fullmatch('[0-9a-f]{32}', nonce):
        raise ValueError('original activation window nonce required')

    def verify():
        if verify_recipe(recipe) != (inputs, sources):
            raise ValueError('original activation recipe changed')

    with private_report(OUTPUT_PARENT, 'libvirt-activation-' + nonce[:12]) as (write, output):
        def persist(name, value):
            write(name, json.dumps(value, sort_keys=True).encode() + b'\n')

        persist('invocation.json', dict(window=agreement, sources_sha256=sources,
                                        activation_source_sha256=sha((recipe / 'activation-source.json').read_bytes())))
        try:
            activated = activate(inputs, sources, verify=verify, persist=persist)
            result = dict(status='ready_empty', activation=activated)
        except Exception as error:
            result = dict(status='failed', error_type=type(error).__name__, error=str(error))
        persist('result.json', result)
        return result, output


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--recipe', required=True, type=Path)
    parser.add_argument('--activate-host', action='store_true', required=True)
    args = parser.parse_args(argv)
    if not sys.dont_write_bytecode or not sys.flags.isolated or not sys.flags.no_site or os.geteuid() != 0:
        parser.error('root and python -B -I -S required')
    verify_recipe(args.recipe)
    sys.path.insert(0, str(RUNTIME))
    result, output = run(args.recipe)
    print(json.dumps(dict(status=result['status'], output=str(output)), sort_keys=True), flush=True)
    return 0 if result['status'] == 'ready_empty' else 1


if __name__ == '__main__':
    raise SystemExit(main())
