"""Prepare pinned raw source contexts and candidate recipes; never calls Docker."""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import json
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
sys.path.insert(0, str(ROOT / 'src/image-build'))
from patches import _common

DIRECTORIES = {'cisco_n9kv': 'cisco/n9kv_V2', 'cisco_vios': 'cisco/vios_V2'}


def prepare(kind, disk, checkout, output):
    disk = disk.resolve(strict=True)
    if not disk.is_file() or disk.suffix != '.qcow2':
        raise ValueError('candidate requires an existing qcow2 source')
    lock = json.loads((ROOT / 'vrnetlab.lock.json').read_text())
    revision = lock['commit']
    context, preview = output / 'raw-context', output / 'patch-preview'
    context.mkdir(parents=True, exist_ok=False)
    preview.mkdir()
    def blob(path):
        return subprocess.run(['git', '-C', str(checkout), 'show', revision + ':' + path], check=True, capture_output=True).stdout
    sources = {'vrnetlab.py': 'common/vrnetlab.py', 'healthcheck.py': 'common/healthcheck.py', 'launch.py': DIRECTORIES[kind] + '/docker/launch.py', 'Dockerfile': DIRECTORIES[kind] + '/docker/Dockerfile'}
    if kind == 'cisco_n9kv':
        sources['OVMF.fd'] = DIRECTORIES[kind] + '/docker/OVMF.fd'
    hashes = {}
    for filename, source in sources.items():
        content = blob(source)
        (context / filename).write_bytes(content)
        mode = subprocess.run(['git', '-C', str(checkout), 'ls-tree', revision, source], check=True, capture_output=True, text=True).stdout.split()[0]
        if mode not in {'100644', '100755'}:
            raise RuntimeError('candidate source must be a regular Git blob')
        (context / filename).chmod(0o755 if mode == '100755' else 0o644)
        hashes[source] = hashlib.sha256(content).hexdigest()
    module = importlib.import_module('patches.' + kind)
    for target in module.FILES:
        text = (context / Path(target).name).read_text()
        patched, _ = module.apply(target, text)
        if target == '/vrnetlab.py':
            patched, ok = _common.patch_runtime_management(patched)
            if not ok:
                raise RuntimeError('pinned source lacks the management ABI anchors')
        if target == '/launch.py':
            patched, ok = _common.patch_launcher_constructor(patched, (context / 'vrnetlab.py').read_text())
            if not ok:
                raise RuntimeError('pinned launcher/common constructor ABI is unsupported')
        ast.parse(patched)
        (preview / Path(target).name).write_text(patched)
    stat = disk.stat()
    raw_tag = 'dnlab-runtime-candidate/' + kind + ':' + output.name
    recipe = {
        'status': 'prepared-not-built-not-qualified', 'kind': kind,
        'vrnetlab_commit': revision, 'source_hashes': hashes,
        'disk_source': str(disk), 'disk_size': stat.st_size, 'disk_mtime_ns': stat.st_mtime_ns,
        'raw_context': str(context), 'patch_preview': str(preview),
        'commands_not_executed': [
            ['cp', '--reflink=auto', str(disk), str(context / disk.name)],
            ['docker', 'build', '--build-arg', 'IMAGE=' + disk.name, '-t', raw_tag, str(context)],
            [sys.executable, str(ROOT / 'src/image-build/apply.py'), kind, raw_tag, '--runtime-management', '--runtime-management-python=' + ('uv' if kind == 'cisco_n9kv' else 'system'), '--tag-suffix=-runtime-spike'],
        ],
        'qualification_gaps': ['candidate image digest', 'real NOS datapath', 'verified guest shutdown', 'disk persistence', 'dnlab-vrf', 'no-OOB arbitrary port adapter' if kind == 'cisco_vios' else 'OOB bootstrap and guest mapping'],
    }
    (output / 'candidate.json').write_text(json.dumps(recipe, indent=2) + '\n')
    return recipe


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('kind', choices=DIRECTORIES)
    parser.add_argument('disk', type=Path)
    parser.add_argument('--vrnetlab', type=Path, default=Path('/opt/vrnetlab'))
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    output = args.output or Path(tempfile.mkdtemp(prefix='dnlab-nos-candidate-'))
    print(json.dumps(prepare(args.kind, args.disk, args.vrnetlab, output), indent=2))
