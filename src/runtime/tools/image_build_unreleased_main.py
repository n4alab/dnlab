"""Frozen metadata-retirement entry; audit is offline, execution is explicit."""
import argparse
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import re
import sys
import traceback
from types import SimpleNamespace
import uuid


def main(argv=None):
    parser=argparse.ArgumentParser(description=__doc__)
    group=parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--audit',action='store_true')
    group.add_argument('--retire-metadata',action='store_true')
    parser.add_argument('--manifest-sha256',required=True)
    args=parser.parse_args(argv)
    if not (sys.dont_write_bytecode and sys.flags.isolated and sys.flags.no_site):
        raise RuntimeError('original -B -I -S entry required')
    here=Path(__file__).parent;manifest_raw=(here/'manifest.json').read_bytes()
    if not re.fullmatch('[0-9a-f]{64}',args.manifest_sha256) or hashlib.sha256(manifest_raw).hexdigest()!=args.manifest_sha256:
        raise RuntimeError('explicit frozen manifest hash differs')
    manifest=json.loads(manifest_raw);inputs_raw=(here/'inputs.json').read_bytes();inputs=json.loads(inputs_raw)
    def sources():
        if (here/'manifest.json').read_bytes()!=manifest_raw or (here/'inputs.json').read_bytes()!=inputs_raw:
            raise RuntimeError('frozen administrative inputs changed')
        for name,expected in manifest['files'].items():
            part=Path(name)
            if part.is_absolute() or '..' in part.parts or (here/part).is_symlink():
                raise RuntimeError('noncanonical frozen source path')
            if hashlib.sha256((here/part).read_bytes()).hexdigest()!=expected:
                raise RuntimeError('frozen administrative source changed: '+name)
    sources();sys.path[:0]=[str(here/'source/runtime'),str(here/'source/runtime/tools')]
    from dnlab_runtime.manifest import fingerprint
    from dnlab_runtime.vm_template import require
    from image_build_unreleased_recipe import execute_recipe, native_observer
    from image_build_unreleased_retirement import _observation
    _observation(inputs['recipe']['request'],inputs['recipe']['original'])
    require(type(inputs['recipe']['execution_allowed']) is bool
            and manifest.get('execution_allowed') is inputs['recipe']['execution_allowed'],
            'frozen execution declarations differ')
    if args.audit:
        # Construct every native adapter, but do not call it or qualify current
        # host state. No original source paths or journal are opened by audit.
        native_observer(inputs['recipe'],SimpleNamespace(check=lambda:None),
            verify_sources=lambda:inputs['recipe']['request']['sources_sha256'],
            read_context=lambda:deepcopy(inputs['recipe']['profile']['context']),record=lambda proof:None)
        print(json.dumps(dict(status='offline_recipe_audited',execution_allowed=inputs['recipe']['execution_allowed'],
            source_count=len(manifest['files']),native_observation_executed=False)),flush=True)
        return 0
    require(inputs['recipe']['execution_allowed'] is True and os.geteuid()==os.getegid()==0,
            'recipe is not enabled for an explicitly authorized root retirement')
    with open('/proc/self/exe','rb') as stream:
        require(hashlib.file_digest(stream,'sha256').hexdigest()==
                inputs['recipe']['original']['epoch']['snapshot']['record']['executable_sha256'],
                'administrative interpreter differs from the qualified original binary')
    from libvirt_bus_inventory_host import private_report,host_context
    def owner_sources():
        sources()
        for name,expected in inputs['owner_sources']['files'].items():
            path=Path(name)
            require(path.is_absolute() and '..' not in path.parts and not path.is_symlink()
                    and hashlib.sha256(path.read_bytes()).hexdigest()==expected,
                    'original producer source changed: '+name)
        return fingerprint(inputs['owner_sources']['digest_input'])
    attempt=uuid.uuid4().hex
    with private_report(inputs['output_parent'],'unreleased-retirement-'+inputs['recipe']['request']['id'][:12]+'-'+attempt[:12]) as (write,output):
        def persist(name,value):
            write(name,(json.dumps(value,sort_keys=True,indent=2)+'\n').encode());return fingerprint(value)
        sequence=0
        def record(proof):
            nonlocal sequence
            sequence+=1;persist('activity-'+str(sequence).zfill(6)+'.json',proof)
        try:
            receipt=execute_recipe(inputs['recipe'],snapshot=output/'snapshot',persist=persist,record=record,
                verify_sources=owner_sources,read_context=lambda:host_context(inputs['recipe']['profile']['context']['host_id']))
            persist('result.json',dict(status='metadata_retired',receipt=receipt,service_actions=0,vm_operations=0))
            print(json.dumps(dict(status='metadata_retired',output=str(output),service_actions=0,vm_operations=0)),flush=True)
            return 0
        except BaseException as error:
            persist('failure.json',dict(status='pending',error_type=type(error).__name__,error=str(error),traceback=traceback.format_exc()))
            print(json.dumps(dict(status='pending',output=str(output),error=str(error))),flush=True)
            return 1


if __name__=='__main__':raise SystemExit(main())
