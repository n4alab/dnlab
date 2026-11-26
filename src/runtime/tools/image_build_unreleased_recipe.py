"""Native wiring for one frozen, explicitly enabled metadata-only recipe.

No CLI execution on import. The wrapper owns root isolation, source/input pins,
private fsynced reports and the operator authorization. This component opens no
libvirt connection and provides no service mutation transport.
"""
from copy import deepcopy
import os
from pathlib import Path
import time
from urllib.parse import urlencode

from dnlab_runtime.backend import Docker
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import fields, require
from cleanup_container_observer import LinuxProcess
from image_build_activity import ImageBuildActivity
from image_build_binding import ImageBuildBinding
from image_build_control import ImageBuildEngine
from image_build_healthcheck import ImageBuildHealthcheck
from image_build_ledger import JobLedger
from image_build_observation import ImageBuildObservation
from image_build_query import ImageBuildNamespaceQuery
from image_build_admin_fence import OriginalGateFence
from image_build_unreleased_execution import CheckpointedRetirementFence, execute_unreleased
from image_build_unreleased_observation import UnreleasedObservation


class ReadonlyService(Docker):
    def __init__(self, container_id):
        super().__init__();self.container_id=container_id

    def request(self, method, path, payload=None, **kwargs):
        require(method=='GET' and payload is None and path=='/containers/'+self.container_id+'/json',
                'only original container GET inspect is permitted')
        return super().request(method,path,payload,**kwargs)


class ReadonlyLockAsset(ImageBuildEngine):
    def _request(self, suffix, payload, expected, *, method='POST', limit=65536):
        require(method=='GET' and payload is None and expected==200 and limit==65536
                and suffix=='/archive?'+urlencode(dict(path='/opt/dnlab-image-build/vrnetlab.lock.json')),
                'only original lock asset GET archive is permitted')
        return super()._request(suffix,payload,expected,method=method,limit=limit)


def native_observer(inputs, fence, *, verify_sources, read_context, record):
    original=inputs['original'];profile=deepcopy(inputs['profile']);hold=original['hold']
    api=ReadonlyService(hold['actor']['container_id']);engine=ReadonlyLockAsset(hold['actor']['container_id'])
    def no_dispatch(value):raise RuntimeError('unreleased retirement cannot observe a start or stop receipt')
    health=ImageBuildHealthcheck(api,profile,shell_asset=inputs['shell_asset'],read_context=read_context,startup=no_dispatch)
    activity=ImageBuildActivity(api,context=profile['context'],read_context=read_context,
        proc_identity=inputs['proc_identity'],roots=inputs['build_roots'],record=record,qualify_healthcheck=health)
    binding=ImageBuildBinding(inputs['binding'],expected_sha256=fingerprint(inputs['binding']),
        read_context=read_context,read_lock=engine.lock_asset)
    ledger=JobLedger(inputs['ledger'],expected_sha256=profile['ledger_sha256'],read_context=read_context)
    service=ImageBuildObservation(api,profile,context=read_context,
        query=ImageBuildNamespaceQuery(api,profile,read_context=read_context),binding=binding,ledger=ledger,
        activity=activity,exit_receipt=no_dispatch,startup=no_dispatch,process=LinuxProcess())
    return UnreleasedObservation(inputs['request'],original,service=service,networks=inputs['networks'],
        fence=fence,verify_sources=verify_sources,read_context=read_context,
        proc_identity=inputs['proc_identity'],record=record)


def execute_recipe(inputs, *, snapshot, persist, record, verify_sources, read_context, clock=time.monotonic):
    inputs=deepcopy(inputs)
    fields(inputs,('schema_version','execution_allowed','request','original','profile','networks','binding',
                  'ledger','shell_asset','build_roots','directory','physical','proc_identity'),'unreleased recipe')
    require(type(inputs['schema_version']) is int and inputs['schema_version']==1
            and inputs['execution_allowed'] is True and all(callable(fn) for fn in
                (persist,record,verify_sources,read_context,clock)), 'explicit frozen recipe and qualified providers required')
    deadline=clock()+120
    def verify():
        require(clock()<deadline, 'metadata retirement window expired')
        return verify_sources()
    require(verify()==inputs['request']['sources_sha256'] and read_context()==inputs['profile']['context'],
            'original metadata recipe source/context differs')
    intent=dict(inputs_sha256=fingerprint(inputs),request=inputs['request'],physical=inputs['physical'])
    require(persist('intent.json',intent)==fingerprint(intent), 'durable recipe intent not acknowledged')
    try:os.lstat(Path(inputs['directory'])/'journal.sqlite3-wal')
    except FileNotFoundError:fence_type=CheckpointedRetirementFence
    else:fence_type=OriginalGateFence
    with fence_type(inputs['directory'],inputs['physical']) as fence:
        observe=native_observer(inputs,fence,verify_sources=verify,read_context=read_context,record=record)
        original=inputs['original']
        return execute_unreleased(fence,inputs['request'],original,
            arguments=dict(hold_id=original['hold']['id'],command_id=original['command']['id'],epoch=original['epoch']),
            snapshot=snapshot,observe=observe,persist=persist)
