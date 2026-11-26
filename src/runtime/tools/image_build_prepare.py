"""Prepare the existing image-build hold from an explicit original generation.

Preparation performs readonly observations plus controller table setup. Caller
persists returned receipts before prepare/acquire. No service command is sent.
The same caller-owned RuntimeProcess must survive acquire, VM cleanup, restore.
"""
from copy import deepcopy
from types import SimpleNamespace

from cleanup_container_observer import LinuxProcess, config_digest
from image_build_activity import ImageBuildActivity
from image_build_healthcheck import ImageBuildHealthcheck
from dnlab_runtime.image_build_commands import ImageBuildCommands
from image_build_binding import capture_binding, ImageBuildBinding
from image_build_control import ImageBuildEngine
from image_build_ledger import capture_ledger, JobLedger
from image_build_observation import artifact_digest, process_digest, terminal_jobs_digest
from image_build_query import ImageBuildNamespaceQuery
from image_build_session import ImageBuildSession
from dnlab_runtime.image_build_hold import actor
from dnlab_runtime.manifest import fingerprint
from dnlab_runtime.vm_template import require


def prepare_session(*, api, expected_inspect, expected_capture, expected_context,
                    expected_copies, expected_binding, runtime, read_context,
                    verify_original, paths, identities, container_log_dir,
                    checkout, lock_sha256, proc_identity, build_roots,
                    scope, window, cleanup, shell_asset, record_activity):
    """No identity learning, service stop/start, or hold acquisition.

    The expected generation and source hashes must be explicit original inputs;
    current presence alone cannot authorize a replacement API process. Receipt
    capture qualifies only the readonly ledger and checkout for this attempt.
    """
    require(callable(verify_original) and callable(window) and callable(cleanup) and callable(record_activity),
            'original source proof, durable diagnostic writer and explicit window/cleanup providers required')
    cid = expected_inspect['Id']
    def check():
        require(verify_original() is True and read_context() == expected_context,
                'original image-build prerequisites changed')
        current = api.inspect(cid)
        require(current['Id'] == cid and current['Image'] == expected_inspect['Image']
                and config_digest(current) == config_digest(expected_inspect)
                and current['RestartCount'] == expected_inspect['RestartCount']
                and all(current['State'][key] == expected_inspect['State'][key]
                    for key in ('Pid','Running','Status','StartedAt')),
                'original image-build generation/configuration changed')
        require(current['State']['Running'] is True and current['State']['Status'] == 'running'
                and current['State']['Pid'] == expected_capture['process']['pid']
                and not current['State'].get('OOMKilled') and not current['State'].get('Error'),
                'original live image-build process required')
        return current
    inspected = check()
    require(set(expected_capture['sources']) == set(expected_copies)
            and all(expected_capture['sources'][path]['sha256'] == digest
                    for path,digest in expected_copies.items()),
            'expected image-build execution assets differ')
    generation = dict(started_at=inspected['State']['StartedAt'],
        restart_count=inspected['RestartCount'])
    owner = dict(container_id=cid, image_id=inspected['Image'],
        config_sha256=config_digest(inspected), context_sha256=fingerprint(expected_context),
        process_sha256=process_digest(expected_capture,generation),
        artifact_sha256=artifact_digest(inspected['Image'],expected_copies,
            expected_capture['executable']['sha256']))
    actor(owner)
    profile = dict(actor=owner, context=deepcopy(expected_context),
        policy=deepcopy(inspected['HostConfig']['RestartPolicy']),
        capture=deepcopy(expected_capture), generation=generation,
        copies=deepcopy(expected_copies), binding=deepcopy(expected_binding),
        networks={name:value['NetworkID'] for name,value in inspected['NetworkSettings']['Networks'].items()})
    query = ImageBuildNamespaceQuery(api, profile, read_context=read_context)
    process = LinuxProcess()
    with process.capture(expected_capture['process']['pid'],cid,expected_copies) as current:
        require(current == expected_capture, 'original image-build capture changed')
        response = query(dict(actor=owner,scope=scope), current)
        require(response['health'] == dict(ok=True) and response['binding'] == expected_binding,
                'original aligned image-build API differs')
        jobs_sha256 = terminal_jobs_digest(response['jobs'])
        engine = ImageBuildEngine(cid)
        binding_receipt = capture_binding(checkout=checkout,binding=expected_binding,
            original_actor=owner,lock_sha256=lock_sha256,context=expected_context,
            read_context=read_context,read_lock=engine.lock_asset)
        ledger_receipt = capture_ledger(paths=paths,identities=identities,
            container_log_dir=container_log_dir,api_jobs=response['jobs'],original_actor=owner,
            context=expected_context,read_context=read_context)
        check()
    profile['ledger_sha256'] = fingerprint(ledger_receipt)
    binding = ImageBuildBinding(binding_receipt,expected_sha256=fingerprint(binding_receipt),
        read_context=read_context,read_lock=engine.lock_asset)
    ledger = JobLedger(ledger_receipt,expected_sha256=profile['ledger_sha256'],read_context=read_context)
    def original_startup(value):
        item=value['actions'].get('start')
        require(item is not None and item['reference'] is not None,
                'original startup command reference required')
        command=session.commands.qualified_snapshot(item['reference'])
        require(command['command']==item['command'] and command['reference']==item['reference']
                and command['phase'] in ('release_requested','completed')
                and command.get('start_ack')==dict(container_id=cid,status=204,empty_body=True)
                and command.get('start_progress') is not None,
                'original durable start acknowledgement and first generation required')
        proof=command['start_progress']
        ImageBuildCommands._start_proof(proof,item['command'],item['reference'])
        if command['phase']=='completed':
            require(command['details'].get('startup')==proof, 'original completed startup proof differs')
        return deepcopy(proof)
    healthcheck=ImageBuildHealthcheck(api,profile,shell_asset=shell_asset,
        read_context=read_context,startup=original_startup)
    activity = ImageBuildActivity(api,context=expected_context,read_context=read_context,
        proc_identity=proc_identity,roots=build_roots,record=record_activity,
        qualify_healthcheck=healthcheck)
    session = ImageBuildSession(runtime,profile,jobs_sha256=jobs_sha256,api=api,
        read_context=read_context,binding=binding,ledger=ledger,activity=activity,
        window=window,cleanup=cleanup,engine=engine,process=process,query=query)
    observed = session.observe(scope)
    require(observed['running'] is True and observed['actor'] == owner,
            'original image-build readonly preparation differs')
    check()
    return SimpleNamespace(session=session, profile=deepcopy(profile),
        ledger=ledger_receipt,binding=binding_receipt,response=response,observation=observed,
        activity=activity,healthcheck=healthcheck)
