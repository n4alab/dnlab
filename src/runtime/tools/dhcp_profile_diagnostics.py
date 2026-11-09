"""Readonly observation of the original DHCP log validator in a test fixture.

The Python call observer records arguments before the unchanged validator runs.
It never substitutes a function or profile, and never accepts a rejected image.
"""
from copy import deepcopy
import hashlib
import sys

from management_service_diagnostics import private_json
from dnlab_multinode.services import jumphost_host as host


def compare_reference(value,service,main,profile):
    info=value['file']
    return {
        'binary_hash_matches':service['binary_sha256']==profile['binary_sha256'],
        'log_gid_matches':info['gid']==profile['gid'],
        'log_mode_matches':info['mode']==profile['mode'],
        'log_regular_single_link':info['regular'] is True and info['nlink']==1,
        'log_uid_matches_service':info['uid']==service['profile']['uid'],
        'parent_directories_qualified':len(value['directories'])==2 and all(
            row['directory'] is True and row['uid']==0 and not row['mode']&0o022 for row in value['directories']),
        'writer_matches_service':value['writer']=={'host_pid':service['host_pid'],'start':service['start']},
        'log_facility_matches':[line for line in main.splitlines() if line.startswith('log-facility=')]==['log-facility=/run/dnlab-dhcp.log'],
        'configuration_hash_matches':value['configuration_sha256']==hashlib.sha256(main.encode()).hexdigest(),
    }


def observe_validator(callback,path,*,validator=None,profiles=None):
    validator=validator or host.dhcp_validate_log
    profiles=deepcopy(host.DHCP_LOG_PROFILES if profiles is None else profiles)
    previous=sys.getprofile();observations=[]
    def record_call(frame,event,arg):
        if event!='call' or frame.f_code is not validator.__code__:return
        value=deepcopy(frame.f_locals['value']);service=frame.f_locals['service'];main=frame.f_locals['main']
        # Explicit allowlist: no raw main, environment, container config or logs.
        service={key:deepcopy(service[key]) for key in ('container','host_pid','pid','start','command','uids','gids',
            'profile','pid_file','pid_namespace','net_namespace','mount_namespace','binary','mapped_binary','binary_sha256')}
        image=service['container']['image']
        comparisons={digest:compare_reference(value,service,main,profile) for digest,profile in profiles.items()}
        observations.append({'log':value,'service':service,
            'main_sha256':hashlib.sha256(main.encode()).hexdigest(),
            'log_facility':[line for line in main.splitlines() if line.startswith('log-facility=')],
            'image_profile_present':image in profiles,'reference_comparisons':comparisons})
        private_json(path,{'status':'captured-before-original-validator','observations':observations})
    error=None;returned=False
    try:
        sys.setprofile(record_call)
        callback();returned=True
    except Exception as caught:
        error={'type':type(caught).__name__,'message':str(caught)}
    finally:sys.setprofile(previous)
    result={'status':'diagnosed' if observations and not returned else 'incomplete',
        'observations':observations,'original_validator_returned':returned,'original_error':error,
        'profile_map_unchanged':profiles==host.DHCP_LOG_PROFILES if validator is host.dhcp_validate_log else True,
        'observer_restored':sys.getprofile() is previous}
    private_json(path,result)
    return result


def diagnose(worker,expected_config,path):
    original=host.dhcp_validate_log;profiles=deepcopy(host.DHCP_LOG_PROFILES)
    with worker.locked():
        record=worker.read()
        if (not record or record['phase']!='active' or record['action']!='ensure' or record['config']!=expected_config):
            raise RuntimeError('diagnostic requires original active fixture jumphost')
        worker.dhcp_preflight(record)
        journal=worker.path.read_bytes()
        with worker.namespace(record) as fd:
            with host.DHCPHostService(worker,record,fd) as service:
                result=observe_validator(lambda:service.observe(record.get('dhcp_expected_service')),path)
        if worker.path.read_bytes()!=journal:raise RuntimeError('diagnostic journal changed')
    if host.dhcp_validate_log is not original or host.DHCP_LOG_PROFILES!=profiles:
        raise RuntimeError('diagnostic changed validator or profiles')
    if (result['status']!='diagnosed' or len(result['observations'])!=1
            or result['original_error']!={'type':'JumphostError','message':'DHCP log image/configuration profile not qualified'}):
        raise RuntimeError('diagnostic did not preserve original profile rejection')
    result.update(original_validator_unchanged=True,journal_unchanged=True,service_mutations_performed=False)
    private_json(path,result)
    return result
