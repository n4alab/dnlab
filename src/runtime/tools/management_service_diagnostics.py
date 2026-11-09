"""Private diagnostic artifacts for the service fixture; no runtime mutations."""
import hashlib
import json
import os
from pathlib import Path
import shlex
import subprocess
import tempfile
import time

from management_prepare_smoke import Host


def sanitized(value,secrets=()):
    if isinstance(value,str):
        for secret in sorted((v for v in secrets if v),key=len,reverse=True):value=value.replace(secret,'<redacted>')
        return value
    if isinstance(value,dict):return {key:sanitized(item,secrets) for key,item in value.items()}
    if isinstance(value,(list,tuple)):return [sanitized(item,secrets) for item in value]
    return value


def private_json(path,value,secrets=()):
    path=Path(path);fd,temporary=tempfile.mkstemp(dir=path.parent,prefix='.diagnostic-')
    try:
        with os.fdopen(fd,'w') as stream:
            os.fchmod(stream.fileno(),0o600)
            json.dump(sanitized(value,secrets),stream,indent=2);stream.write('\n');stream.flush();os.fsync(stream.fileno())
        os.replace(temporary,path)
        fd=os.open(path.parent,os.O_DIRECTORY)
        try:os.fsync(fd)
        finally:os.close(fd)
    finally:
        if os.path.exists(temporary):os.unlink(temporary)


def exception_chain(error):
    rows=[];seen=set()
    while error is not None and id(error) not in seen:
        seen.add(id(error));rows.append({'type':type(error).__name__,'message':str(error)})
        error=error.__cause__ or (None if error.__suppress_context__ else error.__context__)
    return rows


def comparison_differences(expected,actual,path=''):
    """Retain type evidence that JSON snapshots alone cannot represent."""
    if type(expected) is not type(actual):
        return [{'path':path or '/', 'expected_type':type(expected).__name__,
                 'actual_type':type(actual).__name__,'expected':expected,'actual':actual}]
    if isinstance(expected,dict):
        rows=[]
        for key in sorted(set(expected)|set(actual)):
            child=path+'/'+str(key).replace('~','~0').replace('/','~1')
            if key not in expected or key not in actual:
                rows.append({'path':child,'expected_present':key in expected,'actual_present':key in actual})
            else:rows.extend(comparison_differences(expected[key],actual[key],child))
        return rows
    if isinstance(expected,(list,tuple)):
        rows=[]
        if len(expected)!=len(actual):rows.append({'path':path or '/','expected_length':len(expected),'actual_length':len(actual)})
        for index,(left,right) in enumerate(zip(expected,actual)):
            rows.extend(comparison_differences(left,right,path+'/'+str(index)))
        return rows
    return [] if expected==actual else [{'path':path or '/','expected':expected,'actual':actual}]


def compare_snapshot(root,name,expected,actual,secrets=()):
    if not name or any(c not in 'abcdefghijklmnopqrstuvwxyz0123456789-' for c in name):
        raise ValueError('diagnostic comparison name required')
    path=Path(root)/(name+'.json')
    # The verdict deliberately uses the original equality, without normalization.
    matches=expected==actual
    private_json(path,{'check':name,'matches':matches,'expected':expected,'actual':actual,
                       'differences':comparison_differences(expected,actual)},secrets)
    if not matches:raise RuntimeError('fixture comparison '+name+' differs; see '+path.name)


class DiagnosticHost(Host):
    def __init__(self,root):
        super().__init__();self.root=Path(root);self.phase='setup';self.secrets=[];self.diagnostics=[]

    def run_input(self,command,payload,**kwargs):
        try:
            envelope=json.loads(payload) if payload else {}
            request=envelope.get('request',envelope);action=request.get('action','inventory')
        except (ValueError,AttributeError):action='inventory'
        before=len(self.events);started=time.monotonic()
        row={'phase':self.phase,'action':action,'sequence':len(self.diagnostics),'status':'running',
             'argv_bytes':sum(len(v.encode())+1 for v in shlex.split(command)),'stdin_bytes':len((payload or '').encode())}
        self.diagnostics.append(row);private_json(self.root/'worker-events.json',self.diagnostics,self.secrets)
        try:
            result=super().run_input(command,payload,**kwargs);row['status']='returned';return result
        except Exception as error:
            row.update(status='failed',causes=exception_chain(error));raise
        finally:
            row['elapsed_seconds']=round(time.monotonic()-started,6)
            if len(self.events)>before:
                event=self.events[-1];row.update(exit_code=event['exit_code'],stderr=event['stderr'])
            private_json(self.root/'worker-events.json',self.diagnostics,self.secrets)


def selected_journals(root):
    rows=[];names=set()
    for directory in ('jump','dns','external','management','probes'):
        for path in sorted((Path(root)/directory).glob('*.json')):
            try:
                record=json.loads(path.read_text())
                fields=('phase','action','step','error_type','container_id','nonce','started_at','namespace','host','peer','bridge','qualifying')
                row={key:record[key] for key in fields if key in record};row.update(journal=directory,file=path.name)
                row['attachment_phases']={key:{k:v[k] for k in ('phase','step','error_type') if k in v} for key,v in record.get('management_attachments',{}).items()}
                config=record.get('config',{});row['generation']=config.get('generation')
                row['config_fingerprint']=hashlib.sha256(json.dumps(config,sort_keys=True,separators=(',',':')).encode()).hexdigest()
                row['container_name']=config.get('name');row['image_id']=(record.get('image') or {}).get('Id')
                row['label_prefix']='org.dnlab.jumphost.' if directory=='jump' else 'org.dnlab.dns.'
                if directory=='probes':
                    request=record['request']
                    key=hashlib.sha256(json.dumps(['management-probe-v1',request],sort_keys=True,separators=(',',':')).encode()).hexdigest()
                    row['container_name']='dnlab-probe-'+key[:24]
                    row['label_prefix']='org.dnlab.management-probe.'
                    if record.get('packet_execution'):
                        from dnlab_multinode.services.management_probe_exec import execution_identity
                        row['execution']=execution_identity(record)
                        row['execution_status']={k:record['packet_execution'].get(k) for k in ('phase','create_attempted','start_attempted','create_calls','start_calls','exit_verified','exit_code','error','process','observations','partial_tail')}
                for key in ('host','peer','bridge'):
                    if isinstance(record.get(key),dict) and record[key].get('ifname'):names.add(record[key]['ifname'])
                names.update(record.get('resources',{}))
                if directory=='external':names.add(config['bridge'])
                rows.append(row)
            except Exception as error:rows.append({'journal':directory,'file':path.name,'diagnostic_error':exception_chain(error)})
    return rows,names


def capture_before_cleanup(root,host,api,store,lab):
    rows,names=selected_journals(root)
    snapshot={'phase':host.phase,'journals':rows,'containers':[],'packet_execs':[]}
    for row in rows:
        proof=row.get('execution')
        if not proof:continue
        try:
            value=api.request('GET','/exec/'+proof['id']+'/json',missing_ok=True)
            item={'expected':proof,'present':value is not None}
            if value:
                item.update({key:value.get(key) for key in ('ID','ContainerID','Running','Pid','ExitCode')})
                config=value.get('ProcessConfig') or {}
                command=[config.get('entrypoint')]+(config.get('arguments') or [])
                item['command_sha256']=hashlib.sha256(json.dumps(command,sort_keys=True,separators=(',',':')).encode()).hexdigest()
            snapshot['packet_execs'].append(item)
        except Exception as error:snapshot['packet_execs'].append({'expected':proof,'error':exception_chain(error)})
    try:
        result=subprocess.run(['ip','-j','-d','link','show'],capture_output=True,text=True,timeout=10,check=True)
        snapshot['host_links']=[v for v in json.loads(result.stdout) if v['ifname'] in names]
    except Exception as error:snapshot['host_links_error']=exception_chain(error)
    for row in rows:
        if not row.get('container_id'):continue
        try:
            value=api.request('GET','/containers/'+row['container_id']+'/json',missing_ok=True)
            item={'journal':row['journal'],'present':value is not None}
            if value:
                item.update({key:value.get(key) for key in ('Id','Name','Image','State','NetworkSettings')})
                labels=(value.get('Config') or {}).get('Labels') or {}
                qualified=(value['Id']==row['container_id'] and value['Image']==row['image_id']
                    and value['Name']=='/'+row['container_name'] and labels.get(row['label_prefix']+'nonce')==row['nonce'])
                item['original_birth_qualified']=qualified
                if qualified:
                    result=subprocess.run(['docker','logs','--tail','60',value['Id']],capture_output=True,text=True,timeout=10)
                    item['logs']={'exit_code':result.returncode,'stdout':result.stdout,'stderr':result.stderr}
                    pid=value.get('State',{}).get('Pid')
                    if value.get('State',{}).get('Running') and type(pid) is int and pid>0:
                        result=subprocess.run(['nsenter','--net=/proc/'+str(pid)+'/ns/net','ip','-j','-d','link','show'],capture_output=True,text=True,timeout=10)
                        item['namespace_links']={'exit_code':result.returncode,'stderr':result.stderr,
                            'links':json.loads(result.stdout) if result.returncode==0 else None}
            snapshot['containers'].append(item)
        except Exception as error:snapshot['containers'].append({'journal':row['journal'],'diagnostic_error':exception_chain(error)})
    if store is not None:
        try:
            from dnlab_multinode.services import management_barrier as barrier
            record=barrier.get(store,lab)
            snapshot['coordinator']={'phase':record.get('phase'),'infrastructure_phase':record.get('infrastructure',{}).get('phase'),
                'services_phase':record.get('services',{}).get('phase'),'plan_fingerprint':record.get('plan_fingerprint')}
        except Exception as error:snapshot['coordinator_error']=exception_chain(error)
    private_json(Path(root)/'before-cleanup.json',snapshot,host.secrets)
    return snapshot


def remove_fixture_external(worker,api):
    """Delete a fixture-owned empty network by ID; support Docker HTTP204."""
    record=worker.read()
    if record:
        worker.preflight();value=worker.docker.inspect(record['id'])
        if value['Containers']:raise RuntimeError('fixture external network still has consumers')
        worker.verify(record,value)
        api.request('DELETE','/networks/'+record['id'])
        if worker.docker.inspect(record['id']) is not None:raise RuntimeError('fixture external network remains')
        return record['id']
    if worker.docker.inspect(worker.config['network']) is not None:raise RuntimeError('unbound fixture external network')
    return None


def probe_cleanup_order(directory):
    """Finish live child attempts before replaying cleanup of their predecessors.

    No proof is altered: every entry still passes the original coordinator birth,
    execution and kernel guards in the caller. A failed live cleanup keeps its
    dependent infrastructure protected.
    """
    def order(path):
        try:cleaned=json.loads(path.read_text()).get('phase')=='cleaned'
        except (OSError,ValueError,AttributeError):cleaned=False
        # The caller still reports malformed journals and preserves dependencies.
        return cleaned,path.name
    return sorted(Path(directory).glob('*.json'),key=order)
