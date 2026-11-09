"""Only synthetic systemctl responses and explicit file-observer callbacks."""
from copy import deepcopy

import pytest

from dnlab_runtime.manifest import Conflict
from tools.libvirt_service_units import ServiceUnitReader, PROPERTIES
from test_libvirt_install import install, request_profile


@pytest.fixture
def reader(install):
    installer,_,prepared,_=install;installed=installer.apply(prepared['id'])
    names=installed['profile']['service_order']
    files={item['spec']['path']:deepcopy(item['proof']) for item in installed['items'] if item['spec']['kind']=='file'}
    rows=[dict(Id=name,LoadState='loaded',ActiveState='inactive',SubState='dead',MainPID='0',InvocationID='',
        FragmentPath='/etc/systemd/system/'+name,DropInPaths='',Restart='no',Job='') for name in names]
    state=dict(files=files,rows=rows,stderr='',exit_code=0,calls=[],hook=lambda:None)
    def query(argv,**options):
        state['calls'].append((argv,options));state['hook']()
        raw='\n\n'.join('\n'.join(key+'='+row[key] for key in PROPERTIES) for row in state['rows'])+'\n'
        return dict(exit_code=state['exit_code'],stderr=state['stderr'],stdout=raw)
    return ServiceUnitReader(installed,query=query,files=lambda:deepcopy(state['files'])),state,names


def test_fixed_readonly_query_reports_inactive_units_without_readiness_claim(reader):
    observer,state,names=reader
    result=observer()
    assert all(v['unit']['active']=='inactive' and v['unit']['pid']==0 for v in result.values())
    argv,options=state['calls'][0]
    assert argv==['/usr/bin/systemctl','show','--all','--no-pager','--property='+','.join(PROPERTIES),'--',*names]
    assert options['timeout']==5 and options['env']['LC_ALL']=='C'
    assert observer.diagnostics[0]['status']=='collected'


@pytest.mark.parametrize('fault',['foreign','missing','duplicate','pid','job','invocation','fragment','dropin','stderr','exit'])
def test_unqualified_unit_or_transport_is_refused_with_original_response(reader,fault):
    observer,state,_=reader
    row=state['rows'][0]
    if fault=='foreign':row['Id']='foreign.service'
    elif fault=='missing':state['rows'].pop()
    elif fault=='duplicate':state['rows'].append(deepcopy(row))
    elif fault=='pid':row['MainPID']='-1'
    elif fault=='job':row['Job']='garbage'
    elif fault=='invocation':row['InvocationID']='not-an-id'
    elif fault=='fragment':row['FragmentPath']='/foreign/service'
    elif fault=='dropin':row['DropInPaths']='/run/foreign.conf'
    elif fault=='stderr':state['stderr']='original synthetic denial'
    else:state['exit_code']=1
    with pytest.raises(Conflict):observer()
    assert observer.diagnostics[0]['response']['exit_code']==state['exit_code']


def test_file_conflict_blocks_before_query_and_changes_during_query_are_refused(reader):
    observer,state,_=reader
    first=next(iter(state['files']))
    original=deepcopy(state['files'][first]);state['files'][first]={'foreign':'preserve'}
    with pytest.raises(Conflict):observer()
    assert state['calls']==[]
    state['files'][first]=original
    state['hook']=lambda:state['files'].update({first:{'foreign':'preserve'}})
    with pytest.raises(Conflict,match='changed during query'):observer()
    assert state['files'][first]=={'foreign':'preserve'}
