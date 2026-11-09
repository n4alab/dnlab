"""Read-only reservation preflight and atomic admission regression tests."""
from copy import deepcopy

import pytest

from dnlab_runtime.backend import Backend
from dnlab_runtime.engine import Engine
from dnlab_runtime.journal import Journal
from dnlab_runtime.manifest import Conflict
from fakes import FakeDocker,FakeLinux,planned_request


@pytest.mark.parametrize('resource',['container','published_port'])
def test_initial_plan_and_submit_refuse_existing_reservation(tmp_path,resource):
    journal=Journal(tmp_path/'runtime');docker=FakeDocker();linux=FakeLinux()
    engine=Engine(journal,Backend(docker,linux))
    first={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'first',
           'action':'start','expected_revision':0,'spec':{'kind':'linux',
           'image':'sha256:'+'a'*64,'container_name':'drsp-reserved'}}
    if resource=='published_port':
        first['spec'].update(management={'network':'mgmt','ipv4':'192.0.2.2'},
            ports=[{'host_ip':'127.0.0.1','host_port':18080,'container_port':80,'protocol':'tcp'}])
    try:
        first=planned_request(engine,first);journal.submit(first)
        second=deepcopy(first);second.pop('management_preflight',None)
        second.update(node_id='R2',request_id='second')
        if resource=='published_port':
            second['spec']['container_name']='drsp-other'
            second['spec']['management']['ipv4']='192.0.2.3'
        changes=journal.db.total_changes
        with pytest.raises(Conflict,match='resource reserved'):engine.plan(second)
        assert journal.db.total_changes==changes
        # For management, preserve the previously observed network without a
        # second successful plan, so admission itself is independently checked.
        if resource=='published_port':
            from dnlab_runtime.management_network import preflight
            second['management_preflight']=preflight(engine.backend,second,second['spec'])
        with pytest.raises(Conflict,match='resource reserved'):journal.submit(second)
        assert not docker.calls and not docker.containers and not linux.commands
        assert journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]==1
        assert journal.node('demo','R2') is None
    finally:journal.close()


def test_own_reservations_are_read_only_and_foreign_lab_container_is_refused(tmp_path):
    journal=Journal(tmp_path/'runtime');docker=FakeDocker();linux=FakeLinux()
    engine=Engine(journal,Backend(docker,linux))
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'first',
             'action':'start','expected_revision':0,'spec':{'kind':'linux',
             'image':'sha256:'+'a'*64,'container_name':'drsp-reserved'}}
    try:
        first=journal.submit(request);changes=journal.db.total_changes
        assert engine.plan(request)['mutations_performed'] is False
        assert journal.db.total_changes==changes
        other={**request,'lab_id':'another','request_id':'second'}
        with pytest.raises(Conflict,match='resource reserved'):engine.plan(other)
        # Once the original owner cancels with verified compensation, its name
        # becomes available; successful planning still creates no reservation.
        journal.cancel(first['id']);assert engine.execute(first['id'])['phase']=='cancelled'
        changes=journal.db.total_changes
        assert engine.plan(other)['mutations_performed'] is False
        assert journal.db.total_changes==changes
        assert not docker.calls and not linux.commands
    finally:journal.close()


def test_admission_rechecks_reservation_acquired_after_a_successful_plan(tmp_path):
    journal=Journal(tmp_path/'runtime');engine=Engine(journal,Backend(FakeDocker(),FakeLinux()))
    request={'schema_version':1,'lab_id':'demo','node_id':'R1','request_id':'first',
             'action':'start','expected_revision':0,'spec':{'kind':'linux',
             'image':'sha256:'+'a'*64,'container_name':'drsp-reserved'}}
    other={**request,'node_id':'R2','request_id':'second'}
    try:
        assert engine.plan(other)['mutations_performed'] is False
        journal.submit(request)
        with pytest.raises(Conflict,match='resource reserved'):journal.submit(other)
        assert journal.db.execute('SELECT count(*) FROM operations').fetchone()[0]==1
        assert engine.backend.docker.calls==[]
    finally:journal.close()
