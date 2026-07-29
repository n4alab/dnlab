"""Tests for deploy protection while teardown recovery is pending."""

from types import SimpleNamespace

import pytest

from dnlab_multinode.controllers import plan as plan_module
from dnlab_multinode.models.state import DeploymentState


def test_plan_refuses_deploy_while_teardown_is_pending(monkeypatch):
    monkeypatch.setattr(
        plan_module,
        "parse_topology",
        lambda *_args, **_kwargs: SimpleNamespace(name="demo"),
    )
    monkeypatch.setattr(
        plan_module.state_svc,
        "load_state",
        lambda *_args, **_kwargs: DeploymentState(
            lab_name="demo",
            topology_file="/tmp/demo.yml",
            teardown_requested=True,
        ),
    )

    with pytest.raises(plan_module.PlanError, match="pending teardown"):
        plan_module.PlanController("/tmp/demo.yml").run()
