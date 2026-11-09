"""The machine-readable cleanup report must bypass Rich rendering."""
import json
from types import SimpleNamespace

from click.testing import CliRunner
import pytest
from rich.console import Console

from dnlab_multinode import cli
from dnlab_multinode.services import hosts_config, lab_cleanup


@pytest.mark.parametrize("width", [20, 80])
@pytest.mark.parametrize("dry_run", [True, False])
def test_cleanup_json_preserves_long_ids_and_rich_literals(monkeypatch, width, dry_run):
    data = {
        "dry_run": dry_run,
        "command": "docker rm -f " + "b" * 64,
        "reason": "[red]literal[/red] [link=https://example.invalid]text[/link]",
        "message": "line one\nline two\twith quotes: \" and Unicode: è",
        "errors": [],
    }
    calls = []

    def reconcile(hosts, **kwargs):
        calls.append(kwargs)
        return SimpleNamespace(to_dict=lambda: data)

    monkeypatch.setattr(cli, "_setup_logging", lambda *args: None)
    monkeypatch.setattr(cli, "console", Console(width=width, force_terminal=True))
    monkeypatch.setattr(hosts_config, "load_hosts_config", lambda _: object())
    monkeypatch.setattr(lab_cleanup, "reconcile_once", reconcile)
    result = CliRunner().invoke(
        cli.main, ["cleanup-labs", "--json", "--dry-run" if dry_run else "--execute"]
    )

    assert result.exit_code == 0, result.output
    assert result.stderr == ""
    assert json.loads(result.stdout) == data
    assert result.stdout == json.dumps(data, indent=2, sort_keys=True) + "\n"
    assert calls[0]["dry_run"] is dry_run
