from pathlib import Path
import subprocess

import pytest


_SCRIPT = (
    Path(__file__).resolve().parents[1]
    / "deploy/apache/docker/validate-webui-hostname.sh"
)
_PROXY_TEMPLATE = (
    Path(__file__).resolve().parents[1]
    / "deploy/apache/docker/dnlab-gui-prod.conf.template"
)
_APP_JS = Path(__file__).resolve().parents[1] / "app/views/static/js/app.js"


@pytest.mark.parametrize("hostname", ["dnlab.example.test", "lab.internal.example"])
def test_webui_hostname_validator_accepts_fqdn(hostname):
    assert subprocess.run([str(_SCRIPT), hostname], check=False).returncode == 0


@pytest.mark.parametrize("hostname", [
    "192.0.2.10", "2001:db8::10", "localhost", "dnlab", ".dnlab.example",
    "dnlab.example.", "dnlab..example", "bad_name.example",
])
def test_webui_hostname_validator_rejects_non_fqdn(hostname):
    assert subprocess.run([str(_SCRIPT), hostname], check=False).returncode != 0


def test_proxy_keeps_gui_routing_when_webui_aliases_are_disabled():
    template = _PROXY_TEMPLATE.read_text(encoding="utf-8")

    # The entrypoint substitutes this with either a wildcard ServerAlias or a
    # comment.  In both cases the regular GUI proxy vhosts remain in place.
    assert template.count("${DNLAB_PROXY_WEBUI_SERVER_ALIAS}") == 2
    assert template.count("${DNLAB_PROXY_APACHE_SERVER_NAME_DIRECTIVE}") == 3
    assert 'ProxyPass "/" "http://dnlab-gui:8080/"' in template
    assert "FallbackResource" not in template


def test_browser_opens_webui_unavailable_page_without_configuration_toast():
    app_js = _APP_JS.read_text(encoding="utf-8")
    assert "WindowManager.open('/webui/unavailable'" in app_js
    assert "Opening tunnel WebUI" not in app_js
    assert "matching TLS certificate" not in app_js
