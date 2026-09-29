import pytest

from app.services import device_catalog
from app.views.api.docker_routes import _remote_image


def _remote(repository: str):
    return _remote_image(
        {
            "repository": repository,
            "tag": "latest",
            "image_id": "sha256:abc",
            "kind": "linux",
            "vendor": "linux",
        }
    )


@pytest.mark.parametrize(
    "repository, expected_kind",
    [
        ("vrnetlab/juniper_apstra", "juniper_apstra"),
        ("vrnetlab/dnlab_opnsense", "dnlab_opnsense"),
        ("vrnetlab/n4alab_flinos", "flinos"),
        ("vrnetlab/nvidia_cumulusvx", "nvidia_cumulusvx"),
        ("vrnetlab/dnlab_frr", "frr"),
    ],
)
def test_remote_image_exposes_gui_catalog_kind(repository, expected_kind):
    image = _remote(repository)
    assert image.kind == expected_kind


@pytest.mark.parametrize(
    "repository, expected_kind",
    [
        ("vrnetlab/juniper_apstra", "juniper_apstra"),
        ("vrnetlab/dnlab_opnsense", "dnlab_opnsense"),
        ("vrnetlab/n4alab_flinos", "flinos"),
        ("vrnetlab/nvidia_cumulusvx", "nvidia_cumulusvx"),
        ("vrnetlab/dnlab_frr", "frr"),
    ],
)
def test_local_docker_service_resolves_gui_catalog_kind(repository, expected_kind):
    kind, _vendor = device_catalog.resolve_kind_and_vendor(repository)
    assert kind == expected_kind
