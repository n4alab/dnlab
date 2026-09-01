import pytest

from dnlab_multinode.services import images


def test_runtime_images_default_to_local_latest(monkeypatch):
    monkeypatch.delenv("DNLAB_VERSION", raising=False)
    monkeypatch.delenv("DNLAB_IMAGE_PREFIX", raising=False)
    monkeypatch.delenv("DNLAB_RUNTIME_IMAGE_PREFIX", raising=False)

    assert images.runtime_images() == {
        "jumphost": "dnlab-jumphost:latest",
        "dns": "dnlab-dns:latest",
        "runtime-relay": "dnlab-runtime-relay:latest",
        "realnet-router": "dnlab-realnet-router:latest",
        "realnet-rr": "dnlab-realnet-rr:latest",
        "mgmt-anchor": "dnlab-mgmt-anchor:latest",
    }


def test_runtime_images_can_use_release_version(monkeypatch):
    monkeypatch.setenv("DNLAB_VERSION", "0.1.0")
    monkeypatch.setenv("DNLAB_RUNTIME_IMAGE_PREFIX", "dnlab-")

    assert images.runtime_images() == {
        "jumphost": "dnlab-jumphost:0.1.0",
        "dns": "dnlab-dns:0.1.0",
        "runtime-relay": "dnlab-runtime-relay:0.1.0",
        "realnet-router": "dnlab-realnet-router:0.1.0",
        "realnet-rr": "dnlab-realnet-rr:0.1.0",
        "mgmt-anchor": "dnlab-mgmt-anchor:0.1.0",
    }


def test_ghcr_runtime_prefix_uses_distribution_image_names(monkeypatch):
    monkeypatch.setenv("DNLAB_VERSION", "0.1.0")
    monkeypatch.setenv("DNLAB_RUNTIME_IMAGE_PREFIX", "ghcr.io/n4alab/dnlab-")

    assert (
        images.image_for("realnet-rr")
        == "ghcr.io/n4alab/dnlab-realnet-rr:0.1.0"
    )


def test_runtime_prefix_can_be_derived_from_image_prefix(monkeypatch):
    monkeypatch.setenv("DNLAB_VERSION", "0.1.0")
    monkeypatch.setenv("DNLAB_IMAGE_PREFIX", "ghcr.io/n4alab/")
    monkeypatch.delenv("DNLAB_RUNTIME_IMAGE_PREFIX", raising=False)

    assert (
        images.image_for("realnet-rr")
        == "ghcr.io/n4alab/dnlab-realnet-rr:0.1.0"
    )


def test_unknown_component_is_rejected():
    with pytest.raises(ValueError, match="unknown dNLab image component"):
        images.image_for("postgres")
