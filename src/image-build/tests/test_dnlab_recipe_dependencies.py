"""Regression tests for dNLab vrnetlab recipe runtime dependencies."""

import ast
from pathlib import Path


VRNETLAB_ROOT = Path("/opt/vrnetlab")


def test_debian_runtime_recipes_install_scrapli_for_shared_vrnetlab_helper():
    """Custom Debian images must satisfy common/vrnetlab.py's Scrapli import."""
    recipes = {
        "dnlab/opnsense/docker/Dockerfile": "debian:trixie-slim",
        "dnlab/frr/docker/Dockerfile": "debian:13-slim",
    }

    for recipe, base_image in recipes.items():
        dockerfile = VRNETLAB_ROOT / recipe
        contents = dockerfile.read_text(encoding="utf-8")

        assert f"FROM public.ecr.aws/docker/library/{base_image}" in contents
        assert "COPY vrnetlab.py /vrnetlab.py" in contents or "COPY --chmod=0755 *.py /" in contents
        assert "python3-scrapli" in contents
        assert "python3-pkg-resources" in contents


def test_opnsense_bootstrap_drain_never_blocks_on_the_serial_console():
    """Scrapli cannot emulate telnetlib's non-blocking read_very_eager API."""
    launcher = VRNETLAB_ROOT / "dnlab/opnsense/docker/launch.py"
    module = ast.parse(launcher.read_text(encoding="utf-8"))
    vm_class = next(node for node in module.body if isinstance(node, ast.ClassDef) and node.name == "DNLabOpnsenseVM")
    drain = next(node for node in vm_class.body if isinstance(node, ast.FunctionDef) and node.name == "_drain")

    attributes = [node.attr for node in ast.walk(drain) if isinstance(node, ast.Attribute)]
    assert "read_very_eager" not in attributes
