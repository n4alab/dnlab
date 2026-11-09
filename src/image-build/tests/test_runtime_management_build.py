import json
import sys
from types import SimpleNamespace

import pytest

import apply
from test_runtime_management_patch import SOURCE


def fixture_builder(monkeypatch, tmp_path, *, labels=None, source=SOURCE):
    monkeypatch.setattr(sys, "argv", ["apply.py", "cisco_n9kv", "vendor:raw", "--runtime-management", "--runtime-management-python=uv", "--tag-suffix=-runtime-spike"])
    monkeypatch.setattr(apply, "_image_exists_locally", lambda image: True)
    monkeypatch.setattr(apply, "_image_identity", lambda image: "sha256:fixture")
    monkeypatch.setattr(apply, "_run", lambda *a, **kw: SimpleNamespace(stdout=json.dumps([{"Config": {"Labels": labels or {}}}])))
    module = SimpleNamespace(KIND="cisco_n9kv", FILES=[], apply=lambda target, text: (text, []))
    monkeypatch.setattr(apply.importlib, "import_module", lambda name: module)
    monkeypatch.setattr(apply.warm_links, "profile_for", lambda *args: None)
    monkeypatch.setattr(apply.warm_links, "validation_status", lambda *args: "unqualified")
    extracted, builds = [], []
    def extract(image, targets, dest):
        extracted.extend(targets)
        for target in targets:
            (dest / target.rsplit("/", 1)[-1]).write_text(source)
    monkeypatch.setattr(apply, "_extract_files", extract)
    def build(*args, **kwargs):
        builds.append((args[1], kwargs, args[3]["/vrnetlab.py"].read_text()))
    monkeypatch.setattr(apply, "_build_patched", build)
    return extracted, builds


def test_candidate_extracts_shared_launcher_and_enables_only_explicit_abi(monkeypatch, tmp_path):
    extracted, builds = fixture_builder(monkeypatch, tmp_path)
    assert apply.main() == 0
    assert extracted == ["/vrnetlab.py"]
    assert builds[0][0] == "vendor:raw-runtime-spike"
    assert builds[0][1]["runtime_management"] is True
    assert builds[0][1]["runtime_management_python"] == "uv"
    assert "DNLAB_RUNTIME_BOOT_WAIT" in builds[0][2]


@pytest.mark.parametrize("suffix", ["", "-dnlab"])
def test_separate_candidate_tag_required_before_docker(monkeypatch, suffix):
    monkeypatch.setattr(sys, "argv", ["apply.py", "cisco_n9kv", "vendor:raw", "--runtime-management", "--tag-suffix=" + suffix])
    monkeypatch.setattr(apply, "_image_exists_locally", lambda image: pytest.fail("must not access Docker"))
    with pytest.raises(SystemExit) as error:
        apply.main()
    assert error.value.code == 2


def test_patched_upstream_is_rejected_before_extraction(monkeypatch, tmp_path):
    extracted, builds = fixture_builder(monkeypatch, tmp_path, labels={"org.dnlab.patch.kind": "cisco_n9kv"})
    assert apply.main() == 2
    assert extracted == builds == []


def test_unlabelled_patched_source_is_also_rejected(monkeypatch, tmp_path):
    _, builds = fixture_builder(monkeypatch, tmp_path, source=SOURCE + "\n# dnlab-patched: persist-overlay-v1\n")
    with pytest.raises(RuntimeError, match="unpatched upstream"):
        apply.main()
    assert builds == []


@pytest.mark.parametrize("enabled", [False, True])
def test_candidate_label_is_unqualified_and_absent_on_default_build(monkeypatch, tmp_path, enabled):
    monkeypatch.setattr(apply, "_run", lambda *args, **kwargs: None)
    apply._build_patched("vendor:raw", "vendor:output", tmp_path, {}, kind="fixture", upstream_identity="sha256:fixture", dnlab_version="test", generated_at="test", warm_profile=None, warm_status="unqualified", runtime_management=enabled, runtime_management_python="uv" if enabled else None)
    dockerfile = (tmp_path / "Dockerfile").read_text()
    assert ("runtime-management-v1" in dockerfile) is enabled
    assert ("experimental-unqualified" in dockerfile) is enabled
    assert ("org.dnlab.runtime-management.python" in dockerfile) is enabled


@pytest.mark.parametrize('arguments', [
    ['--runtime-management', '--tag-suffix=-runtime-spike'],
    ['--runtime-management-python=uv'],
])
def test_candidate_python_contract_required_before_docker(monkeypatch, arguments):
    monkeypatch.setattr(sys, 'argv', ['apply.py', 'cisco_n9kv', 'vendor:raw', *arguments])
    monkeypatch.setattr(apply, '_image_exists_locally', lambda image: pytest.fail('must not access Docker'))
    with pytest.raises(SystemExit) as error:
        apply.main()
    assert error.value.code == 2


@pytest.mark.parametrize("kind", ["cisco_vios", "cisco_n9kv"])
def test_standard_nos_build_also_adapts_retired_common_keyword(monkeypatch, tmp_path, kind):
    extracted, builds = fixture_builder(monkeypatch, tmp_path)
    monkeypatch.setattr(sys, "argv", ["apply.py", kind, "vendor:raw"])
    launcher = "class Device(VM):\n    def __init__(self):\n        super(Device, self).__init__(\n            use_scrapli=True,\n        )\n"
    module = SimpleNamespace(KIND=kind, FILES=["/vrnetlab.py", "/launch.py"], apply=lambda target, text: (text, []))
    monkeypatch.setattr(apply.importlib, "import_module", lambda name: module)
    def extract(image, targets, dest):
        (dest / "vrnetlab.py").write_text("class VM:\n    def __init__(self): pass\n")
        (dest / "launch.py").write_text(launcher)
    monkeypatch.setattr(apply, "_extract_files", extract)
    results = []
    def build(*args, **kwargs):
        results.append((args[3]["/launch.py"].read_text(), kwargs["runtime_management"]))
    monkeypatch.setattr(apply, "_build_patched", build)
    assert apply.main() == 0
    assert "use_scrapli=True" not in results[0][0]
    assert results[0][1] is False


@pytest.mark.parametrize('arguments', [
    ['cisco_vios', '--runtime-selected-management'],
    ['cisco_n9kv', '--runtime-selected-management', '--runtime-management', '--runtime-management-python=uv', '--tag-suffix=-selected-spike'],
])
def test_selected_management_rejects_missing_barrier_or_oob_kind_before_docker(monkeypatch, arguments):
    monkeypatch.setattr(sys,'argv',['apply.py',arguments[0],'vendor:raw',*arguments[1:]])
    monkeypatch.setattr(apply,'_image_exists_locally',lambda image:pytest.fail('must not access Docker'))
    with pytest.raises(SystemExit) as error:
        apply.main()
    assert error.value.code == 2


def test_selected_management_builder_copies_helper_and_labels_only_explicit_candidate(monkeypatch,tmp_path):
    monkeypatch.setattr(apply,'_run',lambda *a,**kw:None)
    apply._build_patched('vendor:raw','vendor:selected',tmp_path,{},kind='cisco_vios',upstream_identity='sha256:fixture',dnlab_version='test',generated_at='test',warm_profile={'default_ports':15,'max_ports':15,'vm_index':0},warm_status='unqualified',runtime_management=True,runtime_management_python='system',runtime_selected_management=True)
    dockerfile=(tmp_path/'Dockerfile').read_text()
    assert 'COPY runtime_selected_management.py /runtime_selected_management.py' in dockerfile
    assert 'runtime-selected-management-v1' in dockerfile
    assert (tmp_path/'runtime_selected_management.py').read_bytes() == (apply.Path(apply.__file__).parent/'runtime_selected_management.py').read_bytes()
