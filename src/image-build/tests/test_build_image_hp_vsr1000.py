from types import SimpleNamespace

import build_image


def test_hp_vsr1000_persistent_build_accepts_qco_and_applies_patch(monkeypatch, tmp_path):
    source = tmp_path / "VSR1000_HPE-CMW710-R0633P17-X64.qco"
    source.write_bytes(b"vsr-disk")
    work_dir = tmp_path / "vrnetlab" / "hp" / "vsr1000"
    work_dir.mkdir(parents=True)
    calls: list[list[str]] = []

    monkeypatch.setattr(build_image, "_resolve_vrnetlab_dir", lambda _kind, _root: work_dir)
    monkeypatch.setattr(build_image, "image_globs_for", lambda _dir: ["*.qco"])
    monkeypatch.setattr(
        build_image, "_docker_tag_for", lambda _dir, _name: "vrnetlab/hp_vsr1000:7.10-R0633"
    )
    monkeypatch.setattr(build_image, "_make_build_cmd", lambda _dir: ["make", "docker-image"])
    monkeypatch.setattr(build_image, "_run", lambda cmd, **_kwargs: calls.append(cmd))

    args = SimpleNamespace(
        kind="hp_vsr1000", source=str(source), vrnetlab_root=str(tmp_path / "vrnetlab"),
        with_persistence=True, keep_upstream=False, force=False, dry_run=True,
    )
    assert build_image.cmd_build(args) == 0

    assert [
        build_image.sys.executable, str(build_image.APPLY_SCRIPT), "hp_vsr1000",
        "vrnetlab/hp_vsr1000:7.10-R0633",
    ] in calls
