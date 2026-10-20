from pathlib import Path

from scripts import validate_gate3


def test_gate3_temporary_directory_resolves_symlinked_platform_temp(
    tmp_path, monkeypatch
):
    physical_base = tmp_path / "physical-temp"
    physical_base.mkdir()
    platform_temp = tmp_path / "platform-temp"
    platform_temp.symlink_to(physical_base, target_is_directory=True)
    monkeypatch.setattr(validate_gate3.tempfile, "gettempdir", lambda: str(platform_temp))

    with validate_gate3.gate3_temporary_directory() as temporary:
        temporary_root = Path(temporary)
        assert temporary_root.parent == physical_base
        assert temporary_root.is_dir()
        assert not any(path.is_symlink() for path in (temporary_root, *temporary_root.parents))

    assert not temporary_root.exists()
