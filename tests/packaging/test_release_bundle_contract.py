from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
PACKAGER = (ROOT / "scripts/package_release.py").read_text(encoding="utf-8")
CONTAINER_VALIDATOR = (ROOT / "scripts/validate_container_release.py").read_text(encoding="utf-8")


def test_release_stager_includes_the_production_build_context_and_native_launchers():
    for required in (
        '"Dockerfile"',
        '"compose.yaml"',
        '".env.example"',
        '".dockerignore"',
        '"docker"',
        '"contracts"',
        '"services/analyzer/src/wireclaw_analyzer"',
        '"services/api/src/wireclaw_api"',
        '"launch/macos"',
    ):
        assert required in PACKAGER
    assert '"host-bridge/macos"' in PACKAGER
    assert '"README.md"' in PACKAGER


def test_release_readme_documents_staged_bundle_and_platform_scope():
    readme = (ROOT / "wireclaw-release/README.md").read_text(encoding="utf-8")
    assert "macOS arm64" in readme
    assert "host-bridge/macos" in readme
    assert "launch/macos/start.sh" in readme
    assert "Windows and Linux are future qualification targets, not supported V1 hosts" in readme


def test_container_acceptance_reuses_the_prebuilt_image_for_release_identity():
    assert 'command.extend(["-d", "--no-build"])' in CONTAINER_VALIDATOR
    assert 'compose(env, "up")' in CONTAINER_VALIDATOR
