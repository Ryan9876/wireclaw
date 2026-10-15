import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def rendered_compose():
    result = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            ".env.example",
            "-f",
            "compose.yaml",
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def test_rendered_compose_has_only_loopback_core_publication_and_persistent_mount():
    config = rendered_compose()
    assert set(config["services"]) == {"wireclaw-core"}
    core = config["services"]["wireclaw-core"]
    assert core["ports"] == [
        {
            "mode": "ingress",
            "host_ip": "127.0.0.1",
            "target": 8765,
            "published": "8765",
            "protocol": "tcp",
        }
    ]
    assert "network_mode" not in core
    assert not core.get("privileged", False)
    assert all("docker.sock" not in mount.get("source", "") for mount in core["volumes"])
    assert len(core["volumes"]) == 1
    assert core["volumes"][0]["type"] == "bind"
    assert core["volumes"][0]["target"] == "/var/lib/wireclaw"
    assert core["cap_drop"] == ["ALL"]
    assert core["security_opt"] == ["no-new-privileges:true"]
    assert core["read_only"] is True
    assert core["environment"]["WIRECLAW_PROVIDER_MODE"] == "none"
    assert "WIRECLAW_PROVIDER_API_KEY" in core["environment"]
    assert core["healthcheck"]["test"][0] == "CMD"
    assert "/api/health" in core["healthcheck"]["test"][-1]
    assert "WIRECLAW_PUBLIC_PORT" in core["healthcheck"]["test"][-1]
    assert all(port["published"] != "8767" for port in core["ports"])


def test_env_example_uses_rules_only_and_contains_no_secret():
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "WIRECLAW_PORT=8765" in env
    assert 'WIRECLAW_DATA_ROOT="${HOME}/Library/Application Support/Wireclaw/data"' in env
    assert "WIRECLAW_PROVIDER_MODE=none" in env
    assert "WIRECLAW_BRIDGE_PORT=8766" in env
    assert "API_KEY" not in env
    assert "sk-" not in env


def test_packaged_env_example_defaults_to_embedded_ai_without_token():
    env = (ROOT / "wireclaw-release/.env.example").read_text(encoding="utf-8")
    assert "WIRECLAW_PROVIDER_MODE=embedded_local" in env
    assert "WIRECLAW_AI_PORT=8767" in env
    assert "WIRECLAW_PROVIDER_API_KEY" not in env


def test_launcher_embedded_environment_is_ephemeral_and_has_rules_only_fallback(tmp_path):
    import os

    runtime = tmp_path / "Library/Application Support/Wireclaw/run"
    runtime.mkdir(parents=True)
    status = runtime / "ai-status"
    token_file = runtime / "ai-key"
    token_file.write_text("ephemeral-test-token\n", encoding="utf-8")
    status.write_text("ready\n", encoding="utf-8")
    env_file = tmp_path / ".env"
    env_file.write_text("WIRECLAW_PROVIDER_MODE=embedded_local\n", encoding="utf-8")
    script = (
        '. "$1/launch/macos/common.sh"; configure_provider_environment embedded_local "$2"; '
        'printf "%s\\n%s\\n%s\\n%s\\n%s\\n" "$WIRECLAW_PROVIDER_MODE" "$WIRECLAW_PROVIDER_BASE_URL" '
        '"$WIRECLAW_PROVIDER_MODEL" "$WIRECLAW_PROVIDER_API_KEY" "$WIRECLAW_EMBEDDED_AI_STATUS"'
    )
    result = subprocess.run(
        ["bash", "-c", script, "test", str(ROOT), str(env_file)],
        cwd=ROOT, env=os.environ | {"HOME": str(tmp_path)}, capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "embedded_local", "http://host.docker.internal:8767/v1",
        "wireclaw-qwen3-4b-instruct-2507-q4_k_m", "ephemeral-test-token", "ready",
    ]
    assert env_file.read_text() == "WIRECLAW_PROVIDER_MODE=embedded_local\n"


def test_failed_embedded_connectivity_selects_rules_only_environment():
    launcher = (ROOT / "launch/macos/common.sh").read_text(encoding="utf-8")
    start = (ROOT / "launch/macos/start.sh").read_text(encoding="utf-8")
    assert "host.docker.internal:8767/v1" in launcher
    assert 'ai_unavailable "docker-connectivity"' in start
    assert 'configure_provider_environment embedded_local' in start
    assert 'WIRECLAW_EMBEDDED_AI_STATUS' in launcher


def test_configured_cloud_provider_mode_is_not_overridden_by_embedded_state(tmp_path):
    import os

    script = (
        '. "$1/launch/macos/common.sh"; configure_provider_environment openai_compatible_cloud '
        'https://cloud.example/v1 cloud-model configured-cloud-key; '
        'printf "%s\\n%s\\n%s\\n%s\\n" "$WIRECLAW_PROVIDER_MODE" "$WIRECLAW_PROVIDER_BASE_URL" '
        '"$WIRECLAW_PROVIDER_MODEL" "$WIRECLAW_PROVIDER_API_KEY"'
    )
    result = subprocess.run(
        ["bash", "-c", script, "test", str(ROOT)], cwd=ROOT,
        env=os.environ | {"HOME": str(tmp_path), "WIRECLAW_PROVIDER_MODE": "embedded_local"},
        capture_output=True, text=True,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout.splitlines() == [
        "openai_compatible_cloud", "https://cloud.example/v1", "cloud-model", "configured-cloud-key",
    ]
