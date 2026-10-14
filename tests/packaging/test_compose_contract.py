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


def test_env_example_uses_rules_only_and_contains_no_secret():
    env = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert "WIRECLAW_PORT=8765" in env
    assert 'WIRECLAW_DATA_ROOT="${HOME}/Library/Application Support/Wireclaw/data"' in env
    assert "WIRECLAW_PROVIDER_MODE=none" in env
    assert "WIRECLAW_BRIDGE_PORT=8766" in env
    assert "API_KEY" not in env
    assert "sk-" not in env
