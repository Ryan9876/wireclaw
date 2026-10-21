import json
import os
import shlex
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
LAUNCH = ROOT / "launch/macos"
START_SOURCE = (LAUNCH / "start.sh").read_text(encoding="utf-8")


def run_bash(script: str, *args: str, env: dict[str, str] | None = None):
    return subprocess.run(
        ["bash", "-c", script, "wireclaw-test", *args],
        cwd=ROOT,
        env=os.environ | (env or {}),
        capture_output=True,
        text=True,
    )


def make_release(root: Path, env_text: str):
    release = root / "release"
    shutil.copytree(LAUNCH, release / "launch/macos")
    (release / ".env.example").write_text(env_text, encoding="utf-8")
    (release / ".env").write_text(env_text, encoding="utf-8")
    (release / "compose.yaml").write_text("services: {}\n", encoding="utf-8")
    (release / "core-image-id").write_text("sha256:" + "a" * 64 + "\n", encoding="utf-8")
    (release / "core-image.tar").write_bytes(b"packaged image archive")
    return release


def make_fake_tools(root: Path, *, daemon=True, compose=True, busy_port=""):
    bin_dir = root / "fake-bin"
    bin_dir.mkdir(exist_ok=True)
    docker = bin_dir / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case "$1 $2" in\n'
        f'  "compose version") exit {0 if compose else 1} ;;\n'
        f'  "info "*) exit {0 if daemon else 1} ;;\n'
        '  "image inspect") [ -f "$WIRECLAW_TEST_IMAGE_STATE" ] && cat "$WIRECLAW_TEST_IMAGE_STATE" || exit 1 ;;\n'
        '  "load --input") printf "%s\\n" "$WIRECLAW_TEST_IMAGE_ID" > "$WIRECLAW_TEST_IMAGE_STATE"; printf "%s\\n" "$*" >> "$WIRECLAW_TEST_DOCKER_LOG" ;;\n'
        '  *"inspect --format"*) printf "healthy\\n" ;;\n'
        '  *" ps -q wireclaw-core"*) printf "fake-container\\n" ;;\n'
        '  *) printf "%s\\n" "$*" >> "$WIRECLAW_TEST_DOCKER_LOG"; exit 0 ;;\n'
        "esac\n",
        encoding="utf-8",
    )
    docker.chmod(0o700)
    lsof = bin_dir / "lsof"
    lsof.write_text(
        "#!/bin/sh\n"
        'if [ -n "$WIRECLAW_TEST_BUSY_PORT" ]; then\n'
        '  case "$*" in *"$WIRECLAW_TEST_BUSY_PORT"*) exit 0 ;; esac\n'
        "fi\nexit 1\n",
        encoding="utf-8",
    )
    lsof.chmod(0o700)
    fake_uname = bin_dir / "uname"
    fake_uname.write_text("#!/bin/sh\nprintf 'arm64\\n'\n", encoding="utf-8")
    fake_uname.chmod(0o700)
    log = root / "docker-calls.log"
    env = {
        "HOME": str(root / "home"),
        "PATH": f"{bin_dir}:/usr/bin:/bin",
        "WIRECLAW_TEST_DOCKER_LOG": str(log),
        "WIRECLAW_TEST_BUSY_PORT": busy_port,
        "WIRECLAW_TEST_IMAGE_ID": "sha256:" + "a" * 64,
        "WIRECLAW_TEST_IMAGE_STATE": str(root / "image-id"),
    }
    return env, log


def install_stub_bridge(home: Path):
    binary = home / "Library/Application Support/Wireclaw/bin/wireclaw-host-bridge"
    binary.parent.mkdir(parents=True, exist_ok=True)
    binary.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    binary.chmod(0o700)
    return binary


def test_env_parser_handles_home_and_paths_with_spaces(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        'WIRECLAW_DATA_ROOT="${HOME}/Library/Application Support/Wireclaw data"\n',
        encoding="utf-8",
    )
    result = run_bash(
        '. "$1/launch/macos/common.sh"; read_env_value WIRECLAW_DATA_ROOT "$2"',
        str(ROOT),
        str(env_file),
        env={"HOME": str(tmp_path / "User Home")},
    )
    assert result.returncode == 0
    assert result.stdout == f"{tmp_path}/User Home/Library/Application Support/Wireclaw data"


def test_env_parser_rejects_shell_substitution_without_executing_it(tmp_path):
    marker = tmp_path / "should-not-exist"
    env_file = tmp_path / ".env"
    env_file.write_text(f"WIRECLAW_PORT=$(touch {marker})\n", encoding="utf-8")
    result = run_bash(
        '. "$1/launch/macos/common.sh"; read_env_value WIRECLAW_PORT "$2"',
        str(ROOT),
        str(env_file),
        env={"HOME": str(tmp_path)},
    )
    assert result.returncode != 0
    assert not marker.exists()


def test_release_loads_the_exact_packaged_image_and_skips_an_existing_match(tmp_path):
    release = make_release(tmp_path, "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n")
    image_id = "sha256:" + "a" * 64
    (release / "core-image-id").write_text(image_id + "\n", encoding="utf-8")
    (release / "core-image.tar").write_bytes(b"packaged image archive")
    env, log = make_fake_tools(tmp_path)
    script = '. "$1/launch/macos/common.sh"; load_release_image "$1"'
    result = run_bash(script, str(release), env=env)
    assert result.returncode == 0, result.stderr
    calls = log.read_text(encoding="utf-8")
    assert "load --input" in calls
    assert "core-image.tar" in calls

    Path(env["WIRECLAW_TEST_DOCKER_LOG"]).write_text("", encoding="utf-8")
    Path(env["WIRECLAW_TEST_IMAGE_STATE"]).write_text(image_id + "\n", encoding="utf-8")
    result = run_bash(script, str(release), env=env)
    assert result.returncode == 0, result.stderr
    assert "load --input" not in Path(env["WIRECLAW_TEST_DOCKER_LOG"]).read_text(encoding="utf-8")


@pytest.mark.parametrize("missing", ("core-image.tar", "core-image-id"))
def test_release_image_missing_packaged_artifact_fails_without_acquisition(tmp_path, missing):
    release = make_release(tmp_path, "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n")
    (release / missing).unlink()
    env, log = make_fake_tools(tmp_path)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; load_release_image "$1"',
        str(release),
        env=env,
    )
    assert result.returncode != 0
    assert not log.exists() or log.read_text(encoding="utf-8") == ""


def test_release_image_identity_mismatch_fails_without_external_recovery(tmp_path):
    release = make_release(tmp_path, "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n")
    (release / "core-image-id").write_text("sha256:" + "b" * 64 + "\n", encoding="utf-8")
    env, log = make_fake_tools(tmp_path)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; load_release_image "$1"',
        str(release),
        env=env,
    )
    assert result.returncode != 0
    calls = log.read_text(encoding="utf-8")
    assert "load --input" in calls
    assert "pull" not in calls
    assert "build" not in calls


def test_bridge_health_probe_uses_the_approved_application_origin():
    assert 'curl --silent --fail --header "Origin: http://127.0.0.1:$APP_PORT"' in START_SOURCE
    assert '"http://127.0.0.1:$BRIDGE_PORT/v1/health"' in START_SOURCE


def test_runtime_state_path_rejects_symlinked_ancestor(tmp_path):
    home = tmp_path / "User Home"
    library = home / "Library"
    library.mkdir(parents=True)
    outside = tmp_path / "outside-runtime"
    outside.mkdir()
    (library / "Application Support").symlink_to(outside, target_is_directory=True)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; validate_runtime_path',
        str(ROOT),
        env={"HOME": str(home)},
    )
    assert result.returncode != 0


def test_ai_listener_match_requires_the_owned_loopback_socket():
    script = """
. "$1/launch/macos/common.sh"
lsof() { printf '%s\\n' "$WIRECLAW_TEST_SOCKET"; }
ai_listener_matches 1234 8767
"""
    for socket_name, expected in (("n127.0.0.1:8767", 0), ("n0.0.0.0:8767", 1)):
        result = run_bash(
            script,
            str(ROOT),
            env={"WIRECLAW_TEST_SOCKET": socket_name},
        )
        assert result.returncode == expected


def test_ai_stop_without_state_is_idempotent(tmp_path):
    env, _ = make_fake_tools(tmp_path)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; stop_ai && stop_ai',
        str(ROOT),
        env=env,
    )
    assert result.returncode == 0, result.stderr


def test_start_loads_and_uses_the_packaged_image_without_rebuilding():
    common = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    assert 'load_release_image "$RELEASE_DIR"' in START_SOURCE
    assert 'compose_start_core "$RELEASE_DIR" "$ENV_FILE" "$PROVIDER_MODE"' in START_SOURCE
    assert 'image_archive="$release_dir/core-image.tar"' in common
    assert 'docker load --input "$image_archive"' in common
    assert "docker pull" not in START_SOURCE + common
    assert "docker build" not in START_SOURCE + common
    assert "up -d --force-recreate" in common
    assert "up -d --build" not in START_SOURCE


def test_core_compose_key_handoff_rotation_and_shutdown_contract(tmp_path):
    common = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    start = (LAUNCH / "start.sh").read_text(encoding="utf-8")
    stop = (LAUNCH / "stop.sh").read_text(encoding="utf-8")
    assert "compose_with_provider_environment" in common
    assert "compose_start_core" in start
    assert "--force-recreate" in common
    assert "down --remove-orphans" in stop
    embedded_config = common.split('if [ "$status" = ready ]', 1)[1].split(
        "probe_ai_from_core()", 1
    )[0]
    assert "unset WIRECLAW_PROVIDER_API_KEY" in embedded_config
    assert 'wireclaw_compose_api_key="$wireclaw_ai_start_key"' in embedded_config

    persistent = tmp_path / "case-data"
    persistent.mkdir()
    release = make_release(
        tmp_path,
        f"WIRECLAW_PROVIDER_MODE=embedded_local\nWIRECLAW_DATA_ROOT={persistent}\n",
    )
    (release / "compose.yaml").write_bytes((ROOT / "compose.yaml").read_bytes())
    metadata = tmp_path / "docker-containers"
    metadata.mkdir()
    generation = tmp_path / "docker-generation"
    fake_env, _ = make_fake_tools(tmp_path)
    docker = Path(fake_env["PATH"].split(":", 1)[0]) / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$WIRECLAW_TEST_DOCKER_ARGS"\n'
        'printf "%s" "${WIRECLAW_PROVIDER_API_KEY-<unset>}" > "$WIRECLAW_TEST_DOCKER_ENV"\n'
        'case " $* " in\n'
        '  *" up "*)\n'
        '    [ "${*}" = "${*#*--force-recreate}" ] && exit 9\n'
        '    count=0; [ ! -f "$WIRECLAW_TEST_DOCKER_GENERATION" ] || count=$(cat "$WIRECLAW_TEST_DOCKER_GENERATION")\n'
        '    count=$((count + 1)); printf "%s" "$count" > "$WIRECLAW_TEST_DOCKER_GENERATION"\n'
        '    rm -f "$WIRECLAW_TEST_DOCKER_METADATA"/*\n'
        '    cp "$WIRECLAW_TEST_DOCKER_ENV" "$WIRECLAW_TEST_DOCKER_METADATA/container-$count.env" ;;\n'
        '  *" ps -q wireclaw-core"*) printf "container\\n" ;;\n'
        '  *"inspect --format"*) printf "healthy\\n" ;;\n'
        '  *" down "*) rm -f "$WIRECLAW_TEST_DOCKER_METADATA"/* ;;\n'
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o700)
    case_db = persistent / "cases.sqlite3"
    case_db.write_bytes(b"preserve")
    assets = release / "ai/assets/model.gguf"
    assets.parent.mkdir(parents=True)
    assets.write_bytes(b"model")
    fake_env.update(
        {
            "WIRECLAW_TEST_DOCKER_ARGS": str(tmp_path / "docker-args"),
            "WIRECLAW_TEST_DOCKER_ENV": str(tmp_path / "docker-env"),
            "WIRECLAW_TEST_DOCKER_METADATA": str(metadata),
            "WIRECLAW_TEST_DOCKER_GENERATION": str(generation),
        }
    )
    script = r"""
. "$1/launch/macos/common.sh"
wireclaw_compose_api_key="$2"
WIRECLAW_PROVIDER_MODE=embedded_local
compose_start_core "$1" "$1/.env" embedded_local
"""
    first_key = "1" * 64
    second_key = "2" * 64
    for key in (first_key, second_key):
        result = run_bash(script, str(release), key, env=fake_env)
        assert result.returncode == 0, result.stderr
        assert key not in result.stdout + result.stderr
        containers = list(metadata.glob("*.env"))
        assert len(containers) == 1
        assert containers[0].read_text(encoding="utf-8") == key
    assert generation.read_text(encoding="utf-8") == "2"
    args = Path(fake_env["WIRECLAW_TEST_DOCKER_ARGS"]).read_text(encoding="utf-8")
    assert first_key not in args and second_key not in args
    assert second_key in next(metadata.glob("*.env")).read_text(encoding="utf-8")
    assert "--force-recreate" in args
    env_file = release / ".env"
    assert first_key not in env_file.read_text(encoding="utf-8")
    assert second_key not in env_file.read_text(encoding="utf-8")
    compose_config = subprocess.run(
        [
            "docker",
            "compose",
            "--env-file",
            str(env_file),
            "-f",
            str(release / "compose.yaml"),
            "config",
            "--format",
            "json",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    )
    configured_core = json.loads(compose_config.stdout)["services"]["wireclaw-core"]
    assert configured_core["volumes"][0]["source"] == str(persistent)

    result = subprocess.run(
        ["bash", str(release / "launch/macos/stop.sh")],
        cwd=release,
        env=os.environ | fake_env,
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, result.stderr
    assert not list(metadata.glob("*.env")), (
        "Docker-managed key metadata must be removed with the container"
    )
    assert "down --remove-orphans" in Path(fake_env["WIRECLAW_TEST_DOCKER_ARGS"]).read_text(
        encoding="utf-8"
    )
    assert case_db.read_bytes() == b"preserve"
    assert assets.read_bytes() == b"model"


def test_core_recreate_failure_retries_without_key_and_normalizes_errors(tmp_path):
    release = make_release(tmp_path, "")
    fake_env, _ = make_fake_tools(tmp_path)
    metadata = tmp_path / "docker-containers"
    metadata.mkdir()
    marker = tmp_path / "first-up"
    docker = Path(fake_env["PATH"].split(":", 1)[0]) / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s\\n" "$*" >> "$WIRECLAW_TEST_DOCKER_ARGS"\n'
        'case " $* " in\n'
        '  *" up "*)\n'
        '    if [ ! -f "$WIRECLAW_TEST_FIRST_UP" ]; then\n'
        '      printf "%s" "${WIRECLAW_PROVIDER_API_KEY-}" > "$WIRECLAW_TEST_METADATA/failed.env"\n'
        '      printf "compose failed for key %s\\n" "${WIRECLAW_PROVIDER_API_KEY-}" >&2\n'
        '      touch "$WIRECLAW_TEST_FIRST_UP"; exit 1\n'
        "    fi\n"
        '    printf "%s" "${WIRECLAW_PROVIDER_API_KEY-}" > "$WIRECLAW_TEST_METADATA/fallback.env" ;;\n'
        '  *" rm "*) rm -f "$WIRECLAW_TEST_METADATA"/* ;;\n'
        '  *" ps -q wireclaw-core"*) printf "container\\n" ;;\n'
        '  *"inspect --format"*) printf "healthy\\n" ;;\n'
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o700)
    fake_env.update(
        {
            "WIRECLAW_TEST_DOCKER_ARGS": str(tmp_path / "docker-args"),
            "WIRECLAW_TEST_METADATA": str(metadata),
            "WIRECLAW_TEST_FIRST_UP": str(marker),
        }
    )
    runtime = Path(fake_env["HOME"]) / "Library/Application Support/Wireclaw/run"
    runtime.mkdir(parents=True)
    key = "f" * 64
    script = r"""
. "$1/launch/macos/common.sh"
wireclaw_compose_api_key="$2"
WIRECLAW_PROVIDER_MODE=embedded_local
stop_ai() { return 0; }
compose_start_core "$1" "$1/.env" embedded_local
printf 'MODE:%s KEY:%s' "$WIRECLAW_PROVIDER_MODE" "${WIRECLAW_PROVIDER_API_KEY:-}"
"""
    result = run_bash(script, str(release), key, env=fake_env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("MODE:none KEY:")
    assert key not in result.stdout
    assert result.stderr == ""
    assert (runtime / "ai-status").read_text(encoding="utf-8").strip() == "unavailable:start-failed"
    assert list(metadata.glob("*")) == [metadata / "fallback.env"]
    assert (metadata / "fallback.env").read_text(encoding="utf-8") == ""
    args = Path(fake_env["WIRECLAW_TEST_DOCKER_ARGS"]).read_text(encoding="utf-8")
    assert key not in args


def test_core_unhealthy_embedded_start_removes_key_and_retries_rules_only(tmp_path):
    release = make_release(tmp_path, "")
    fake_env, _ = make_fake_tools(tmp_path)
    metadata = tmp_path / "docker-containers"
    metadata.mkdir()
    docker = Path(fake_env["PATH"].split(":", 1)[0]) / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'case " $* " in\n'
        '  *" up "*)\n'
        '    if [ -n "${WIRECLAW_PROVIDER_API_KEY-}" ]; then printf "%s" "$WIRECLAW_PROVIDER_API_KEY" > "$WIRECLAW_TEST_METADATA/embedded.env"; '
        '    else printf "" > "$WIRECLAW_TEST_METADATA/rules-only.env"; fi ;;\n'
        '  *" rm "*) rm -f "$WIRECLAW_TEST_METADATA"/* ;;\n'
        '  *" ps -q wireclaw-core"*) printf "container\\n" ;;\n'
        '  *"inspect --format"*)\n'
        '    if [ -f "$WIRECLAW_TEST_METADATA/embedded.env" ]; then printf "starting\\n"; else printf "healthy\\n"; fi ;;\n'
        "esac\n"
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o700)
    fake_env["WIRECLAW_TEST_METADATA"] = str(metadata)
    fake_env["HOME"] = str(tmp_path / "home")
    (Path(fake_env["HOME"]) / "Library/Application Support/Wireclaw/run").mkdir(parents=True)
    key = "e" * 64
    script = r"""
. "$1/launch/macos/common.sh"
wireclaw_compose_api_key="$2"
WIRECLAW_PROVIDER_MODE=embedded_local
stop_ai() { return 0; }
sleep() { :; }
compose_start_core "$1" "$1/.env" embedded_local
printf 'MODE:%s KEY:%s' "$WIRECLAW_PROVIDER_MODE" "${WIRECLAW_PROVIDER_API_KEY:-}"
"""
    result = run_bash(script, str(release), key, env=fake_env)
    assert result.returncode == 0, result.stderr
    assert result.stdout.endswith("MODE:none KEY:")
    assert key not in result.stdout + result.stderr
    assert list(metadata.iterdir()) == [metadata / "rules-only.env"]
    assert (metadata / "rules-only.env").read_text(encoding="utf-8") == ""
    assert (
        Path(fake_env["HOME"]) / "Library/Application Support/Wireclaw/run/ai-status"
    ).read_text().strip() == "unavailable:readiness-failed"


def test_start_reports_missing_docker_cli(tmp_path):
    release = make_release(tmp_path, "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n")
    empty_bin = tmp_path / "empty-bin"
    empty_bin.mkdir()
    (empty_bin / "dirname").symlink_to(shutil.which("dirname"))
    env = os.environ | {"HOME": str(tmp_path), "PATH": str(empty_bin)}
    result = subprocess.run(
        ["/bin/bash", str(release / "launch/macos/start.sh")],
        cwd=release,
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "Docker CLI is missing" in result.stderr


def test_start_reports_compose_and_daemon_failures(tmp_path):
    for compose, daemon, expected in (
        (False, True, "Docker Compose is unavailable"),
        (True, False, "Docker daemon is not running"),
    ):
        trial = tmp_path / expected.replace(" ", "-")
        trial.mkdir()
        release = make_release(trial, "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n")
        fake_env, _ = make_fake_tools(trial, compose=compose, daemon=daemon)
        result = subprocess.run(
            ["bash", str(release / "launch/macos/start.sh")],
            cwd=release,
            env=os.environ | fake_env,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert expected in result.stderr


def test_start_rejects_invalid_app_and_bridge_ports_before_mutation(tmp_path):
    for env_text, expected in (
        ("WIRECLAW_PORT=0\nWIRECLAW_BRIDGE_PORT=8766\n", "WIRECLAW_PORT must be a port number"),
        (
            "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=abc\n",
            "WIRECLAW_BRIDGE_PORT must be a port number",
        ),
    ):
        trial = tmp_path / expected.split()[0] / str(len(list(tmp_path.iterdir())))
        trial.mkdir(parents=True)
        release = make_release(trial, env_text)
        fake_env, log = make_fake_tools(trial)
        result = subprocess.run(
            ["bash", str(release / "launch/macos/start.sh")],
            cwd=release,
            env=os.environ | fake_env,
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert expected in result.stderr
        assert not log.exists()


def test_start_reports_data_root_and_missing_bridge_failures(tmp_path):
    env_text = (
        f"WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n"
        "WIRECLAW_PROVIDER_MODE=none\n"
        f"WIRECLAW_DATA_ROOT={tmp_path}/file/child\n"
    )
    (tmp_path / "file").write_text("not a directory", encoding="utf-8")
    release = make_release(tmp_path, env_text)
    fake_env, _ = make_fake_tools(tmp_path)
    result = subprocess.run(
        ["bash", str(release / "launch/macos/start.sh")],
        cwd=release,
        env=os.environ | fake_env,
        capture_output=True,
        text=True,
    )
    assert "cannot create the Wireclaw data root" in result.stderr

    other = tmp_path / "bridge-missing"
    other.mkdir()
    release = make_release(
        other,
        "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\nWIRECLAW_PROVIDER_MODE=none\n"
        f"WIRECLAW_DATA_ROOT={other}/Wireclaw Data\n",
    )
    fake_env, _ = make_fake_tools(other)
    result = subprocess.run(
        ["bash", str(release / "launch/macos/start.sh")],
        cwd=release,
        env=os.environ | fake_env,
        capture_output=True,
        text=True,
    )
    assert "Wireclaw host bridge is not installed" in result.stderr


def test_start_rejects_busy_ports_and_missing_configured_wireshark(tmp_path):
    for busy_port, wireshark, expected in (
        ("18765", "/usr/bin/true", "port 18765 is already in use"),
        ("18766", "/usr/bin/true", "port 18766 is already in use"),
        ("", "/not/a/wireshark", "configured Wireshark executable is not available"),
    ):
        trial = tmp_path / str(len(list(tmp_path.iterdir())))
        trial.mkdir()
        release = make_release(
            trial,
            "WIRECLAW_PORT=18765\nWIRECLAW_BRIDGE_PORT=18766\nWIRECLAW_PROVIDER_MODE=none\n"
            f"WIRECLAW_DATA_ROOT={trial}/Wireclaw Test Data\n",
        )
        fake_env, log = make_fake_tools(trial, busy_port=busy_port)
        install_stub_bridge(Path(fake_env["HOME"]))
        result = subprocess.run(
            ["bash", str(release / "launch/macos/start.sh")],
            cwd=release,
            env=os.environ | fake_env | {"WIRECLAW_WIRESHARK_PATH": wireshark},
            capture_output=True,
            text=True,
        )
        assert result.returncode != 0
        assert expected in result.stderr
        assert not log.exists()


def test_stop_and_uninstall_preserve_case_data_and_ignore_reused_pid(tmp_path):
    release = make_release(
        tmp_path,
        "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n"
        "WIRECLAW_PROVIDER_MODE=none\nWIRECLAW_DATA_ROOT=/unused\n",
    )
    fake_env, log = make_fake_tools(tmp_path)
    data = tmp_path / "Wireclaw Case Data"
    data.mkdir()
    database = data / "cases.sqlite3"
    database.write_bytes(b"preserve this case database")
    home = Path(fake_env["HOME"])
    bridge = install_stub_bridge(home)

    unrelated = subprocess.Popen(["/bin/sleep", "60"])
    pid_file = home / "Library/Application Support/Wireclaw/run/bridge.pid"
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    pid_file.write_text(f"{unrelated.pid}\n", encoding="utf-8")
    try:
        result = subprocess.run(
            ["bash", str(release / "launch/macos/stop.sh")],
            cwd=release,
            env=os.environ | fake_env,
            capture_output=True,
            text=True,
        )
        assert result.returncode == 0, result.stderr
        assert "stale bridge PID ignored" in result.stderr
        assert unrelated.poll() is None
        assert database.read_bytes() == b"preserve this case database"
        calls = log.read_text(encoding="utf-8")
        assert "down --remove-orphans" in calls
        assert " -v" not in calls
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)

    package = release / "host-bridge/macos/wireclaw-host-bridge-darwin-arm64"
    package.parent.mkdir(parents=True)
    package.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    package.chmod(0o700)
    install = subprocess.run(
        ["bash", str(release / "launch/macos/install-host-bridge.sh")],
        cwd=release,
        env=os.environ | fake_env,
        capture_output=True,
        text=True,
    )
    assert install.returncode == 0, install.stderr
    assert bridge.is_file()
    uninstall = subprocess.run(
        ["bash", str(release / "launch/macos/uninstall-host-bridge.sh")],
        cwd=release,
        env=os.environ | fake_env,
        capture_output=True,
        text=True,
    )
    assert uninstall.returncode == 0, uninstall.stderr
    assert not bridge.exists()
    assert database.read_bytes() == b"preserve this case database"


def test_embedded_start_uses_fixed_wrapper_with_key_only_on_fd3_and_allowlisted_env(tmp_path):
    home = tmp_path / "home"
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    observed = tmp_path / "wrapper-observed.json"
    sandbox_state = (
        home
        / "Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI"
    )
    case_database = tmp_path / "cases.sqlite3"
    import sqlite3

    with sqlite3.connect(case_database) as database:
        database.execute("CREATE TABLE cases (name TEXT)")
        database.execute("INSERT INTO cases VALUES ('non-secret fixture')")
    (tmp_path / "report.json").write_bytes(b'{"finding":"non-secret fixture"}')
    (tmp_path / "artifact.bin").write_bytes(b"non-secret fixture")
    (tmp_path / "provider.log").write_bytes(b"provider initialized")
    app.write_text(
        "#!/usr/bin/python3\n"
        "import json, os, sys\n"
        "key = os.read(3, 128).decode().strip() if sys.argv[1] == 'start' else ''\n"
        "state = os.path.join(os.environ['HOME'], 'Library/Containers/com.wireclaw.WireclawAI/Data/Library/Application Support/WireclawAI')\n"
        "os.makedirs(state, mode=0o700, exist_ok=True)\n"
        "open(os.path.join(state, 'process.json'), 'w').write(json.dumps({'pid':12345,'process_start':'1:2','executable_sha256':'"
        + "a"
        * 64
        + "'}))\n"
        f"open({str(observed)!r}, 'w').write(json.dumps({{'op':sys.argv[1], 'argv':sys.argv[1:], 'env':dict(os.environ), 'key':key}}))\n"
        "print(json.dumps({'state':'running','pid':12345,'process_start':'1:2','executable':"
        + repr(str(app.parent / "llama-server"))
        + ",'executable_sha256':'"
        + "a" * 64
        + "'}))\n",
        encoding="utf-8",
    )
    app.chmod(0o700)
    helper = app.parent / "llama-server"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    fake_env, _ = make_fake_tools(tmp_path)
    docker_env_capture = tmp_path / "compose-key-env"
    docker_args_capture = tmp_path / "compose-args"
    docker = Path(fake_env["PATH"].split(":", 1)[0]) / "docker"
    docker.write_text(
        "#!/bin/sh\n"
        'printf "%s" "${WIRECLAW_PROVIDER_API_KEY-<unset>}" > "$WIRECLAW_TEST_COMPOSE_KEY_ENV"\n'
        'printf "%s\\n" "$*" >> "$WIRECLAW_TEST_COMPOSE_ARGS"\n'
        "exit 0\n",
        encoding="utf-8",
    )
    docker.chmod(0o700)
    fake_env["WIRECLAW_TEST_COMPOSE_KEY_ENV"] = str(docker_env_capture)
    fake_env["WIRECLAW_TEST_COMPOSE_ARGS"] = str(docker_args_capture)
    codesign = Path(fake_env["PATH"].split(":", 1)[0]) / "codesign"
    codesign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    codesign.chmod(0o700)
    fake_env["HOME"] = str(home)
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
ai_host_receipt_create() { cat > "$wireclaw_ai_host_receipt_file"; chmod 600 "$wireclaw_ai_host_receipt_file"; }
probe_ai_health() { return 0; }
ai_listener_matches() { return 0; }
start_ai "$2" 18765 18766 embedded_local
configure_provider_environment embedded_local
compose_with_provider_environment "$2" "$2/.env" config --quiet
"""
    result = run_bash(script, str(release), str(release), env=fake_env)
    assert result.returncode == 0, result.stderr
    call = json.loads(observed.read_text(encoding="utf-8"))
    assert call["argv"] == ["start"]
    assert call["key"] and len(call["key"]) == 64
    assert all(char in "0123456789abcdef" for char in call["key"])
    assert docker_env_capture.read_text(encoding="utf-8") == call["key"]
    assert call["key"] not in docker_args_capture.read_text(encoding="utf-8")
    assert call["key"] not in json.dumps(call["env"])
    assert set(call["env"]) <= {
        "HOME",
        "TMPDIR",
        "PATH",
        "__CF_USER_TEXT_ENCODING",
        "SDKROOT",
        "CPATH",
        "LIBRARY_PATH",
        "MANPATH",
        "LC_CTYPE",
    }
    assert "WIRECLAW_PROVIDER_API_KEY" not in call["env"]
    assert call["key"] not in result.stdout + result.stderr
    receipt = runtime_dir / "ai-host-receipt.json"
    assert receipt.stat().st_mode & 0o777 == 0o600
    assert call["key"] not in receipt.read_text(encoding="utf-8")
    assert (runtime_dir / "ai-status").read_text(encoding="utf-8").strip() == "ready"
    assert call["key"] not in (sandbox_state / "process.json").read_text(encoding="utf-8")
    assert call["key"] not in docker_args_capture.read_text(encoding="utf-8")
    # The observer files capture the trusted Compose process environment and the
    # wrapper fd-3 input for this test. They are the deliberate Docker metadata
    # exception and test instrumentation; all other generated files are scanned.
    excluded_observers = {observed, docker_env_capture}
    for path in tmp_path.rglob("*"):
        if path.is_file() and path not in excluded_observers:
            assert call["key"].encode() not in path.read_bytes(), path


def test_stop_ai_uses_host_verified_stop_then_wrapper_cleanup_without_shell_signals(tmp_path):
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    calls = tmp_path / "calls"
    app.write_text(
        '#!/bin/sh\ncase "$1" in status) state=running ;; *) state=stopped ;; esac\n'
        "printf 'wrapper:%s\\n' \"$1\" >> " + shlex.quote(str(calls)) + "\n"
        'printf \'{"state":"%s"}\\n\' "$state"\n',
        encoding="utf-8",
    )
    app.chmod(0o700)
    fake_env, _ = make_fake_tools(tmp_path)
    codesign = Path(fake_env["PATH"].split(":", 1)[0]) / "codesign"
    codesign.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    codesign.chmod(0o700)
    home = Path(fake_env["HOME"])
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    receipt = runtime_dir / "ai-host-receipt.json"
    receipt.write_text("{}\n", encoding="utf-8")
    receipt.chmod(0o600)
    fake_env["WIRECLAW_TEST_CALLS"] = str(calls)
    fake_env["RELEASE_DIR"] = str(release)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
ai_host_stop_verified() { printf 'host:stop\n' >> "$WIRECLAW_TEST_CALLS"; }
ai_host_receipt_remove() { printf 'host:remove\n' >> "$WIRECLAW_TEST_CALLS"; rm -f "$wireclaw_ai_host_receipt_file"; }
stop_ai
"""
    result = run_bash(script, str(release), env=fake_env)
    assert result.returncode == 0, result.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "wrapper:status",
        "host:stop",
        "wrapper:stop",
        "host:remove",
    ]
    ai_stop = (
        (LAUNCH / "common.sh")
        .read_text(encoding="utf-8")
        .split("stop_ai() {", 1)[1]
        .split("probe_ai_health() {", 1)[0]
    )
    assert "kill " not in ai_stop


def test_missing_host_receipt_recovers_only_from_fresh_wrapper_status(tmp_path):
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    calls = tmp_path / "calls"
    app.write_text(
        "#!/usr/bin/python3\nimport json,sys\n"
        "open(" + repr(str(calls)) + ", 'a').write('wrapper:' + sys.argv[1] + '\\n')\n"
        "identity={'state':'running','pid':12345,'process_start':'1:2','executable':"
        + repr(str(app.parent / "llama-server"))
        + ",'executable_sha256':'"
        + "a" * 64
        + "'}\n"
        "print(json.dumps(identity if sys.argv[1] == 'status' else {'state':'stopped'}))\n",
        encoding="utf-8",
    )
    app.chmod(0o700)
    helper = app.parent / "llama-server"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    home = tmp_path / "home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    fake_env["RELEASE_DIR"] = str(release)
    fake_env["WIRECLAW_TEST_CALLS"] = str(calls)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
ai_host_receipt_recover() { cat >/dev/null; printf 'host:recover\n' >> "$WIRECLAW_TEST_CALLS"; printf '{}\n' > "$wireclaw_ai_host_receipt_file"; chmod 600 "$wireclaw_ai_host_receipt_file"; }
ai_host_stop_verified() { printf 'host:stop\n' >> "$WIRECLAW_TEST_CALLS"; }
ai_host_receipt_remove() { printf 'host:remove\n' >> "$WIRECLAW_TEST_CALLS"; rm -f "$wireclaw_ai_host_receipt_file"; }
stop_ai
"""
    result = run_bash(script, str(release), env=fake_env)
    assert result.returncode == 0, result.stderr
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "wrapper:status",
        "host:recover",
        "wrapper:status",
        "host:stop",
        "wrapper:stop",
        "host:remove",
    ]


def test_mismatched_fresh_status_never_recovers_or_signals(tmp_path):
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    calls = tmp_path / "calls"
    app.write_text(
        "#!/usr/bin/python3\nimport json,sys\n"
        "open(" + repr(str(calls)) + ", 'a').write('wrapper:' + sys.argv[1] + '\\n')\n"
        "print(json.dumps({'state':'running','pid':12345,'process_start':'1:2','executable':'/tmp/unrelated','executable_sha256':'"
        + "a" * 64
        + "'}))\n",
        encoding="utf-8",
    )
    app.chmod(0o700)
    helper = app.parent / "llama-server"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    home = tmp_path / "home"
    (home / "Library/Application Support/Wireclaw/run").mkdir(parents=True)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    fake_env["RELEASE_DIR"] = str(release)
    fake_env["WIRECLAW_TEST_CALLS"] = str(calls)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
ai_host_receipt_recover() { printf 'host:recover\n' >> "$WIRECLAW_TEST_CALLS"; return 1; }
ai_host_stop_verified() { printf 'host:stop\n' >> "$WIRECLAW_TEST_CALLS"; }
stop_ai
"""
    result = run_bash(script, str(release), env=fake_env)
    assert result.returncode != 0
    assert calls.read_text(encoding="utf-8").splitlines() == ["wrapper:status", "host:recover"]


def test_signature_failure_falls_back_without_starting_wrapper(tmp_path):
    home = tmp_path / "home"
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    app.write_text('#!/bin/sh\ntouch "$WIRECLAW_TEST_WRAPPER_STARTED"\n', encoding="utf-8")
    app.chmod(0o700)
    helper = app.parent / "llama-server"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    fake_env["WIRECLAW_TEST_WRAPPER_STARTED"] = str(tmp_path / "started")
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; ai_codesign_verify() { return 1; }; start_ai "$2" 18765 18766 embedded_local',
        str(release),
        str(release),
        env=fake_env,
    )
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai-status").read_text().strip() == "unavailable:invalid-signature"
    assert not (tmp_path / "started").exists()


def test_invalid_start_identity_falls_back_without_signaling(tmp_path):
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    helper = app.parent / "llama-server"
    calls = tmp_path / "calls"
    app.write_text(
        "#!/usr/bin/python3\nimport json,sys\n"
        "op=sys.argv[1]; open(" + repr(str(calls)) + ", 'a').write('wrapper:' + op + '\\n')\n"
        "identity={'state':'running','pid':12345,'process_start':'1:2','executable':'/tmp/unrelated','executable_sha256':'"
        + "a"
        * 64
        + "'}\n"
        "print(json.dumps(identity if op == 'start' else {'state':'stopped'}))\n",
        encoding="utf-8",
    )
    app.chmod(0o700)
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    home = tmp_path / "home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    fake_env["WIRECLAW_TEST_CALLS"] = str(calls)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; ai_codesign_verify() { return 0; }; start_ai "$2" 18765 18766 embedded_local',
        str(release),
        str(release),
        env=fake_env,
    )
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai-status").read_text().strip() == "unavailable:verification-failed"
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "wrapper:start",
        "wrapper:status",
        "wrapper:stop",
    ]
    assert not (runtime_dir / "ai-host-receipt.json").exists()


def test_readiness_loss_uses_verified_stop_before_cleanup_and_falls_back(tmp_path):
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    calls = tmp_path / "calls"
    helper = app.parent / "llama-server"
    app.write_text(
        "#!/usr/bin/python3\nimport json,sys\n"
        "open(" + repr(str(calls)) + ", 'a').write('wrapper:' + sys.argv[1] + '\\n')\n"
        "identity={'state':'running','pid':12345,'process_start':'1:2','executable':"
        + repr(str(helper))
        + ",'executable_sha256':'"
        + "a" * 64
        + "'}\n"
        "print(json.dumps(identity if sys.argv[1] == 'start' else {'state':'unavailable','reason':'process_missing'} if sys.argv[1] == 'status' else {'state':'stopped'}))\n",
        encoding="utf-8",
    )
    app.chmod(0o700)
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    home = tmp_path / "home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    fake_env["WIRECLAW_TEST_CALLS"] = str(calls)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
ai_host_receipt_create() { cat > "$wireclaw_ai_host_receipt_file"; chmod 600 "$wireclaw_ai_host_receipt_file"; }
ai_host_stop_verified() { printf 'host:stop\n' >> "$WIRECLAW_TEST_CALLS"; }
ai_host_receipt_remove() { printf 'host:remove\n' >> "$WIRECLAW_TEST_CALLS"; rm -f "$wireclaw_ai_host_receipt_file"; }
probe_ai_health() { return 1; }
ai_listener_matches() { return 1; }
start_ai "$2" 18765 18766 embedded_local
"""
    result = run_bash(script, str(release), str(release), env=fake_env)
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai-status").read_text().strip() == "unavailable:readiness-failed"
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "wrapper:start",
        "wrapper:status",
        "host:stop",
        "wrapper:stop",
        "host:remove",
    ]


def test_authenticated_health_requires_owned_listener_and_expected_model(tmp_path):
    key = "a" * 64
    fake_net = tmp_path / "fake_net"
    fake_net.mkdir()
    (fake_net / "sitecustomize.py").write_text(
        "import subprocess, socket\n"
        "subprocess.run=lambda argv, **kwargs: subprocess.CompletedProcess(argv, 0, 'n127.0.0.1:' + argv[5].split(':')[-1] + '\\n', '')\n"
        "class Response:\n"
        " def __init__(self): self.first=True\n"
        " def __enter__(self): return self\n"
        " def __exit__(self, *args): return False\n"
        " def sendall(self, data): open("
        + repr(str(tmp_path / "request"))
        + ", 'wb').write(data)\n"
        " def recv(self, size):\n"
        "  if not self.first: return b''\n"
        "  self.first=False\n"
        '  body=b\'{"data":[{"id":"wireclaw-qwen3-4b-instruct-2507-q4_k_m"}]}\'\n'
        "  return b'HTTP/1.1 200 OK\\r\\nContent-Length: ' + str(len(body)).encode() + b'\\r\\n\\r\\n' + body\n"
        "socket.create_connection=lambda *args, **kwargs: Response()\n",
        encoding="utf-8",
    )
    port = 18767
    key_file = tmp_path / "probe-key"
    key_file.write_text(key, encoding="ascii")
    result = run_bash(
        '. "$1/launch/macos/common.sh"; wireclaw_ai_port="$2"; IFS= read -r key < "$3"; probe_ai_health "$4" "$key"',
        str(ROOT),
        str(port),
        str(key_file),
        str(os.getpid()),
        env={"HOME": str(tmp_path), "PYTHONPATH": str(fake_net)},
    )
    assert result.returncode == 0, result.stderr
    request = (tmp_path / "request").read_bytes()
    assert b"Authorization: Bearer " + key.encode("ascii") in request
    assert b"/v1/models" in request


def test_launcher_has_no_direct_llama_runtime_launch_or_ai_pid_signal_path():
    common = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    stop = (LAUNCH / "stop.sh").read_text(encoding="utf-8")
    assert '"$ai_bin"' not in common
    assert 'kill -TERM "$AI_PID"' not in common
    assert 'kill -KILL "$ai_pid"' not in common
    assert 'kill -TERM "$ai_pid"' not in common
    assert "stop_ai" in stop
    assert "WireclawAI.app" in common


def test_ai_listener_is_verified_during_bounded_health_probe_before_final_check():
    source = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    assert "ai_listener_matches()" in source
    start = source.index('wrapper_receipt="$(ai_wrapper_call start')
    assert start < source.index("ai_host_receipt_create", start)
    assert source.index("probe_ai_health", start) < source.index(
        'ai_listener_matches "$ai_pid"', start
    )
    probe = source[source.index("probe_ai_health()") : source.index("start_ai()")]
    assert '"/usr/sbin/lsof"' in probe
    assert '"Authorization: Bearer " + key' in probe
    assert "urllib" not in probe and "ProxyHandler" not in probe
    assert "read(3, 128)" in probe


def test_missing_wrapper_app_falls_back_without_a_host_receipt(tmp_path):
    home = tmp_path / "User Home"
    release = make_release(tmp_path, "")
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; start_ai "$2" 18765 18766 embedded_local',
        str(release),
        str(release),
        env=fake_env,
    )
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai-status").read_text().strip() == "unavailable:invalid-app"
    assert not (runtime_dir / "ai-host-receipt.json").exists()


def test_stale_legacy_ai_pid_state_never_signals_or_authorizes_cleanup(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    unrelated = subprocess.Popen(["/bin/sleep", "60"])
    (runtime_dir / "ai.pid").write_text(f"{unrelated.pid}\nnot-authoritative\n", encoding="utf-8")
    try:
        result = run_bash(
            '. "$1/launch/macos/common.sh"; stop_ai',
            str(ROOT),
            env={"HOME": str(home)},
        )
        assert result.returncode == 0, result.stderr
        assert unrelated.poll() is None
        assert (runtime_dir / "ai.pid").exists()
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_symlinked_host_receipt_is_not_overwritten_or_removed(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    sentinel = tmp_path / "receipt-target"
    sentinel.write_text("preserve", encoding="utf-8")
    (runtime_dir / "ai-host-receipt.json").symlink_to(sentinel)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; ai_unavailable unsafe-state',
        str(ROOT),
        env={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert sentinel.read_text(encoding="utf-8") == "preserve"


def test_launcher_does_not_launch_runtime_or_signal_ai_pid_from_shell():
    source = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    ai_lifecycle = source.split("stop_ai() {", 1)[1].split("configure_provider_environment() {", 1)[
        0
    ]
    assert '"$ai_bin"' not in source
    assert "AI_PID=" not in source
    assert 'kill -TERM "$ai_pid"' not in ai_lifecycle
    assert 'kill -KILL "$ai_pid"' not in ai_lifecycle
    assert "ai_host_stop_verified" in ai_lifecycle


def test_wrapper_start_failure_falls_back_without_retaining_the_ephemeral_key(tmp_path):
    home = tmp_path / "home"
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    app.write_text("#!/bin/sh\nexit 1\n", encoding="utf-8")
    app.chmod(0o700)
    helper = app.parent / "llama-server"
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
start_ai "$2" 18765 18766 embedded_local
printf 'KEY:%s' "$wireclaw_ai_start_key"
"""
    result = run_bash(script, str(release), str(release), env=fake_env)
    assert result.returncode == 0, result.stderr
    assert "unavailable:start-failed" in (runtime_dir / "ai-status").read_text()
    assert "KEY:" in result.stdout and result.stdout.endswith("KEY:")
    assert not (runtime_dir / "ai-host-receipt.json").exists()


def test_failed_start_recovers_running_helper_before_fallback(tmp_path):
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    helper = app.parent / "llama-server"
    calls = tmp_path / "calls"
    app.write_text(
        "#!/usr/bin/python3\nimport json,sys\n"
        "op=sys.argv[1]; open(" + repr(str(calls)) + ", 'a').write('wrapper:' + op + '\\n')\n"
        "identity={'state':'running','pid':12345,'process_start':'1:2','executable':"
        + repr(str(helper))
        + ",'executable_sha256':'"
        + "a" * 64
        + "'}\n"
        "print(json.dumps(identity if op in ('start','status') else {'state':'stopped'}))\n"
        "sys.exit(1 if op == 'start' else 0)\n",
        encoding="utf-8",
    )
    app.chmod(0o700)
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    home = tmp_path / "home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    fake_env["WIRECLAW_TEST_CALLS"] = str(calls)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
ai_host_receipt_recover() { cat >/dev/null; printf 'host:recover\n' >> "$WIRECLAW_TEST_CALLS"; printf '{}\n' > "$wireclaw_ai_host_receipt_file"; chmod 600 "$wireclaw_ai_host_receipt_file"; }
ai_host_stop_verified() { printf 'host:stop\n' >> "$WIRECLAW_TEST_CALLS"; }
ai_host_receipt_remove() { printf 'host:remove\n' >> "$WIRECLAW_TEST_CALLS"; rm -f "$wireclaw_ai_host_receipt_file"; }
start_ai "$2" 18765 18766 embedded_local
"""
    result = run_bash(script, str(release), str(release), env=fake_env)
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai-status").read_text().strip() == "unavailable:start-failed"
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "wrapper:start",
        "wrapper:status",
        "host:recover",
        "host:stop",
        "wrapper:stop",
        "host:remove",
    ]


def test_receipt_create_failure_recovers_and_stops_launched_helper(tmp_path):
    release = make_release(tmp_path, "")
    app = release / "ai/WireclawAI.app/Contents/MacOS/WireclawAI"
    app.parent.mkdir(parents=True)
    helper = app.parent / "llama-server"
    calls = tmp_path / "calls"
    app.write_text(
        "#!/usr/bin/python3\nimport json,sys\n"
        "op=sys.argv[1]; open(" + repr(str(calls)) + ", 'a').write('wrapper:' + op + '\\n')\n"
        "identity={'state':'running','pid':12345,'process_start':'1:2','executable':"
        + repr(str(helper))
        + ",'executable_sha256':'"
        + "a" * 64
        + "'}\n"
        "print(json.dumps(identity if op in ('start','status') else {'state':'stopped'}))\n",
        encoding="utf-8",
    )
    app.chmod(0o700)
    helper.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    helper.chmod(0o700)
    home = tmp_path / "home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    fake_env, _ = make_fake_tools(tmp_path)
    fake_env["HOME"] = str(home)
    fake_env["WIRECLAW_TEST_CALLS"] = str(calls)
    script = r"""
. "$1/launch/macos/common.sh"
ai_codesign_verify() { return 0; }
ai_host_receipt_create() { cat >/dev/null; printf 'host:create-failed\n' >> "$WIRECLAW_TEST_CALLS"; return 1; }
ai_host_receipt_recover() { cat >/dev/null; printf 'host:recover\n' >> "$WIRECLAW_TEST_CALLS"; printf '{}\n' > "$wireclaw_ai_host_receipt_file"; chmod 600 "$wireclaw_ai_host_receipt_file"; }
ai_host_stop_verified() { printf 'host:stop\n' >> "$WIRECLAW_TEST_CALLS"; }
ai_host_receipt_remove() { printf 'host:remove\n' >> "$WIRECLAW_TEST_CALLS"; rm -f "$wireclaw_ai_host_receipt_file"; }
start_ai "$2" 18765 18766 embedded_local
"""
    result = run_bash(script, str(release), str(release), env=fake_env)
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai-status").read_text().strip() == "unavailable:receipt-failed"
    assert calls.read_text(encoding="utf-8").splitlines() == [
        "wrapper:start",
        "host:create-failed",
        "wrapper:status",
        "host:recover",
        "host:stop",
        "wrapper:stop",
        "host:remove",
    ]


def test_untrusted_provider_values_cannot_override_embedded_runtime_identity(tmp_path):
    home = tmp_path / "home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True, exist_ok=True)
    (runtime_dir / "ai-status").write_text("ready\n", encoding="utf-8")
    result = run_bash(
        '. "$1/launch/macos/common.sh"; wireclaw_ai_start_key=' + "a" * 64 + "; "
        "configure_provider_environment embedded_local https://attacker.invalid/v1 attacker-model attacker-token; "
        'printf "%s|%s|%s|%s" "$WIRECLAW_PROVIDER_MODE" "$WIRECLAW_PROVIDER_BASE_URL" '
        '"$WIRECLAW_PROVIDER_MODEL" "$WIRECLAW_EMBEDDED_AI_STATUS"',
        str(ROOT),
        env={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == (
        "embedded_local|http://host.docker.internal:8767/v1|"
        "wireclaw-qwen3-4b-instruct-2507-q4_k_m|ready"
    )
    assert "attacker" not in result.stdout
