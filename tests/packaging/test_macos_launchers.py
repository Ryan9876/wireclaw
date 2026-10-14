import os
import shutil
import subprocess
from pathlib import Path

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


def test_bridge_health_probe_uses_the_approved_application_origin():
    assert 'curl --silent --fail --header "Origin: http://127.0.0.1:$APP_PORT"' in START_SOURCE
    assert '"http://127.0.0.1:$BRIDGE_PORT/v1/health"' in START_SOURCE


def test_start_loads_and_uses_the_packaged_image_without_rebuilding():
    assert 'load_release_image "$RELEASE_DIR"' in START_SOURCE
    assert 'compose.yaml" up -d;' in START_SOURCE
    assert "up -d --build" not in START_SOURCE


def test_start_reports_missing_docker_cli(tmp_path):
    release = make_release(tmp_path, "WIRECLAW_PORT=8765\nWIRECLAW_BRIDGE_PORT=8766\n")
    env = os.environ | {"HOME": str(tmp_path), "PATH": "/usr/bin:/bin"}
    result = subprocess.run(
        ["bash", str(release / "launch/macos/start.sh")],
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
