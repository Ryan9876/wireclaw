import hashlib
import json
import os
import shlex
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


def make_ai_assets(release: Path):
    model = release / "ai/models/qwen3-4b-instruct-2507-q4_k_m.gguf"
    runtime = release / "ai/macos-arm64/llama-server"
    model.parent.mkdir(parents=True)
    runtime.parent.mkdir(parents=True)
    model.write_bytes(b"test model")
    runtime.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
    runtime.chmod(0o700)
    (release / "ai/licenses").mkdir()
    (release / "ai/licenses/Qwen-Apache-2.0.txt").write_text("Apache License", encoding="utf-8")
    (release / "ai/licenses/llama.cpp-MIT.txt").write_text("MIT License", encoding="utf-8")
    (release / "ai/model-manifest.json").write_text(
        json.dumps(
            {
                "model_id": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
                "revision": "cdbee75f17c01a7cc42f958dc650907174af0554",
                "license": "Apache-2.0",
                "quantization": "Q4_K_M",
                "architecture": "qwen3",
                "license_path": "licenses/Qwen-Apache-2.0.txt",
                "artifact": {
                    "path": "models/qwen3-4b-instruct-2507-q4_k_m.gguf",
                    "sha256": hashlib.sha256(model.read_bytes()).hexdigest(),
                    "size_bytes": model.stat().st_size,
                },
            }
        ),
        encoding="utf-8",
    )
    (release / "ai/runtime-manifest.json").write_text(
        json.dumps(
            {
                "repository": "ggml-org/llama.cpp",
                "revision": "8345f333951c661d166b00e6f9362e553768f292",
                "platform": "macos",
                "architecture": "arm64",
                "entrypoint": "macos-arm64/llama-server",
                "build_settings": {"metal": True, "server": True},
                "files": [
                    {
                        "path": "macos-arm64/llama-server",
                        "sha256": hashlib.sha256(runtime.read_bytes()).hexdigest(),
                        "size_bytes": runtime.stat().st_size,
                    }
                ],
                "license_paths": ["licenses/llama.cpp-MIT.txt"],
                "policy": {
                    "platform": "macos",
                    "architecture": "arm64",
                    "listen_host": "127.0.0.1",
                    "context_size": 16384,
                    "batch_size": 128,
                    "micro_batch_size": 32,
                    "max_tokens": 2048,
                    "parallel": 1,
                    "prompt_cache_ram_mib": 0,
                    "port": 8767,
                    "model_alias": "wireclaw-qwen3-4b-instruct-2507-q4_k_m",
                    "authentication_required": True,
                    "agent_tools": False,
                    "web_ui": False,
                    "network_downloads": False,
                },
            }
        ),
        encoding="utf-8",
    )


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


def test_ai_manifest_hash_is_verified_before_runtime_use_and_symlink_escape_rejected(tmp_path):
    release = make_release(tmp_path, "")
    make_ai_assets(release)
    result = run_bash('. "$1/launch/macos/common.sh"; verify_ai_bundle "$1"', str(release))
    assert result.returncode == 0, result.stderr
    model = release / "ai/models/qwen3-4b-instruct-2507-q4_k_m.gguf"
    model.write_bytes(b"tampered")
    result = run_bash('. "$1/launch/macos/common.sh"; verify_ai_bundle "$1"', str(release))
    assert result.returncode != 0
    outside = tmp_path / "outside.gguf"
    outside.write_bytes(b"test model")
    model.unlink()
    model.symlink_to(outside)
    result = run_bash('. "$1/launch/macos/common.sh"; verify_ai_bundle "$1"', str(release))
    assert result.returncode != 0


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


def test_ai_listener_is_verified_during_bounded_health_probe_before_final_check():
    source = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    assert "ai_listener_matches()" in source
    startup_start = source.index('if ! ai_process_matches "$AI_PID"')
    startup = source[startup_start : source.index("  printf 'ready", startup_start)]
    assert startup.index('! ai_process_matches "$AI_PID"') < startup.index(
        '! probe_ai_health "$AI_PID"'
    )
    assert startup.index('! probe_ai_health "$AI_PID"') < startup.index(
        '! ai_listener_matches "$AI_PID"'
    )
    probe = source[source.index("probe_ai_health()") : source.index("start_ai()")]
    assert '"/usr/sbin/lsof"' in probe
    assert '"n127.0.0.1:8767"' in probe
    assert "getsockopt(0, 2, 4)" not in source


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


def test_ai_port_conflict_sets_unavailable_without_starting_runtime(tmp_path):
    release = make_release(tmp_path, "")
    make_ai_assets(release)
    fake_env, _ = make_fake_tools(tmp_path, busy_port="8767")
    runtime_dir = Path(fake_env["HOME"]) / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; start_ai "$2" 18765 18766 embedded_local',
        str(ROOT),
        str(release),
        env=fake_env,
    )
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai-status").read_text().strip() == "unavailable:port-in-use"
    assert not (runtime_dir / "ai.pid").exists()
    assert not (runtime_dir / "ai-key").exists()


def test_ai_runtime_survives_the_startup_launcher_exiting(tmp_path):
    release = make_release(tmp_path, "")
    make_ai_assets(release)
    runtime = release / "ai/macos-arm64/llama-server"
    runtime.write_text("#!/bin/bash\nexec /bin/sleep 15\n", encoding="utf-8")
    runtime.chmod(0o700)
    manifest_path = release / "ai/runtime-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    manifest["files"][0]["size_bytes"] = runtime.stat().st_size
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    fake_env, _ = make_fake_tools(tmp_path)
    fake_ps = Path(fake_env["PATH"].split(":", 1)[0]) / "ps"
    fake_ps.write_text("#!/bin/sh\nprintf 'Wed Oct 14 23:00:00 2026\\n'\n", encoding="utf-8")
    fake_ps.chmod(0o700)
    runtime_dir = Path(fake_env["HOME"]) / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    script = (
        '. "$1/launch/macos/common.sh"; '
        "ai_process_matches() { return 0; }; "
        "probe_ai_health() { return 0; }; "
        "ai_listener_matches() { return 0; }; "
        'start_ai "$2" 18765 18766 embedded_local'
    )
    result = subprocess.run(
        ["bash", "-c", script, "wireclaw-test", str(ROOT), str(release)],
        cwd=ROOT,
        env=fake_env,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert (runtime_dir / "ai.pid").exists(), result.stdout + result.stderr
    pid = int((runtime_dir / "ai.pid").read_text(encoding="utf-8").splitlines()[0])
    try:
        assert subprocess.run(["/bin/kill", "-0", str(pid)], check=False).returncode == 0
    finally:
        subprocess.run(["/bin/kill", "-TERM", str(pid)], check=False)


def test_stale_or_reused_ai_pid_never_signals_an_unrelated_process(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    unrelated = subprocess.Popen(["/bin/sleep", "60"])
    (runtime_dir / "ai.pid").write_text(
        f"{unrelated.pid}\nnot-the-process-start-time\n", encoding="utf-8"
    )
    try:
        result = run_bash(
            '. "$1/launch/macos/common.sh"; stop_ai', str(ROOT), env={"HOME": str(home)}
        )
        assert result.returncode == 0, result.stderr
        assert "stale AI PID ignored" in result.stderr
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_ai_stop_ignores_pid_with_unrelated_executable(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    release = make_release(tmp_path, "")
    make_ai_assets(release)
    unrelated = subprocess.Popen(["/bin/sleep", "60"])
    env, _ = make_fake_tools(tmp_path)
    runtime_dir.joinpath("ai.pid").write_text(
        f"{unrelated.pid}\nWed Oct 14 23:00:00 2026\n", encoding="utf-8"
    )
    fake_ps = Path(env["PATH"].split(":", 1)[0]) / "ps"
    fake_ps.write_text("#!/bin/sh\nprintf 'Wed Oct 14 23:00:00 2026\\n'\n", encoding="utf-8")
    fake_ps.chmod(0o700)
    fake_lsof = Path(env["PATH"].split(":", 1)[0]) / "lsof"
    fake_lsof.write_text("#!/bin/sh\nprintf 'n/bin/sleep\\n'\n", encoding="utf-8")
    fake_lsof.chmod(0o700)
    try:
        result = run_bash(
            '. "$1/launch/macos/common.sh"; stop_ai',
            str(release),
            env=env | {"HOME": str(home)},
        )
        assert result.returncode == 0, result.stderr
        assert "stale AI PID ignored" in result.stderr
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_ai_stop_ignores_same_executable_with_mismatched_start_time(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    release = make_release(tmp_path, "")
    make_ai_assets(release)
    unrelated = subprocess.Popen(["/bin/sleep", "60"])
    env, _ = make_fake_tools(tmp_path)
    runtime_dir.joinpath("ai.pid").write_text(
        f"{unrelated.pid}\nold-start-time\n", encoding="utf-8"
    )
    fake_ps = Path(env["PATH"].split(":", 1)[0]) / "ps"
    fake_ps.write_text("#!/bin/sh\nprintf 'current-start-time\\n'\n", encoding="utf-8")
    fake_ps.chmod(0o700)
    fake_lsof = Path(env["PATH"].split(":", 1)[0]) / "lsof"
    fake_lsof.write_text(
        f"#!/bin/sh\nprintf 'n{release}/ai/macos-arm64/llama-server\\n'\n",
        encoding="utf-8",
    )
    fake_lsof.chmod(0o700)
    try:
        result = run_bash(
            '. "$1/launch/macos/common.sh"; stop_ai',
            str(release),
            env=env | {"HOME": str(home)},
        )
        assert result.returncode == 0, result.stderr
        assert "stale AI PID ignored" in result.stderr
        assert unrelated.poll() is None
    finally:
        unrelated.terminate()
        unrelated.wait(timeout=5)


def test_ai_stop_rechecks_identity_before_forced_termination(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    (runtime_dir / "ai.pid").write_text("424242\nmanaged-start\n", encoding="utf-8")
    signal_log = tmp_path / "signals.log"
    identity_log = tmp_path / "identity-checks.log"
    env = {
        "HOME": str(home),
        "WIRECLAW_TEST_SIGNAL_LOG": str(signal_log),
        "WIRECLAW_TEST_IDENTITY_LOG": str(identity_log),
    }
    script = r"""
. "$1/launch/macos/common.sh"
match_count=0
ai_process_matches() {
  match_count=$((match_count + 1))
  printf 'check\n' >> "$WIRECLAW_TEST_IDENTITY_LOG"
  [ "$match_count" -eq 1 ]
}
kill() {
  printf '%s\n' "$*" >> "$WIRECLAW_TEST_SIGNAL_LOG"
  case "$1" in -0|-TERM) return 0 ;; esac
  return 0
}
sleep() { :; }
stop_ai
"""
    result = run_bash(script, str(ROOT), env=env)
    assert result.returncode != 0
    signals = signal_log.read_text(encoding="utf-8").splitlines()
    assert signals[:2] == ["-0 424242", "-TERM 424242"]
    assert "-KILL 424242" not in signals
    assert identity_log.read_text(encoding="utf-8").splitlines() == ["check", "check"]


def test_ai_stop_without_state_is_idempotent(tmp_path):
    env, _ = make_fake_tools(tmp_path)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; stop_ai && stop_ai',
        str(ROOT),
        env=env,
    )
    assert result.returncode == 0, result.stderr


def test_symlinked_ai_secret_state_is_not_overwritten(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    sentinel = tmp_path / "outside-secret-target"
    sentinel.write_text("preserve", encoding="utf-8")
    (runtime_dir / "ai-key").symlink_to(sentinel)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; start_ai "$2" 18765 18766 embedded_local',
        str(ROOT),
        str(ROOT),
        env={"HOME": str(home)},
    )
    assert result.returncode == 0, result.stderr
    assert "(unsafe-state)" in result.stdout
    assert not (runtime_dir / "ai-status").exists()
    assert sentinel.read_text() == "preserve"


def test_ai_log_fifo_is_not_unlinked_before_runtime_opens_it():
    source = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    runtime_started = source.index("  AI_PID=$!")
    runtime_ready = source.index('probe_ai_health "$AI_PID"', runtime_started)
    startup_block = source[runtime_started:runtime_ready]
    assert 'rm -f "$wireclaw_ai_fifo"' not in startup_block
    assert 'rm -f "$wireclaw_ai_fifo"' in source[source.index("stop_ai()") :]


def test_runtime_policy_is_fixed_loopback_only_and_no_user_values_become_argv():
    source = (LAUNCH / "common.sh").read_text(encoding="utf-8")
    assert '--host 127.0.0.1 --port "$wireclaw_ai_port"' in source
    assert (
        "--ctx-size 16384 --batch-size 128 --ubatch-size 32 --n-predict 2048 --parallel 1" in source
    )
    assert '--api-key-file "$wireclaw_ai_key_file" --no-agent --no-webui --cache-ram 0' in source
    assert 'env -i HOME="$wireclaw_runtime_dir"' in source
    assert "pkill" not in source


def test_unsupported_required_prompt_cache_flag_leaves_embedded_ai_unavailable(tmp_path):
    release = make_release(tmp_path, "")
    make_ai_assets(release)
    runtime = release / "ai/macos-arm64/llama-server"
    runtime.write_text(
        "#!/bin/sh\nprintf '%s\\n' \"$@\" > "
        + shlex.quote(str(tmp_path / "runtime-argv.txt"))
        + "\nexit 64\n",
        encoding="utf-8",
    )
    runtime.chmod(0o700)
    manifest_path = release / "ai/runtime-manifest.json"
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    manifest["files"][0]["sha256"] = hashlib.sha256(runtime.read_bytes()).hexdigest()
    manifest["files"][0]["size_bytes"] = runtime.stat().st_size
    manifest_path.write_text(json.dumps(manifest), encoding="utf-8")
    fake_env, _ = make_fake_tools(tmp_path)
    argv_log = tmp_path / "runtime-argv.txt"
    fake_env["WIRECLAW_TEST_RUNTIME_ARGV"] = str(argv_log)
    runtime_dir = Path(fake_env["HOME"]) / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    result = run_bash(
        '. "$1/launch/macos/common.sh"; start_ai "$2" 18765 18766 embedded_local',
        str(ROOT),
        str(release),
        env=fake_env,
    )
    assert result.returncode == 0, result.stderr
    assert "unavailable" in result.stdout
    assert (runtime_dir / "ai-status").read_text().strip().startswith("unavailable:")
    assert "ready" not in (runtime_dir / "ai-status").read_text()
    assert "--cache-ram\n0" in argv_log.read_text(encoding="utf-8")


def test_untrusted_provider_values_cannot_override_embedded_runtime_identity(tmp_path):
    home = tmp_path / "User Home"
    runtime_dir = home / "Library/Application Support/Wireclaw/run"
    runtime_dir.mkdir(parents=True)
    (runtime_dir / "ai-status").write_text("ready\n", encoding="utf-8")
    (runtime_dir / "ai-key").write_text("private-key-do-not-print\n", encoding="utf-8")
    result = run_bash(
        '. "$1/launch/macos/common.sh"; configure_provider_environment embedded_local '
        "https://attacker.invalid/v1 attacker-model attacker-token; "
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
    assert "private-key-do-not-print" not in result.stdout


def test_start_loads_and_uses_the_packaged_image_without_rebuilding():
    assert 'load_release_image "$RELEASE_DIR"' in START_SOURCE
    assert 'compose.yaml" up -d;' in START_SOURCE
    assert "up -d --build" not in START_SOURCE


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
