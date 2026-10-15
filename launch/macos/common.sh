#!/bin/bash

set -u

wireclaw_support_root="${HOME}/Library/Application Support/Wireclaw"
wireclaw_runtime_dir="${wireclaw_support_root}/run"
wireclaw_bridge_bin="${wireclaw_support_root}/bin/wireclaw-host-bridge"
wireclaw_pid_file="${wireclaw_runtime_dir}/bridge.pid"
wireclaw_ai_pid_file="${wireclaw_runtime_dir}/ai.pid"
wireclaw_ai_status_file="${wireclaw_runtime_dir}/ai-status"
wireclaw_ai_key_file="${wireclaw_runtime_dir}/ai-key"
wireclaw_ai_log_file="${wireclaw_runtime_dir}/ai.log"
wireclaw_ai_fifo="${wireclaw_runtime_dir}/ai-log.fifo"
wireclaw_ai_port=8767
wireclaw_ai_model_id=wireclaw-qwen3-4b-instruct-2507-q4_k_m
wireclaw_ai_model_file=qwen3-4b-instruct-2507-q4_k_m.gguf
wireclaw_ai_base_url=http://host.docker.internal:8767/v1

fail() {
  printf 'Wireclaw: %s\n' "$1" >&2
  exit 1
}

ai_unavailable() {
  if [ -L "$wireclaw_ai_status_file" ]; then
    printf 'Wireclaw: Local embedded AI unavailable — deterministic analysis remains available (unsafe-state).\n'
    return
  fi
  if printf 'unavailable:%s\n' "$1" > "$wireclaw_ai_status_file"; then chmod 600 "$wireclaw_ai_status_file" 2>/dev/null || true; fi
  printf 'Wireclaw: Local embedded AI unavailable — deterministic analysis remains available (%s).\n' "$1"
}

verify_ai_bundle() {
  release_dir="$1"
  ai_root="$release_dir/ai"
  [ -d "$ai_root" ] && [ ! -L "$ai_root" ] || fail "embedded AI release directory is missing or unsafe"
  /usr/bin/python3 - "$ai_root" <<'PY'
import hashlib, json, os, pathlib, sys
root = pathlib.Path(sys.argv[1]).resolve(strict=True)
def fail():
    raise SystemExit("Wireclaw: embedded AI manifest or artifact is invalid")
def read_manifest(name):
    path = root / name
    if path.is_symlink() or not path.is_file(): fail()
    try: return json.loads(path.read_text(encoding="utf-8"))
    except Exception: fail()
def artifact(relative, digest):
    if not isinstance(relative, str) or not relative or os.path.isabs(relative): fail()
    path = root / relative
    try: resolved = path.resolve(strict=True)
    except Exception: fail()
    if resolved != path or root not in resolved.parents or path.is_symlink() or not path.is_file(): fail()
    if hashlib.sha256(path.read_bytes()).hexdigest() != digest: fail()
    return path
model = read_manifest("model-manifest.json")
runtime = read_manifest("runtime-manifest.json")
if model.get("model_id") != "wireclaw-qwen3-4b-instruct-2507-q4_k_m" or model.get("revision") != "cdbee75f17c01a7cc42f958dc650907174af0554" or model.get("license") != "Apache-2.0" or model.get("quantization") != "Q4_K_M" or model.get("architecture") != "qwen3": fail()
model_entry = model.get("artifact") or {}
model_path = artifact(model_entry.get("path"), model_entry.get("sha256"))
if model_path.stat().st_size != model_entry.get("size_bytes") or model_path.stat().st_size > 3758096384: fail()
if runtime.get("repository") != "ggml-org/llama.cpp" or runtime.get("revision") != "8345f333951c661d166b00e6f9362e553768f292" or runtime.get("platform") != "macos" or runtime.get("architecture") != "arm64" or runtime.get("entrypoint") != "macos-arm64/llama-server": fail()
if runtime.get("build_settings", {}).get("metal") is not True or runtime.get("build_settings", {}).get("server") is not True: fail()
policy = runtime.get("policy") or {}
if policy != {"platform": "macos", "architecture": "arm64", "listen_host": "127.0.0.1", "context_size": 16384, "max_tokens": 2048, "parallel": 1, "port": 8767, "model_alias": "wireclaw-qwen3-4b-instruct-2507-q4_k_m", "authentication_required": True, "agent_tools": False, "web_ui": False, "network_downloads": False}: fail()
files = runtime.get("files")
if not isinstance(files, list) or not any(item.get("path") == "macos-arm64/llama-server" for item in files if isinstance(item, dict)): fail()
for item in files:
    if not isinstance(item, dict): fail()
    runtime_path = artifact(item.get("path"), item.get("sha256"))
    if runtime_path.stat().st_size != item.get("size_bytes"): fail()
def license_file(relative):
    path = artifact(relative, hashlib.sha256((root / relative).read_bytes()).hexdigest())
    if path.stat().st_size == 0: fail()
license_file(model.get("license_path"))
licenses = runtime.get("license_paths")
if not isinstance(licenses, list) or not licenses: fail()
for relative in licenses: license_file(relative)
PY
}

ai_process_matches() {
  ai_pid="$1"
  ai_start="$2"
  ai_bin="$3"
  [ -x "$ai_bin" ] || return 1
  command -v lsof >/dev/null 2>&1 || return 1
  current_start="$(ps -p "$ai_pid" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  [ -n "$current_start" ] && [ "$current_start" = "$ai_start" ] || return 1
  [ "$(lsof -a -p "$ai_pid" -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1)" = "$ai_bin" ]
}

stop_ai() {
  [ ! -L "$wireclaw_ai_pid_file" ] || { printf 'Wireclaw: unsafe AI PID state ignored.\n' >&2; return 1; }
  [ -f "$wireclaw_ai_pid_file" ] || { rm -f "$wireclaw_ai_key_file" "$wireclaw_ai_fifo"; return 0; }
  {
    IFS= read -r ai_pid || ai_pid=''
    IFS= read -r ai_start || ai_start=''
  } < "$wireclaw_ai_pid_file"
  case "$ai_pid" in ''|*[!0-9]*) rm -f "$wireclaw_ai_pid_file" "$wireclaw_ai_key_file" "$wireclaw_ai_fifo"; return 0 ;; esac
  ai_bin="${RELEASE_DIR:-}/ai/macos-arm64/llama-server"
  if ! kill -0 "$ai_pid" 2>/dev/null || ! ai_process_matches "$ai_pid" "$ai_start" "$ai_bin"; then
    rm -f "$wireclaw_ai_pid_file" "$wireclaw_ai_key_file" "$wireclaw_ai_fifo"
    printf 'Wireclaw: stale AI PID ignored; no process was signaled.\n' >&2
    return 0
  fi
  kill -TERM "$ai_pid" 2>/dev/null || return 1
  attempts=0
  while kill -0 "$ai_pid" 2>/dev/null && [ "$attempts" -lt 10 ]; do sleep 1; attempts=$((attempts + 1)); done
  if kill -0 "$ai_pid" 2>/dev/null; then
    ai_process_matches "$ai_pid" "$ai_start" "$ai_bin" || return 1
    kill -KILL "$ai_pid" 2>/dev/null || return 1
  fi
  rm -f "$wireclaw_ai_pid_file" "$wireclaw_ai_key_file" "$wireclaw_ai_fifo"
}

probe_ai_health() {
  /usr/bin/python3 - "$wireclaw_ai_key_file" "$wireclaw_ai_model_id" <<'PY'
import json, sys, time, urllib.request
key = open(sys.argv[1], encoding="ascii").read().strip()
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
for _ in range(60):
    try:
        request = urllib.request.Request("http://127.0.0.1:8767/v1/models", headers={"Authorization": "Bearer " + key})
        with opener.open(request, timeout=1) as response:
            body = json.load(response)
        if any(item.get("id") == sys.argv[2] for item in body.get("data", [])): raise SystemExit(0)
    except Exception: pass
    time.sleep(1)
raise SystemExit(1)
PY
}

start_ai() {
  release_dir="$1"
  app_port="$2"
  bridge_port="$3"
  mode="$4"
  configured_ai_port="${5:-8767}"
  if [ "$mode" != embedded_local ]; then
    if ! stop_ai; then printf 'Wireclaw: existing embedded AI state could not be safely stopped; configured provider remains unchanged.\n' >&2; fi
    rm -f "$wireclaw_ai_status_file"
    return 0
  fi
  if [ "$configured_ai_port" != "$wireclaw_ai_port" ]; then ai_unavailable "invalid-port"; return 0; fi
  for state_file in "$wireclaw_ai_pid_file" "$wireclaw_ai_status_file" "$wireclaw_ai_key_file" "$wireclaw_ai_log_file" "$wireclaw_ai_fifo"; do
    if [ -L "$state_file" ]; then printf 'Wireclaw: Local embedded AI unavailable — deterministic analysis remains available (unsafe-state).\n'; return 0; fi
  done
  if [ "$wireclaw_ai_port" = "$app_port" ] || [ "$wireclaw_ai_port" = "$bridge_port" ]; then ai_unavailable "port-conflict"; return 0; fi
  if ! verify_ai_bundle "$release_dir" 2>/dev/null; then ai_unavailable "invalid-bundle"; return 0; fi
  ai_bin="$release_dir/ai/macos-arm64/llama-server"
  if lsof -nP -iTCP:"$wireclaw_ai_port" -sTCP:LISTEN >/dev/null 2>&1; then ai_unavailable "port-in-use"; return 0; fi
  if [ -e "$wireclaw_ai_pid_file" ] || [ -L "$wireclaw_ai_pid_file" ]; then
    if ! stop_ai; then ai_unavailable "unsafe-state"; return 0; fi
  fi
  if ! /usr/bin/python3 - "$wireclaw_ai_key_file" <<'PY'
import os, secrets, sys, tempfile
path = sys.argv[1]
fd, temporary = tempfile.mkstemp(prefix=".ai-key-", dir=os.path.dirname(path))
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="ascii") as stream:
        stream.write(secrets.token_hex(32) + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
except Exception:
    try: os.unlink(temporary)
    except OSError: pass
    raise
PY
  then ai_unavailable "secret-generation-failed"; return 0; fi
  rm -f "$wireclaw_ai_fifo"
  mkfifo -m 600 "$wireclaw_ai_fifo" || { ai_unavailable "log-init-failed"; rm -f "$wireclaw_ai_key_file"; return 0; }
  /usr/bin/python3 - "$wireclaw_ai_fifo" "$wireclaw_ai_log_file" <<'PY' &
import sys
source, destination = sys.argv[1:]
total = 0
with open(source, "rb") as inp, open(destination, "wb") as out:
    while True:
        chunk = inp.read(8192)
        if not chunk:
            break
        if total < 1048576:
            allowed = chunk[:1048576 - total]
            out.write(allowed)
            total += len(allowed)
PY
  log_pid=$!
  ( exec /usr/bin/env -i HOME="$wireclaw_runtime_dir" TMPDIR="$wireclaw_runtime_dir" PATH=/usr/bin:/bin "$ai_bin" \
      --model "$release_dir/ai/models/$wireclaw_ai_model_file" --alias "$wireclaw_ai_model_id" \
      --host 127.0.0.1 --port "$wireclaw_ai_port" --ctx-size 16384 --n-predict 2048 --parallel 1 \
      --api-key-file "$wireclaw_ai_key_file" --no-agent --no-webui ) > "$wireclaw_ai_fifo" 2>&1 &
  AI_PID=$!
  rm -f "$wireclaw_ai_fifo"
  AI_START="$(ps -p "$AI_PID" -o lstart= 2>/dev/null | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')"
  if [ -z "$AI_START" ]; then ai_unavailable "runtime-start-failed"; rm -f "$wireclaw_ai_key_file"; return 0; fi
  if ! /usr/bin/python3 - "$wireclaw_ai_pid_file" "$AI_PID" "$AI_START" <<'PY'
import os, sys, tempfile
path, pid, identity = sys.argv[1:]
fd, temporary = tempfile.mkstemp(prefix=".ai-pid-", dir=os.path.dirname(path))
try:
    os.fchmod(fd, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        stream.write(pid + "\n" + identity + "\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)
except Exception:
    try: os.unlink(temporary)
    except OSError: pass
    raise
PY
  then
    if ai_process_matches "$AI_PID" "$AI_START" "$ai_bin"; then kill -TERM "$AI_PID" 2>/dev/null || true; fi
    ai_unavailable "state-write-failed"
    return 0
  fi
  if ! probe_ai_health || ! ai_process_matches "$AI_PID" "$AI_START" "$ai_bin"; then
    stop_ai || true
    ai_unavailable "runtime-unhealthy"
    return 0
  fi
  printf 'ready\n' > "$wireclaw_ai_status_file"
  chmod 600 "$wireclaw_ai_status_file"
}

configure_provider_environment() {
  configured_mode="$1"
  if [ "$configured_mode" != embedded_local ]; then
    export WIRECLAW_PROVIDER_MODE="$configured_mode"
    export WIRECLAW_PROVIDER_BASE_URL="${2:-}"
    export WIRECLAW_PROVIDER_MODEL="${3:-}"
    export WIRECLAW_PROVIDER_API_KEY="${4:-}"
    export WIRECLAW_EMBEDDED_AI_STATUS=not_applicable
    return 0
  fi
  status="$(cat "$wireclaw_ai_status_file" 2>/dev/null || printf 'unavailable:not-ready')"
  if [ "$status" = ready ] && [ -f "$wireclaw_ai_key_file" ] && [ ! -L "$wireclaw_ai_key_file" ]; then
    export WIRECLAW_PROVIDER_MODE=embedded_local
    export WIRECLAW_PROVIDER_BASE_URL="$wireclaw_ai_base_url"
    export WIRECLAW_PROVIDER_MODEL="$wireclaw_ai_model_id"
    export WIRECLAW_PROVIDER_API_KEY="$(cat "$wireclaw_ai_key_file")"
    export WIRECLAW_EMBEDDED_AI_STATUS=ready
    return 0
  fi
  failure="${status#unavailable:}"
  [ "$failure" != "$status" ] || failure=not-ready
  export WIRECLAW_PROVIDER_MODE=none
  export WIRECLAW_PROVIDER_BASE_URL=
  export WIRECLAW_PROVIDER_MODEL=
  export WIRECLAW_PROVIDER_API_KEY=
  export WIRECLAW_EMBEDDED_AI_STATUS="unavailable:$failure"
}

probe_ai_from_core() {
  release_dir="$1"
  env_file="$2"
  probe_script='import json,os,urllib.request; req=urllib.request.Request("http://host.docker.internal:8767/v1/models",headers={"Authorization":"Bearer "+os.environ["WIRECLAW_PROVIDER_API_KEY"]}); opener=urllib.request.build_opener(urllib.request.ProxyHandler({})); body=json.load(opener.open(req,timeout=3)); expected="wireclaw-qwen3-4b-instruct-2507-q4_k_m"; raise SystemExit(0 if any(item.get("id")==expected for item in body.get("data",[])) else 1)'
  docker compose --env-file "$env_file" -f "$release_dir/compose.yaml" run --rm --no-deps --entrypoint python wireclaw-core -c "$probe_script" >/dev/null 2>&1
}

load_release_image() {
  release_dir="$1"
  image_archive="$release_dir/core-image.tar"
  image_id_file="$release_dir/core-image-id"
  [ -f "$image_archive" ] && [ -r "$image_archive" ] || fail "the packaged core image archive is missing"
  [ -f "$image_id_file" ] && [ -r "$image_id_file" ] || fail "the packaged core image identity is missing"
  expected_image_id="$(cat "$image_id_file")"
  case "$expected_image_id" in sha256:*) image_digest="${expected_image_id#sha256:}" ;; *) fail "the packaged core image identity is invalid" ;; esac
  [ "${#image_digest}" -eq 64 ] || fail "the packaged core image identity is invalid"
  case "$image_digest" in *[!0-9a-f]*) fail "the packaged core image identity is invalid" ;; esac
  actual_image_id="$(docker image inspect --format '{{.Id}}' wireclaw-core:gate8 2>/dev/null || true)"
  if [ "$actual_image_id" != "$expected_image_id" ]; then
    docker load --input "$image_archive" >/dev/null || fail "could not load the packaged core image"
    actual_image_id="$(docker image inspect --format '{{.Id}}' wireclaw-core:gate8 2>/dev/null || true)"
  fi
  [ "$actual_image_id" = "$expected_image_id" ] || fail "loaded core image does not match the packaged release identity"
}

# Read one allowlisted KEY=value without evaluating shell syntax.
read_env_value() {
  wanted="$1"
  file="$2"
  found=0
  result=''
  while IFS= read -r line || [ -n "$line" ]; do
    line="${line%$'\r'}"
    case "$line" in
      "$wanted="*)
        [ "$found" -eq 0 ] || fail "duplicate $wanted in .env"
        found=1
        result="${line#*=}"
        ;;
    esac
  done < "$file"
  if [ "${#result}" -ge 2 ]; then
    first="${result:0:1}"
    last="${result: -1}"
    if { [ "$first" = '"' ] && [ "$last" = '"' ]; } || { [ "$first" = "'" ] && [ "$last" = "'" ]; }; then
      result="${result:1:${#result}-2}"
    fi
  fi
  case "$result" in
    *'`'*|*'$('*|*'\'*|*'"'*|*"'"*|*$'\n'*|*$'\t'*) fail "unsafe value for $wanted in .env" ;;
  esac
  case "$result" in
    '${HOME}'*) result="${HOME}${result#'${HOME}'}" ;;
    *'${'*|*'$'*) fail "unsupported interpolation in $wanted; only a leading \${HOME} is allowed" ;;
  esac
  printf '%s' "$result"
}

validate_port() {
  label="$1"
  value="$2"
  case "$value" in
    ''|*[!0-9]*) fail "$label must be a port number from 1 to 65535" ;;
  esac
  [ "$value" -ge 1 ] && [ "$value" -le 65535 ] || fail "$label must be a port number from 1 to 65535"
}

resolve_data_root() {
  input="$1"
  case "$input" in
    /*) ;;
    *) fail "WIRECLAW_DATA_ROOT must resolve to an absolute path" ;;
  esac
  mkdir -p "$input" 2>/dev/null || fail "cannot create the Wireclaw data root: $input"
  [ -d "$input" ] && [ -w "$input" ] || fail "Wireclaw data root is not writable: $input"
  (cd "$input" && pwd -P) || fail "cannot resolve Wireclaw data root"
}

bridge_process_matches() {
  pid="$1"
  [ -x "$wireclaw_bridge_bin" ] || return 1
  command -v lsof >/dev/null 2>&1 || return 1
  [ "$(lsof -a -p "$pid" -d txt -Fn 2>/dev/null | sed -n 's/^n//p' | head -n 1)" = "$wireclaw_bridge_bin" ]
}

stop_bridge() {
  [ -f "$wireclaw_pid_file" ] || return 0
  IFS= read -r bridge_pid < "$wireclaw_pid_file" || bridge_pid=''
  case "$bridge_pid" in
    ''|*[!0-9]*) rm -f "$wireclaw_pid_file"; return 0 ;;
  esac
  if ! kill -0 "$bridge_pid" 2>/dev/null; then
    rm -f "$wireclaw_pid_file"
    return 0
  fi
  if ! bridge_process_matches "$bridge_pid"; then
    rm -f "$wireclaw_pid_file"
    printf 'Wireclaw: stale bridge PID ignored; no process was signaled.\n' >&2
    return 0
  fi
  kill -TERM "$bridge_pid" 2>/dev/null || return 1
  attempts=0
  while kill -0 "$bridge_pid" 2>/dev/null && [ "$attempts" -lt 10 ]; do
    sleep 1
    attempts=$((attempts + 1))
  done
  if kill -0 "$bridge_pid" 2>/dev/null; then
    bridge_process_matches "$bridge_pid" || return 1
    kill -KILL "$bridge_pid" 2>/dev/null || return 1
  fi
  rm -f "$wireclaw_pid_file"
}
