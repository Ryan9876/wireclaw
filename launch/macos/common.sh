#!/bin/bash

set -u

wireclaw_support_root="${HOME}/Library/Application Support/Wireclaw"
wireclaw_runtime_dir="${wireclaw_support_root}/run"
wireclaw_bridge_bin="${wireclaw_support_root}/bin/wireclaw-host-bridge"
wireclaw_pid_file="${wireclaw_runtime_dir}/bridge.pid"
wireclaw_ai_status_file="${wireclaw_runtime_dir}/ai-status"
wireclaw_ai_app=""
wireclaw_ai_wrapper=""
wireclaw_ai_helper=""
wireclaw_ai_start_key=""
wireclaw_ai_release_dir=""
wireclaw_ai_port=8767
wireclaw_ai_model_id=wireclaw-qwen3-4b-instruct-2507-q4_k_m
wireclaw_ai_base_url=http://host.docker.internal:8767/v1
wireclaw_ai_host_receipt_file="${wireclaw_runtime_dir}/ai-host-receipt.json"
wireclaw_ai_lifecycle_tool="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd -P)/ai_lifecycle.py"

# Task 6 trusted-host primitives. Task 7 wires these into start/stop order.
# create/recover read the bounded internal wrapper receipt on stdin.
ai_host_receipt_create() {
  /usr/bin/python3 "$wireclaw_ai_lifecycle_tool" create "$wireclaw_ai_host_receipt_file" "$1"
}

ai_host_receipt_recover() {
  /usr/bin/python3 "$wireclaw_ai_lifecycle_tool" recover "$wireclaw_ai_host_receipt_file" "$1"
}

ai_host_stop_verified() {
  /usr/bin/python3 "$wireclaw_ai_lifecycle_tool" stop "$wireclaw_ai_host_receipt_file" "$1"
}

ai_host_receipt_remove() {
  /usr/bin/python3 "$wireclaw_ai_lifecycle_tool" remove "$wireclaw_ai_host_receipt_file" "$1"
}

fail() {
  printf 'Wireclaw: %s\n' "$1" >&2
  exit 1
}

ai_listener_matches() {
  ai_pid="$1"
  ai_port="$2"
  command -v lsof >/dev/null 2>&1 || return 1
  lsof -nP -a -p "$ai_pid" -iTCP:"$ai_port" -sTCP:LISTEN -Fn 2>/dev/null \
    | grep -Fx "n127.0.0.1:$ai_port" >/dev/null
}

ai_codesign_verify() {
  /usr/bin/codesign --verify --strict --verbose=4 "$1" >/dev/null 2>&1
}

ai_wrapper_signature_valid() {
  [ -d "$wireclaw_ai_app" ] && [ ! -L "$wireclaw_ai_app" ] \
    && [ -x "$wireclaw_ai_wrapper" ] && [ ! -L "$wireclaw_ai_wrapper" ] \
    && ai_codesign_verify "$wireclaw_ai_app"
}

ai_wrapper_call() {
  operation="$1"
  key="${2:-}"
  case "$operation" in start|status|stop) ;; *) return 1 ;; esac
  ai_wrapper_signature_valid || return 1
  if [ "$operation" = start ]; then
    [ "${#key}" -eq 64 ] || return 1
    case "$key" in *[!0-9a-f]*) return 1 ;; esac
    output="$(printf '%s\n' "$key" | /usr/bin/env -i HOME="$HOME" TMPDIR="$wireclaw_runtime_dir" PATH=/usr/bin:/bin \
      "$wireclaw_ai_wrapper" "$operation" 3<&0)" || return 1
  else
    output="$(/usr/bin/env -i HOME="$HOME" TMPDIR="$wireclaw_runtime_dir" PATH=/usr/bin:/bin \
      "$wireclaw_ai_wrapper" "$operation" </dev/null)" || return 1
  fi
  [ "${#output}" -le 1024 ] || return 1
  printf '%s' "$output"
}

ai_status_is_running() {
  /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if isinstance(d,dict) and d.get("state")=="running" else 1)' <<< "$1" 2>/dev/null
}

ai_status_is_stopped() {
  /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d=={"state":"stopped"} else 1)' <<< "$1" 2>/dev/null
}

ai_status_is_process_missing() {
  /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d=={"state":"unavailable","reason":"process_missing"} else 1)' <<< "$1" 2>/dev/null
}

ai_receipt_pid() {
  /usr/bin/python3 -c 'import json,re,sys; d=json.load(sys.stdin); p=d.get("pid"); e=d.get("executable"); h=d.get("executable_sha256"); t=d.get("process_start"); ok=set(d)=={"state","pid","process_start","executable","executable_sha256"} and d.get("state")=="running" and type(p) is int and 0<p<=999999 and isinstance(t,str) and re.fullmatch(r"[0-9]{1,20}:[0-9]{1,6}",t) and e==sys.argv[1] and isinstance(h,str) and re.fullmatch(r"[0-9a-f]{64}",h); print(p) if ok else sys.exit(1)' "$wireclaw_ai_helper" <<< "$1" 2>/dev/null
}

ai_status_receipt() { ai_wrapper_call status; }

ai_recover_host_receipt() {
  printf '%s\n' "$1" | ai_host_receipt_recover "$wireclaw_ai_helper"
}

ai_recover_failed_start() {
  receipt="$(ai_status_receipt 2>/dev/null)" || return 1
  if ai_status_is_running "$receipt"; then
    ai_recover_host_receipt "$receipt" || return 1
    ai_host_stop_verified "$wireclaw_ai_helper" || return 1
    cleanup="$(ai_wrapper_call stop 2>/dev/null)" || return 1
    ai_status_is_stopped "$cleanup" || return 1
    ai_host_receipt_remove "$wireclaw_ai_helper" || return 1
  elif ai_status_is_stopped "$receipt"; then
    cleanup="$(ai_wrapper_call stop 2>/dev/null)" || return 1
    ai_status_is_stopped "$cleanup" || return 1
  elif ai_status_is_process_missing "$receipt"; then
    cleanup="$(ai_wrapper_call stop 2>/dev/null)" || return 1
    ai_status_is_stopped "$cleanup" || return 1
  else
    return 1
  fi
  wireclaw_ai_start_key=''
}

ai_unavailable() {
  reason="$1"
  case "$reason" in invalid-port|port-conflict|port-in-use|unsafe-state|invalid-app|invalid-signature|start-failed|receipt-failed|readiness-failed|verification-failed|secret-generation-failed|unavailable) ;; *) reason=unavailable ;; esac
  if [ -L "$wireclaw_ai_status_file" ]; then
    printf 'Wireclaw: Local embedded AI unavailable — deterministic analysis remains available (unsafe-state).\n'
    return
  fi
  if printf 'unavailable:%s\n' "$reason" > "$wireclaw_ai_status_file"; then chmod 600 "$wireclaw_ai_status_file" 2>/dev/null || true; fi
  printf 'Wireclaw: Local embedded AI unavailable — deterministic analysis remains available (%s).\n' "$reason"
}

validate_runtime_path() {
  /usr/bin/python3 - "$wireclaw_support_root" "$wireclaw_runtime_dir" <<'PY'
import os, pathlib, stat, sys

for value in sys.argv[1:]:
    path = pathlib.Path(value)
    if not path.is_absolute():
        raise SystemExit("Wireclaw: runtime path must be absolute")
    if str(path) != os.path.normpath(value):
        raise SystemExit("Wireclaw: runtime path is not normalized")
    current = pathlib.Path(path.anchor)
    for part in path.parts[1:]:
        current = current / part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or not stat.S_ISDIR(info.st_mode):
            raise SystemExit("Wireclaw: runtime path contains an unsafe component")
        if current == pathlib.Path(value) and info.st_uid != os.getuid():
            raise SystemExit("Wireclaw: runtime directory is not owned by the current user")
PY
}

stop_ai() {
  wireclaw_ai_app="${RELEASE_DIR:-$wireclaw_ai_release_dir}/ai/WireclawAI.app"
  wireclaw_ai_wrapper="$wireclaw_ai_app/Contents/MacOS/WireclawAI"
  wireclaw_ai_helper="$wireclaw_ai_app/Contents/MacOS/llama-server"
  if [ ! -e "$wireclaw_ai_host_receipt_file" ] && [ ! -L "$wireclaw_ai_host_receipt_file" ]; then
    status_receipt="$(ai_status_receipt 2>/dev/null)" || status_receipt=''
    if [ -n "$status_receipt" ] && ai_status_is_running "$status_receipt"; then
      ai_recover_host_receipt "$status_receipt" || return 1
    elif [ -n "$status_receipt" ] && ai_status_is_stopped "$status_receipt"; then
      cleanup="$(ai_wrapper_call stop 2>/dev/null)" || return 1
      ai_status_is_stopped "$cleanup" || return 1
      rm -f "$wireclaw_ai_status_file"
      wireclaw_ai_start_key=''
      return 0
    elif [ -n "$status_receipt" ] && ai_status_is_process_missing "$status_receipt"; then
      cleanup="$(ai_wrapper_call stop 2>/dev/null)" || return 1
      ai_status_is_stopped "$cleanup" || return 1
      rm -f "$wireclaw_ai_status_file"
      wireclaw_ai_start_key=''
      return 0
    else
      if [ ! -e "$wireclaw_ai_wrapper" ] && [ ! -L "$wireclaw_ai_host_receipt_file" ]; then
        return 0
      fi
      return 1
    fi
  fi
  status_receipt="$(ai_status_receipt 2>/dev/null)" || status_receipt=''
  if [ -n "$status_receipt" ] && ai_status_is_running "$status_receipt"; then
    if ! ai_host_stop_verified "$wireclaw_ai_helper"; then
      ai_recover_host_receipt "$status_receipt" || return 1
      ai_host_stop_verified "$wireclaw_ai_helper" || return 1
    fi
  else
    ai_host_stop_verified "$wireclaw_ai_helper" || return 1
  fi
  cleanup="$(ai_wrapper_call stop 2>/dev/null)" || return 1
  /usr/bin/python3 -c 'import json,sys; d=json.load(sys.stdin); sys.exit(0 if d=={"state":"stopped"} else 1)' <<< "$cleanup" || return 1
  ai_host_receipt_remove "$wireclaw_ai_helper" || return 1
  rm -f "$wireclaw_ai_status_file"
  wireclaw_ai_start_key=''
}

probe_ai_health() {
  ai_pid="$1"
  ai_key="$2"
  /usr/bin/python3 - "$ai_pid" "$wireclaw_ai_model_id" "$wireclaw_ai_port" 3<<<"$ai_key" <<'PY'
import json, re, socket, subprocess, sys, time
pid, model_id, port = sys.argv[1:]
key = __import__("os").read(3, 128).decode("ascii").strip()
if not re.fullmatch(r"[0-9a-f]{64}", key): raise SystemExit(1)
for _ in range(60):
    try:
        listener = subprocess.run(
            ["/usr/sbin/lsof", "-nP", "-a", "-p", pid, f"-iTCP:{port}", "-sTCP:LISTEN", "-Fn"],
            capture_output=True, text=True, check=False,
        )
        if listener.returncode or f"n127.0.0.1:{port}" not in listener.stdout.splitlines():
            raise RuntimeError("listener_not_owned")
        with socket.create_connection(("127.0.0.1", int(port)), timeout=1) as connection:
            connection.sendall((
                "GET /v1/models HTTP/1.1\r\nHost: 127.0.0.1\r\n"
                "Authorization: Bearer " + key + "\r\nConnection: close\r\n\r\n"
            ).encode("ascii"))
            response = b""
            while len(response) <= 1048576:
                chunk = connection.recv(65536)
                if not chunk: break
                response += chunk
        headers, payload = response.split(b"\r\n\r\n", 1)
        if b" 200 " not in headers.split(b"\r\n", 1)[0]: raise RuntimeError("health_status_invalid")
        body = json.loads(payload)
        if isinstance(body, dict) and any(isinstance(item, dict) and item.get("id") == model_id for item in body.get("data", [])):
            raise SystemExit(0)
    except Exception:
        pass
    time.sleep(1)
raise SystemExit(1)
PY
}

start_ai() {
  release_dir="$1"
  wireclaw_ai_release_dir="$release_dir"
  app_port="$2"
  bridge_port="$3"
  mode="$4"
  configured_ai_port="${5:-8767}"
  wireclaw_ai_app="$release_dir/ai/WireclawAI.app"
  wireclaw_ai_wrapper="$wireclaw_ai_app/Contents/MacOS/WireclawAI"
  wireclaw_ai_helper="$wireclaw_ai_app/Contents/MacOS/llama-server"
  if [ "$mode" != embedded_local ]; then
    if ! stop_ai; then printf 'Wireclaw: existing embedded AI state could not be safely stopped; configured provider remains unchanged.\n' >&2; fi
    rm -f "$wireclaw_ai_status_file"
    return 0
  fi
  if [ "$configured_ai_port" != "$wireclaw_ai_port" ]; then ai_unavailable invalid-port; return 0; fi
  for state_file in "$wireclaw_ai_status_file" "$wireclaw_ai_host_receipt_file"; do
    if [ -L "$state_file" ]; then ai_unavailable unsafe-state; return 0; fi
  done
  if [ "$wireclaw_ai_port" = "$app_port" ] || [ "$wireclaw_ai_port" = "$bridge_port" ]; then ai_unavailable port-conflict; return 0; fi
  if [ ! -d "$wireclaw_ai_app" ] || [ -L "$wireclaw_ai_app" ] || [ ! -x "$wireclaw_ai_wrapper" ] || [ ! -x "$wireclaw_ai_helper" ]; then
    ai_unavailable invalid-app; return 0
  fi
  if ! ai_wrapper_signature_valid; then ai_unavailable invalid-signature; return 0; fi
  if command -v lsof >/dev/null 2>&1 && lsof -nP -iTCP:"$wireclaw_ai_port" -sTCP:LISTEN >/dev/null 2>&1; then ai_unavailable port-in-use; return 0; fi
  if [ -e "$wireclaw_ai_host_receipt_file" ] || [ -L "$wireclaw_ai_host_receipt_file" ]; then
    if ! stop_ai; then ai_unavailable unsafe-state; return 0; fi
  fi
  wireclaw_ai_start_key="$(/usr/bin/python3 -c 'import secrets; print(secrets.token_hex(32))')" || { ai_unavailable secret-generation-failed; return 0; }
  if [ "${#wireclaw_ai_start_key}" -ne 64 ]; then ai_unavailable secret-generation-failed; return 0; fi
  wrapper_receipt="$(ai_wrapper_call start "$wireclaw_ai_start_key" 2>/dev/null)" || {
    wireclaw_ai_start_key=''
    ai_recover_failed_start || true
    ai_unavailable start-failed
    return 0
  }
  ai_pid="$(ai_receipt_pid "$wrapper_receipt")" || {
    wireclaw_ai_start_key=''
    ai_recover_failed_start || true
    ai_unavailable verification-failed
    return 0
  }
  if ! printf '%s\n' "$wrapper_receipt" | ai_host_receipt_create "$wireclaw_ai_helper"; then
    wireclaw_ai_start_key=''
    ai_recover_failed_start || true
    ai_unavailable receipt-failed
    return 0
  fi
  if ! probe_ai_health "$ai_pid" "$wireclaw_ai_start_key" || ! ai_listener_matches "$ai_pid" "$wireclaw_ai_port"; then
    wireclaw_ai_start_key=''
    stop_ai || true
    ai_unavailable readiness-failed
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
  if [ "$status" = ready ] && [ "${#wireclaw_ai_start_key}" -eq 64 ]; then
    export WIRECLAW_PROVIDER_MODE=embedded_local
    export WIRECLAW_PROVIDER_BASE_URL="$wireclaw_ai_base_url"
    export WIRECLAW_PROVIDER_MODEL="$wireclaw_ai_model_id"
    export WIRECLAW_PROVIDER_API_KEY="$wireclaw_ai_start_key"
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
