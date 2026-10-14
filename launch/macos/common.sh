#!/bin/bash

set -u

wireclaw_support_root="${HOME}/Library/Application Support/Wireclaw"
wireclaw_runtime_dir="${wireclaw_support_root}/run"
wireclaw_bridge_bin="${wireclaw_support_root}/bin/wireclaw-host-bridge"
wireclaw_pid_file="${wireclaw_runtime_dir}/bridge.pid"

fail() {
  printf 'Wireclaw: %s\n' "$1" >&2
  exit 1
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
