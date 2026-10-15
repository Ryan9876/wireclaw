#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
RELEASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
. "$SCRIPT_DIR/common.sh"

command -v docker >/dev/null 2>&1 || fail "Docker CLI is missing. Install and start Docker Desktop, then retry."
docker compose version >/dev/null 2>&1 || fail "Docker Compose is unavailable. Install a Docker runtime with Compose v2."
docker info >/dev/null 2>&1 || fail "Docker daemon is not running. Start Docker Desktop, wait for it to be ready, then retry."

ENV_FILE="$RELEASE_DIR/.env"
if [ ! -f "$ENV_FILE" ]; then
  cp "$RELEASE_DIR/.env.example" "$ENV_FILE" || fail "could not create .env from .env.example"
  chmod 600 "$ENV_FILE"
  printf 'Created %s with the packaged provider defaults.\n' "$ENV_FILE"
fi
APP_PORT="$(read_env_value WIRECLAW_PORT "$ENV_FILE")"
BRIDGE_PORT="$(read_env_value WIRECLAW_BRIDGE_PORT "$ENV_FILE")"
DATA_CONFIG="$(read_env_value WIRECLAW_DATA_ROOT "$ENV_FILE")"
PROVIDER_MODE="$(read_env_value WIRECLAW_PROVIDER_MODE "$ENV_FILE")"
PROVIDER_BASE_URL="$(read_env_value WIRECLAW_PROVIDER_BASE_URL "$ENV_FILE")"
PROVIDER_MODEL="$(read_env_value WIRECLAW_PROVIDER_MODEL "$ENV_FILE")"
PROVIDER_API_KEY="$(read_env_value WIRECLAW_PROVIDER_API_KEY "$ENV_FILE")"
AI_PORT_CONFIG="$(read_env_value WIRECLAW_AI_PORT "$ENV_FILE")"
[ -n "$AI_PORT_CONFIG" ] || AI_PORT_CONFIG=8767
validate_port WIRECLAW_PORT "$APP_PORT"
validate_port WIRECLAW_BRIDGE_PORT "$BRIDGE_PORT"
[ "$APP_PORT" != "$BRIDGE_PORT" ] || fail "application and bridge ports must differ"
case "$PROVIDER_MODE" in
  none|openai_compatible_cloud|openai_compatible_local|embedded_local) ;;
  *) fail "WIRECLAW_PROVIDER_MODE must be none, openai_compatible_cloud, openai_compatible_local, or embedded_local" ;;
esac
DATA_ROOT="$(resolve_data_root "$DATA_CONFIG")"
[ -x "$wireclaw_bridge_bin" ] || fail "Wireclaw host bridge is not installed. Run launch/macos/install-host-bridge.sh."
WIRESHARK="${WIRECLAW_WIRESHARK_PATH:-}"
if [ -n "$WIRESHARK" ]; then
  [ -x "$WIRESHARK" ] || fail "configured Wireshark executable is not available; check WIRECLAW_WIRESHARK_PATH"
elif [ -x /Applications/Wireshark.app/Contents/MacOS/Wireshark ]; then
  WIRESHARK=/Applications/Wireshark.app/Contents/MacOS/Wireshark
elif command -v wireshark >/dev/null 2>&1; then
  WIRESHARK="$(command -v wireshark)"
else
  fail "Wireshark was not found. Install the native Wireshark application or set WIRECLAW_WIRESHARK_PATH."
fi

command -v lsof >/dev/null 2>&1 || fail "lsof is required for safe port and process checks on macOS."
for port in "$APP_PORT" "$BRIDGE_PORT"; do
  if lsof -nP -iTCP:"$port" -sTCP:LISTEN >/dev/null 2>&1; then
    fail "port $port is already in use. Stop the conflicting app or choose another port in .env."
  fi
done
if [ -L "$wireclaw_support_root" ] || [ -L "$wireclaw_runtime_dir" ]; then
  fail "Wireclaw runtime directory cannot be a symlink"
fi
mkdir -p "$wireclaw_runtime_dir"
chmod 700 "$wireclaw_support_root" "$wireclaw_runtime_dir"
start_ai "$RELEASE_DIR" "$APP_PORT" "$BRIDGE_PORT" "$PROVIDER_MODE" "$AI_PORT_CONFIG"
export WIRECLAW_DATA_ROOT="$DATA_ROOT"
export WIRECLAW_UID="$(id -u)"
export WIRECLAW_GID="$(id -g)"
load_release_image "$RELEASE_DIR"
configure_provider_environment "$PROVIDER_MODE" "$PROVIDER_BASE_URL" "$PROVIDER_MODEL" "$PROVIDER_API_KEY"
if [ "$PROVIDER_MODE" = embedded_local ] && [ "$WIRECLAW_PROVIDER_MODE" = embedded_local ]; then
  if ! probe_ai_from_core "$RELEASE_DIR" "$ENV_FILE"; then
    stop_ai || true
    ai_unavailable "docker-connectivity"
    configure_provider_environment embedded_local
  fi
fi
docker compose --env-file "$ENV_FILE" -f "$RELEASE_DIR/compose.yaml" config --quiet \
  || fail "Compose configuration is invalid; review .env against .env.example."
if ! docker compose --env-file "$ENV_FILE" -f "$RELEASE_DIR/compose.yaml" up -d; then
  docker compose --env-file "$ENV_FILE" -f "$RELEASE_DIR/compose.yaml" stop wireclaw-core >/dev/null 2>&1 || true
  fail "Wireclaw core did not start. Check Docker Desktop and the packaged release files."
fi

ready=0
attempt=0
while [ "$attempt" -lt 45 ]; do
  container_id="$(docker compose --env-file "$ENV_FILE" -f "$RELEASE_DIR/compose.yaml" ps -q wireclaw-core 2>/dev/null || true)"
  if [ -n "$container_id" ] && [ "$(docker inspect --format '{{.State.Health.Status}}' "$container_id" 2>/dev/null || true)" = healthy ]; then
    ready=1
    break
  fi
  sleep 2
  attempt=$((attempt + 1))
done
if [ "$ready" -ne 1 ]; then
  docker compose --env-file "$ENV_FILE" -f "$RELEASE_DIR/compose.yaml" stop wireclaw-core >/dev/null 2>&1 || true
  fail "Wireclaw core did not become healthy within 90 seconds. Data was preserved; inspect Docker Desktop logs."
fi

if [ -f "$wireclaw_pid_file" ]; then
  stop_bridge || fail "existing Wireclaw bridge could not be stopped safely"
fi
if [ -n "$WIRESHARK" ]; then
  "$wireclaw_bridge_bin" --data-root "$DATA_ROOT" --listen "127.0.0.1:$BRIDGE_PORT" --app-port "$APP_PORT" --wireshark "$WIRESHARK" >/dev/null 2>&1 &
else
  "$wireclaw_bridge_bin" --data-root "$DATA_ROOT" --listen "127.0.0.1:$BRIDGE_PORT" --app-port "$APP_PORT" >/dev/null 2>&1 &
fi
BRIDGE_PID=$!
printf '%s\n' "$BRIDGE_PID" > "$wireclaw_pid_file"
chmod 600 "$wireclaw_pid_file"
bridge_ready=0
attempt=0
while [ "$attempt" -lt 10 ]; do
  if ! kill -0 "$BRIDGE_PID" 2>/dev/null; then break; fi
  if curl --silent --fail --header "Origin: http://127.0.0.1:$APP_PORT" \
    "http://127.0.0.1:$BRIDGE_PORT/v1/health" >/dev/null 2>&1; then
    bridge_ready=1
    break
  fi
  sleep 1
  attempt=$((attempt + 1))
done
if [ "$bridge_ready" -ne 1 ]; then
  stop_bridge || true
  docker compose --env-file "$ENV_FILE" -f "$RELEASE_DIR/compose.yaml" stop wireclaw-core >/dev/null 2>&1 || true
  fail "Wireclaw host bridge did not become ready. Check Wireshark configuration; case data was preserved."
fi
if [ "$PROVIDER_MODE" = embedded_local ] && [ "$(cat "$wireclaw_ai_status_file" 2>/dev/null || true)" = ready ]; then
  printf 'Wireclaw core, host bridge, and local embedded AI are ready.\n'
fi
printf 'Open http://127.0.0.1:%s\n' "$APP_PORT"
