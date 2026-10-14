#!/bin/bash
set -u

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
RELEASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
. "$SCRIPT_DIR/common.sh"

stop_failed=0
if ! stop_bridge; then
  printf 'Wireclaw: failed to stop the host bridge safely.\n' >&2
  stop_failed=1
fi
if command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
  ENV_FILE="$RELEASE_DIR/.env"
  if [ -f "$ENV_FILE" ] && docker info >/dev/null 2>&1; then
    if ! docker compose --env-file "$ENV_FILE" -f "$RELEASE_DIR/compose.yaml" down --remove-orphans; then
      printf 'Wireclaw: Compose stop failed; case data was not removed.\n' >&2
      stop_failed=1
    fi
  elif [ -f "$ENV_FILE" ]; then
    printf 'Wireclaw: Docker daemon is unavailable; the core could not be stopped. Case data is unchanged.\n' >&2
    stop_failed=1
  fi
else
  printf 'Wireclaw: Docker Compose is unavailable; the core could not be stopped. Case data is unchanged.\n' >&2
  stop_failed=1
fi
[ "$stop_failed" -eq 0 ] || exit 1
printf 'Wireclaw stopped. Case data was preserved.\n'
