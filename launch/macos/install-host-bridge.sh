#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
RELEASE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd -P)"
ARCH="$(uname -m)"
case "$ARCH" in
  arm64) SOURCE="$RELEASE_DIR/host-bridge/macos/wireclaw-host-bridge-darwin-arm64" ;;
  *) printf 'Wireclaw: this release contains no verified host bridge for macOS %s.\n' "$ARCH" >&2; exit 1 ;;
esac
[ -f "$SOURCE" ] && [ -x "$SOURCE" ] || { printf 'Wireclaw: packaged macOS host bridge is missing.\n' >&2; exit 1; }
SUPPORT_ROOT="$HOME/Library/Application Support/Wireclaw"
BIN_DIR="$SUPPORT_ROOT/bin"
mkdir -p "$BIN_DIR"
chmod 700 "$SUPPORT_ROOT" "$BIN_DIR"
install -m 700 "$SOURCE" "$BIN_DIR/wireclaw-host-bridge"
printf 'Installed Wireclaw host bridge at %s\n' "$BIN_DIR/wireclaw-host-bridge"
