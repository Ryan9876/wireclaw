#!/bin/bash
set -eu

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd -P)"
. "$SCRIPT_DIR/common.sh"

stop_bridge || fail "could not stop the Wireclaw host bridge; no files were removed"
rm -f "$wireclaw_bridge_bin"
rmdir "$wireclaw_support_root/bin" 2>/dev/null || true
rmdir "$wireclaw_runtime_dir" 2>/dev/null || true
printf 'Removed Wireclaw host bridge. Case data was preserved.\n'
