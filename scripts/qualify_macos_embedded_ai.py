#!/usr/bin/env python3
"""Run the opt-in signed native App Sandbox boundary probe on Apple Silicon."""
from __future__ import annotations

import os
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if sys.platform != "darwin" or platform.machine() != "arm64":
        print("Task 9 native qualification requires macOS arm64", file=sys.stderr)
        return 2
    env = os.environ.copy()
    env["WIRECLAW_NATIVE_TASK9"] = "1"
    result = subprocess.run(
        ["go", "test", "-run", "^TestNativeTask9Isolation$", "-count=1", "-v"],
        cwd=ROOT / "ai/macos/WireclawAI",
        env=env,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        check=False,
    )
    output = result.stdout
    if result.returncode:
        # The probe output is fixed and secret-free. Bound diagnostics even on failure.
        print(output[-4096:], end="" if output.endswith("\n") else "\n")
        return result.returncode
    # Preserve explicit DENIED/NOT_RUN evidence while keeping output bounded.
    print(output[-4096:], end="" if output.endswith("\n") else "\n")
    print("Task 9 signed App Sandbox isolation: PASS")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
