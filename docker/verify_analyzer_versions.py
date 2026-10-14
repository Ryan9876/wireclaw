"""Fail the image build if its recorded deterministic toolchain does not match the lock."""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path

DEFAULT_LOCK = Path(__file__).with_name("analyzer-versions.lock")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, default=DEFAULT_LOCK)
    args = parser.parse_args()
    lock = json.loads(args.lock.read_text(encoding="utf-8"))
    commands = {
        "python": (["python3.12", "--version"], lock["python"]),
        "tshark": (["tshark", "--version"], lock["tshark"]),
        "capinfos": (["capinfos", "--version"], lock["capinfos"]),
        "editcap": (["editcap", "--version"], lock["editcap"]),
        "mergecap": (["mergecap", "--version"], lock["mergecap"]),
    }
    for tool, (argv, expected) in commands.items():
        result = subprocess.run(argv, check=True, capture_output=True, text=True)
        output = result.stdout + result.stderr
        if tool == "python":
            actual = re.search(r"Python (\d+\.\d+\.\d+)", output)
        else:
            actual = re.search(r"\b(\d+\.\d+\.\d+)\b", output)
        if actual is None or actual.group(1) != expected:
            raise SystemExit(f"{tool}_version_mismatch: expected {expected}")
        print(f"{tool}={actual.group(1)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
