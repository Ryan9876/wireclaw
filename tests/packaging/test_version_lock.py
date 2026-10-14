import json
import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
CHECKER = ROOT / "docker/verify_analyzer_versions.py"


def test_version_lock_checker_fails_on_installed_analyzer_drift(tmp_path):
    fake_bin = tmp_path / "bin"
    fake_bin.mkdir()
    versions = {
        "python3.12": "Python 3.12.3",
        "tshark": "TShark (Wireshark) 4.2.3",
        "capinfos": "Capinfos (Wireshark) 4.2.2",
        "editcap": "Editcap (Wireshark) 4.2.2",
        "mergecap": "Mergecap (Wireshark) 4.2.2",
    }
    for command, version in versions.items():
        executable = fake_bin / command
        executable.write_text(f"#!/bin/sh\nprintf '%s\\n' '{version}'\n", encoding="utf-8")
        executable.chmod(0o700)
    lock = tmp_path / "lock.json"
    lock.write_text(
        json.dumps(
            {
                "python": "3.12.3",
                "tshark": "4.2.2",
                "capinfos": "4.2.2",
                "editcap": "4.2.2",
                "mergecap": "4.2.2",
            }
        ),
        encoding="utf-8",
    )
    env = os.environ | {"PATH": f"{fake_bin}:/usr/bin:/bin"}
    result = subprocess.run(
        [sys.executable, str(CHECKER), "--lock", str(lock)],
        env=env,
        capture_output=True,
        text=True,
    )
    assert result.returncode != 0
    assert "tshark_version_mismatch" in result.stderr
