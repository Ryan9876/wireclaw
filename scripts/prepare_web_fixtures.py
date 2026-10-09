"""Gate 5 browser inputs and component fixtures from the real local API/analyzer."""

import json
import shutil
import sys
import tempfile
from pathlib import Path

from fastapi.testclient import TestClient
from wireclaw_api import create_app

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/fixtures"))
from generate import generate as baseline  # noqa: E402
from generate_gate2 import generate as diagnostics  # noqa: E402


def main():
    if not shutil.which("tshark") or not shutil.which("capinfos"):
        raise RuntimeError("real_packet_tools_required")
    captures = ROOT / "artifacts/web-captures"
    captures.mkdir(parents=True, exist_ok=True)
    fixtures = ROOT / "apps/web/tests/fixtures"
    fixtures.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="wireclaw-web-fixtures-") as temporary:
        directory = Path(temporary)
        gate1 = baseline(directory / "baseline")
        gate2 = diagnostics(directory / "diagnostics")
        for name, content in {**gate1, **gate2}.items():
            (captures / f"{name}.pcap").write_bytes(content)
        (captures / "malformed.pcap").write_bytes(b"this is not a packet capture")
        scenarios = {
            "supported": ("a" * 32, "application is slow", gate2["high_rtt"]),
            "insufficient": ("b" * 32, "application is slow", gate2["clean_tcp"]),
            "limited": ("c" * 32, "application is slow", gate1["midstream"]),
        }
        with TestClient(create_app(directory / "api"), base_url="http://127.0.0.1:8765") as client:
            for name, (fixed_id, symptom, capture) in scenarios.items():
                created = client.post("/api/cases", json={"symptom": symptom})
                created.raise_for_status()
                case_id = created.json()["id"]
                uploaded = client.post(
                    f"/api/cases/{case_id}/capture",
                    content=capture,
                    headers={"content-type": "application/octet-stream"},
                )
                uploaded.raise_for_status()
                completed = client.post(f"/api/cases/{case_id}/investigate")
                completed.raise_for_status()
                case = completed.json()
                report = client.get(f"/api/cases/{case_id}/report").json()
                evidence = client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]
                case["id"] = fixed_id
                report["case_id"] = fixed_id
                for run in case["runs"]:
                    run["case_id"] = fixed_id
                (fixtures / f"{name}.json").write_text(
                    json.dumps({"case": case, "report": report, "evidence": evidence}, indent=2)
                    + "\n"
                )
    print("Generated browser captures and three real-backend component fixtures.")


if __name__ == "__main__":
    main()
