"""Reproducible real-tool CLI/live API smoke and shared-contract checks."""

import json
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import httpx
from jsonschema import Draft202012Validator

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/fixtures"))
from generate import generate  # noqa: E402
from generate_gate2 import generate as generate_diagnostics  # noqa: E402


def records(value):
    if isinstance(value, dict):
        if "epistemic_class" in value and "source" in value:
            yield value
        else:
            for nested in value.values():
                yield from records(nested)
    elif isinstance(value, list):
        for nested in value:
            yield from records(nested)


def main():
    if not shutil.which("tshark") or not shutil.which("capinfos"):
        raise RuntimeError("real_packet_tools_required")
    schema = json.loads((ROOT / "contracts/evidence.schema.json").read_text())
    Draft202012Validator.check_schema(schema)
    validator = Draft202012Validator(schema)
    checks = 0
    for pattern in (
        "tests/golden/*.json",
        "tests/golden/gate2/*.json",
        "docs/gate*-evidence*.json",
    ):
        for path in ROOT.glob(pattern):
            for item in records(json.loads(path.read_text())):
                item["source"].setdefault("version", "4.2.2")
                validator.validate(item)
                checks += 1
    with tempfile.TemporaryDirectory(prefix="wireclaw-gate3-") as temporary:
        directory = Path(temporary)
        captures = generate(directory / "incoming")
        generate_diagnostics(directory / "incoming")
        cli_counts = []
        for name, options in (("healthy", []), ("dns_sequences", ["--diagnostics"])):
            command = [
                sys.executable,
                "-m",
                "wireclaw_analyzer.cli",
                "--data-root",
                str(directory),
                f"incoming/{name}.capture",
                *options,
            ]
            result = json.loads(
                subprocess.run(command, check=True, capture_output=True, timeout=120).stdout
            )
            for item in result["evidence"]:
                validator.validate(item)
                checks += 1
            cli_counts.append(len(result["evidence"]))
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        process = subprocess.Popen(
            [
                sys.executable,
                "-m",
                "wireclaw_api.cli",
                "--data-root",
                str(directory / "api"),
                "--port",
                str(port),
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            with httpx.Client(
                base_url=f"http://127.0.0.1:{port}", timeout=120, trust_env=False
            ) as client:
                deadline = time.monotonic() + 15
                while True:
                    if process.poll() is not None:
                        raise RuntimeError("api_startup_failed")
                    try:
                        health = client.get("/api/health")
                        health.raise_for_status()
                        break
                    except httpx.TransportError:
                        if time.monotonic() >= deadline:
                            raise RuntimeError("api_startup_timeout") from None
                        time.sleep(0.1)
                case = client.post("/api/cases", json={"symptom": "synthetic smoke"})
                case.raise_for_status()
                case_id = case.json()["id"]
                intake = client.post(
                    f"/api/cases/{case_id}/capture",
                    content=captures["healthy"],
                    headers={"content-type": "application/octet-stream"},
                )
                intake.raise_for_status()
                response = client.post(f"/api/cases/{case_id}/investigate")
                response.raise_for_status()
                assert response.json()["state"] == "COMPLETE"
                evidence = client.get(f"/api/cases/{case_id}/evidence").json()["evidence"]
                for item in evidence:
                    validator.validate(item)
                    checks += 1
                original = response.json()["original_id"]
                request = {"artifact_id": original, "capability": "analyze_rtt", "tcp_stream": 0}
                first = client.post(f"/api/cases/{case_id}/capabilities", json=request)
                first.raise_for_status()
                assert (
                    client.post(f"/api/cases/{case_id}/capabilities", json=request).json()
                    == first.json()
                )
                deletion = client.delete(f"/api/cases/{case_id}")
                deletion.raise_for_status()
                assert deletion.json()["cleanup_pending"] is False
                assert client.get(f"/api/cases/{case_id}").status_code == 404
        finally:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
    print(
        json.dumps(
            {
                "schema_record_checks": checks,
                "cli_evidence_counts": cli_counts,
                "live_loopback_api": "passed",
                "repeat_request": "passed",
                "deletion": "passed",
            }
        )
    )


if __name__ == "__main__":
    main()
