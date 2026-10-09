"""Gate 6 evidence extraction and one-time native Wireshark launch grants."""

from __future__ import annotations

import hashlib
import json
import os
import re
import secrets
import time
from contextlib import suppress
from pathlib import Path

from wireclaw_analyzer import AnalyzerError, EvidenceExtractor

from .gate4_service import Service as Gate4Service
from .models import State
from .service import identifier, now
from .storage import ApiError, encode


class Service(Gate4Service):
    def get(self, case_id):
        case = super().get(case_id)
        case["gate_boundary"] = (
            "Gate 6: deterministic report with bounded evidence capture and native Wireshark bridge"
        )
        return case

    def _finding(self, case_id, finding_id):
        report = self.report(case_id)
        for finding in report["findings"]:
            if finding["id"] == finding_id:
                return finding
        raise ApiError("finding_not_found", 404)

    def _validate_filter(self, value):
        if value is None:
            return ""
        if not isinstance(value, str) or len(value) > self.policy.max_display_filter_chars:
            raise ApiError("display_filter_limit", 422)
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            raise ApiError("invalid_display_filter", 422)
        return value

    def _finding_filter(self, case_id, finding):
        actions = finding.get("wireshark") or {}
        if not actions.get("applicable"):
            raise ApiError("wireshark_not_applicable", 409)
        display_filter = self._validate_filter(actions.get("display_filter"))
        if display_filter:
            if re.fullmatch(r"\s*tcp\.stream\s*==\s*\d+\s*", display_filter):
                mode = "tcp_stream"
            elif "dns" in display_filter.lower():
                mode = "dns_transaction_set"
            elif "frame.number" in display_filter:
                mode = "frame_set"
            else:
                mode = "finding_filter"
            return display_filter, mode

        frames = []
        for evidence_id in finding["evidence_ids"]:
            record = self.evidence(case_id, evidence_id=evidence_id)
            for value in record.get("frame_refs", []):
                if type(value) is int and value > 0:
                    frames.append(value)
        frames = sorted(set(frames))
        if not frames:
            raise ApiError("packet_evidence_unavailable", 409)
        candidate = " || ".join(f"frame.number == {frame}" for frame in frames)
        if len(candidate) <= self.policy.max_display_filter_chars:
            return candidate, "frame_set"
        candidate = f"frame.number >= {frames[0]} && frame.number <= {frames[-1]}"
        return self._validate_filter(candidate), "bounded_frame_range"

    def create_evidence_capture(self, case_id, finding_id):
        case = self.get(case_id)
        if case["state"] != State.COMPLETE or not case["original_id"]:
            raise ApiError("report_not_ready")
        finding = self._finding(case_id, finding_id)
        display_filter, mode = self._finding_filter(case_id, finding)
        with self.db.connect() as conn:
            count = conn.execute(
                "SELECT count(*) FROM artifacts WHERE case_id=? AND kind='evidence_capture'",
                (case_id,),
            ).fetchone()[0]
        if count >= self.policy.max_evidence_captures:
            raise ApiError("evidence_capture_count_limit", 429)

        original, original_path = self.artifact(case_id, case["original_id"])
        case_root = self.files.case(case_id)
        evidence_dir = self.files.store.confined(case_root / "evidence", exists=False)
        evidence_dir.mkdir(parents=True, exist_ok=True)
        temporary_name = identifier()
        capture_path = self.files.store.confined(
            evidence_dir / f"{temporary_name}.pcapng", exists=False
        )
        provenance_path = self.files.store.confined(
            evidence_dir / f"{temporary_name}.json", exists=False
        )
        extractor = EvidenceExtractor(case_root, self.policy.analyzer)
        started = time.monotonic()
        try:
            result = extractor.extract(
                original_path.relative_to(case_root),
                capture_path.relative_to(case_root),
                display_filter,
                max_bytes=self.policy.max_evidence_capture_bytes,
            )
            self.artifact(case_id, case["original_id"])
            tool_versions = self.analyzer_versions(case_id)
            provenance = {
                "artifact_id": "",
                "parent_sha256": original["sha256"],
                "case_id": case_id,
                "finding_id": finding_id,
                "evidence_ids": list(finding["evidence_ids"]),
                "extraction_mode": mode,
                "extraction_rule": {"display_filter": display_filter},
                "display_filter": display_filter,
                "created": now(),
                "tool_versions": tool_versions,
            }
            with self.db.connect() as conn:
                artifact_id = self.register(
                    conn, case_id, capture_path, "evidence_capture", original["sha256"]
                )
                provenance["artifact_id"] = artifact_id
                encoded = encode(provenance).encode()
                if len(encoded) > self.policy.max_json_bytes:
                    raise ApiError("provenance_size_limit", 413)
                with provenance_path.open("xb") as stream:
                    stream.write(encoded)
                    stream.flush()
                    os.fsync(stream.fileno())
                provenance_path.chmod(0o400)
                self.register(
                    conn, case_id, provenance_path, "evidence_provenance", original["sha256"]
                )
            self.log(case_id, "evidence_capture", started, "complete")
            return {
                "artifact_id": artifact_id,
                "sha256": result["sha256"],
                "bytes": result["bytes"],
                "provenance": provenance,
            }
        except Exception as error:
            for path in (capture_path, provenance_path):
                if path.exists():
                    with suppress(OSError):
                        path.chmod(0o600)
                    path.unlink(missing_ok=True)
            code = (
                error.code if isinstance(error, (ApiError, AnalyzerError)) else "operation_failed"
            )
            self.log(case_id, "evidence_capture", started, "failed", code)
            if isinstance(error, ApiError):
                raise
            raise ApiError(code, 422) from None

    def _evidence_capture_provenance(self, case_id, artifact_id):
        """Return the registered, integrity-checked provenance paired with one evidence capture."""
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT relative_path FROM artifacts "
                "WHERE id=? AND case_id=? AND kind='evidence_capture'",
                (artifact_id, case_id),
            ).fetchone()
            if row is None:
                raise ApiError("artifact_not_found", 404)
            relative = Path(row["relative_path"])
            provenance_relative = relative.with_suffix(".json").as_posix()
            provenance_row = conn.execute(
                "SELECT id FROM artifacts "
                "WHERE case_id=? AND kind='evidence_provenance' AND relative_path=?",
                (case_id, provenance_relative),
            ).fetchone()
        if provenance_row is None:
            raise ApiError("evidence_provenance_missing", 409)
        _, provenance_path = self.artifact(case_id, provenance_row["id"])
        try:
            if provenance_path.stat().st_size > self.policy.max_json_bytes:
                raise ApiError("evidence_provenance_invalid", 409)
            value = json.loads(provenance_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            raise ApiError("evidence_provenance_invalid", 409) from None
        if (
            not isinstance(value, dict)
            or value.get("artifact_id") != artifact_id
            or value.get("case_id") != case_id
            or not isinstance(value.get("finding_id"), str)
            or not isinstance(value.get("display_filter"), str)
        ):
            raise ApiError("evidence_provenance_invalid", 409)
        return value

    def _cleanup_bridge_grants(self):
        directory = self.files.path(Path("bridge") / "requests")
        directory.mkdir(parents=True, exist_ok=True)
        current = int(time.time())
        active = 0
        for path in directory.iterdir():
            if path.is_symlink():
                path.unlink(missing_ok=True)
                continue
            if not path.is_file() or not re.fullmatch(r"[a-f0-9]{32}\.json", path.name):
                continue
            try:
                if path.stat().st_size > self.policy.max_json_bytes:
                    expired = True
                else:
                    value = json.loads(path.read_text(encoding="utf-8"))
                    expired = (
                        type(value.get("expires_unix")) is not int
                        or value["expires_unix"] < current
                    )
            except (OSError, json.JSONDecodeError):
                expired = True
            if expired:
                with suppress(OSError):
                    path.chmod(0o600)
                path.unlink(missing_ok=True)
            else:
                active += 1
        if active >= self.policy.max_bridge_grants:
            raise ApiError("bridge_grant_limit", 429)
        return directory

    def create_bridge_grant(self, case_id, artifact_id, finding_id):
        case = self.get(case_id)
        if case["state"] != State.COMPLETE:
            raise ApiError("report_not_ready")
        finding = self._finding(case_id, finding_id)
        current_filter, _ = self._finding_filter(case_id, finding)
        artifact, _ = self.artifact(case_id, artifact_id)
        if artifact["kind"] not in ("original", "evidence_capture"):
            raise ApiError("capture_artifact_required", 409)
        if artifact["kind"] == "original":
            if artifact_id != case["original_id"]:
                raise ApiError("original_artifact_required", 409)
            display_filter = current_filter
        else:
            provenance = self._evidence_capture_provenance(case_id, artifact_id)
            if provenance["finding_id"] != finding_id:
                raise ApiError("evidence_finding_mismatch", 409)
            display_filter = self._validate_filter(provenance["display_filter"])
            if display_filter != current_filter:
                raise ApiError("evidence_provenance_mismatch", 409)

        directory = self._cleanup_bridge_grants()
        request_id = identifier()
        token = secrets.token_urlsafe(32)
        expires_unix = int(time.time()) + self.policy.bridge_grant_ttl_seconds
        with self.db.connect() as conn:
            row = conn.execute(
                "SELECT relative_path FROM artifacts WHERE id=? AND case_id=?",
                (artifact_id, case_id),
            ).fetchone()
            if row is None:
                raise ApiError("artifact_not_found", 404)
            relative_path = row["relative_path"]
        manifest = {
            "schema_version": 1,
            "request_id": request_id,
            "token_sha256": hashlib.sha256(token.encode()).hexdigest(),
            "case_id": case_id,
            "artifact_id": artifact_id,
            "artifact_kind": artifact["kind"],
            "relative_path": relative_path,
            "artifact_sha256": artifact["sha256"],
            "display_filter": display_filter,
            "expires_unix": expires_unix,
        }
        path = self.files.path(directory.relative_to(self.files.root) / f"{request_id}.json")
        payload = encode(manifest).encode()
        if len(payload) > self.policy.max_json_bytes:
            raise ApiError("bridge_manifest_size_limit", 500)
        try:
            with path.open("xb") as stream:
                stream.write(payload)
                stream.flush()
                os.fsync(stream.fileno())
            path.chmod(0o600)
        except OSError:
            path.unlink(missing_ok=True)
            raise ApiError("storage_failure", 503) from None
        return {
            "request_id": request_id,
            "token": token,
            "bridge_origin": f"http://127.0.0.1:{self.policy.bridge_port}",
            "expires_unix": expires_unix,
        }

    def _remove_case_bridge_grants(self, case_id):
        directory = self.files.path(Path("bridge") / "requests")
        if not directory.exists():
            return
        for path in directory.iterdir():
            if path.is_symlink() or not path.is_file():
                continue
            if not re.fullmatch(r"[a-f0-9]{32}\.json", path.name):
                continue
            try:
                if path.stat().st_size > self.policy.max_json_bytes:
                    continue
                value = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                continue
            if value.get("case_id") == case_id:
                with suppress(OSError):
                    path.chmod(0o600)
                path.unlink(missing_ok=True)

    def delete(self, case_id):
        self._remove_case_bridge_grants(case_id)
        return super().delete(case_id)
