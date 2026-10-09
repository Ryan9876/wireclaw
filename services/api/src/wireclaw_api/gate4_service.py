"""Gate 4 deterministic report assembly layered on the proven Gate 3 service."""

from __future__ import annotations

import hashlib
import json
import os
import sqlite3
import time
from contextlib import suppress
from pathlib import Path

from jsonschema import Draft202012Validator, ValidationError

from .investigation import build_investigation_result
from .models import TRANSITIONS, State
from .service import Service as Gate3Service
from .storage import ApiError, encode


class Service(Gate3Service):
    """Gate 4 service: deterministic findings and persisted investigation reports."""

    def __init__(self, root, policy):
        super().__init__(root, policy)
        schema = Path(__file__).resolve().parents[4] / "contracts/investigation-result.schema.json"
        document = json.loads(schema.read_text(encoding="utf-8"))
        Draft202012Validator.check_schema(document)
        self.report_validator = Draft202012Validator(document)

    def get(self, case_id):
        case = super().get(case_id)
        case["gate_boundary"] = (
            "Gate 4: deterministic findings and report; model reasoning deferred"
        )
        return case

    def evidence_records(self, case_id):
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            return [
                json.loads(row["record"])
                for row in conn.execute(
                    "SELECT record FROM evidence WHERE case_id=? ORDER BY id", (case_id,)
                )
            ]

    def analyzer_versions(self, case_id):
        versions = {}
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            rows = conn.execute(
                "SELECT versions FROM runs WHERE case_id=? AND status='complete' "
                "AND versions IS NOT NULL ORDER BY created,id",
                (case_id,),
            )
            for row in rows:
                current = json.loads(row["versions"])
                if isinstance(current, dict):
                    for key, value in sorted(current.items()):
                        if isinstance(key, str) and isinstance(value, (str, int, float)):
                            versions[key] = str(value)
        return versions

    def _report_row(self, case_id):
        with self.db.connect() as conn:
            self.db.case(conn, case_id)
            rows = conn.execute(
                "SELECT * FROM artifacts WHERE case_id=? AND kind='report'", (case_id,)
            ).fetchall()
        if len(rows) > 1:
            raise ApiError("report_registry_invalid", 500)
        return dict(rows[0]) if rows else None

    def save_report(self, case_id, report):
        self.report_validator.validate(report)
        serialized = encode(report).encode()
        if len(serialized) > self.policy.max_evidence_bytes:
            raise ApiError("report_size_limit", 413)

        case = self.get(case_id)
        digest = hashlib.sha256(serialized).hexdigest()
        relative = f"cases/{case_id}/reports/{digest}.json"
        path = self.files.path(relative)
        existing = self._report_row(case_id)

        if existing and existing["relative_path"] == relative:
            self.artifact(case_id, existing["id"])
            return existing["id"]

        self.files.store.confined(path, exists=False)
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists():
            path.unlink()
        old_path = None
        try:
            with path.open("xb") as stream:
                stream.write(serialized)
                stream.flush()
                os.fsync(stream.fileno())
            path.chmod(0o400)

            with self.db.connect() as conn:
                self.db.case(conn, case_id)
                if existing:
                    old_path = self.files.path(existing["relative_path"], exists=True)
                    conn.execute(
                        "UPDATE artifacts SET relative_path=?,sha256=?,bytes=?,parent_sha=? "
                        "WHERE id=? AND case_id=? AND kind='report'",
                        (
                            relative,
                            digest,
                            len(serialized),
                            case["capture_sha"],
                            existing["id"],
                            case_id,
                        ),
                    )
                    artifact_id = existing["id"]
                else:
                    artifact_id = self.register(conn, case_id, path, "report", case["capture_sha"])
        except BaseException:
            path.chmod(0o600) if path.exists() else None
            path.unlink(missing_ok=True)
            raise

        if old_path is not None and old_path != path:
            old_path.chmod(0o600)
            old_path.unlink(missing_ok=True)
        return artifact_id

    def report(self, case_id):
        case = self.get(case_id)
        if case["state"] != State.COMPLETE:
            raise ApiError("report_not_ready")
        row = self._report_row(case_id)
        if row is None:
            raise ApiError("report_not_found", 404)
        _, path = self.artifact(case_id, row["id"])
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            self.report_validator.validate(document)
        except (json.JSONDecodeError, ValidationError):
            raise ApiError("report_integrity_failure", 500) from None
        if document.get("case_id") != case_id:
            raise ApiError("report_integrity_failure", 500)
        return document

    def findings(self, case_id):
        return self.report(case_id)["findings"]

    def investigate(self, case_id):
        super().investigate(case_id)
        self.transition(case_id, State.ASSEMBLING_REPORT)
        started = time.monotonic()
        try:
            case = self.get(case_id)
            result = build_investigation_result(
                case_id=case_id,
                symptom=case["symptom"],
                evidence=self.evidence_records(case_id),
                analyzer_versions=self.analyzer_versions(case_id),
            )
            self.save_report(case_id, result)
            self.transition(case_id, State.COMPLETE)
        except Exception as error:
            if isinstance(error, ApiError):
                code = error.code
                status = error.status
            elif isinstance(error, ValidationError):
                code, status = "report_contract_failure", 500
            elif isinstance(error, sqlite3.Error):
                code, status = "persistence_failure", 503
            elif isinstance(error, OSError):
                code, status = "storage_failure", 503
            else:
                code, status = "report_assembly_failed", 500
            with suppress(ApiError, sqlite3.Error):
                with self.db.connect() as conn:
                    state = State(self.db.case(conn, case_id)["state"])
                if State.FAILED in TRANSITIONS[state]:
                    self.transition(case_id, State.FAILED, error=code)
            self.log(case_id, "report", started, "failed", code)
            raise ApiError(code, status) from None
        self.log(case_id, "report", started, "complete")
        return self.get(case_id)

    def recover(self):
        super().recover()
        with self.db.connect() as conn:
            case_ids = [row["id"] for row in conn.execute("SELECT id FROM cases ORDER BY id")]
            known = {
                row["relative_path"]
                for row in conn.execute("SELECT relative_path FROM artifacts WHERE kind='report'")
            }
        for case_id in case_ids:
            directory = self.files.case(case_id) / "reports"
            if not directory.exists():
                continue
            self.files.checked_tree(directory)
            for path in directory.iterdir():
                relative = path.relative_to(self.files.root).as_posix()
                if relative not in known:
                    if path.is_dir():
                        self.remove_tree(path)
                    else:
                        path.chmod(0o600)
                        path.unlink()
