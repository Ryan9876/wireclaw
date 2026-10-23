"""Gate 7 provider loop layered over the accepted Gate 6 case/report service."""

import json
import os
from pathlib import Path

from .config import EMBEDDED_MODEL_ID, effective_ai_status
from .correlation import correlate_tcp
from .gate4_service import Service as Gate4Service
from .gate6_service import Service as Gate6Service
from .investigation import build_investigation_result
from .providers.openai_compatible import embedded_runtime_available
from .reasoning import persistence
from .reasoning.loop import NEXT_EVIDENCE, run_loop
from .service import Service as Gate3Service
from .service import now
from .storage import ApiError, encode


class Service(Gate6Service):
    def __init__(self, root, policy):
        self._embedded_runtime_failure_code = None
        super().__init__(root, policy)

    def ai_status(self):
        launcher_status = effective_ai_status(self.policy)
        if (
            self.policy.provider_mode.value == "embedded_local"
            and launcher_status["embedded_availability"] == "ready"
        ):
            if not embedded_runtime_available(self.policy):
                return effective_ai_status(self.policy, runtime_failure_code="runtime-unhealthy")
            if self._embedded_runtime_failure_code == "runtime-unhealthy":
                self._embedded_runtime_failure_code = None
        return effective_ai_status(
            self.policy,
            runtime_failure_code=self._embedded_runtime_failure_code,
        )

    def get(self, case_id):
        case = super().get(case_id)
        case["gate_boundary"] = (
            "Gate 7: deterministic evidence with bounded optional model reasoning"
        )
        case["provider_mode"] = self.policy.provider_mode.value
        case["ai_status"] = self.ai_status()
        return case

    def build_investigation_result(self, **kwargs):
        return build_investigation_result(**kwargs)

    def run_reasoning_capability(self, case_id, request):
        # This dispatch reaches the existing typed analyzer boundary only.
        return Gate6Service.capability(self, case_id, request)

    def correlation_records(self, case_id):
        cached = getattr(self, "_correlation_records_snapshot", None)
        if cached is not None:
            return cached
        case = self.get(case_id)
        if len(case["captures"]) < 2:
            return []
        with self.db.connect() as conn:
            evidence_rows = conn.execute(
                "SELECT id,capture_id FROM evidence WHERE case_id=? AND capture_id IS NOT NULL",
                (case_id,),
            ).fetchall()
        evidence_by_capture = {}
        for row in evidence_rows:
            evidence_by_capture.setdefault(row["capture_id"], []).append(row["id"])
        captures = []
        for capture in case["captures"]:
            if not capture["original_artifact_id"] or not capture["sha256"]:
                continue
            try:
                with self.db.connect() as conn:
                    cached_observation = conn.execute(
                        "SELECT id FROM artifacts WHERE case_id=? AND capture_id=? "
                        "AND kind='correlation_observations'",
                        (case_id, capture["id"]),
                    ).fetchone()
                if cached_observation:
                    _, path = self.artifact(case_id, cached_observation["id"])
                    observations = json.loads(path.read_text(encoding="utf-8"))
                else:
                    analyzer = self.analyzer(case_id, capture["id"])
                    observations = analyzer.tcp_correlation_observations(
                        capture["sha256"], capture["id"]
                    )
                    serialized = encode(observations).encode()
                    if len(serialized) > self.policy.max_evidence_bytes:
                        continue
                    path = self.files.path(
                        Path("cases")
                        / case_id
                        / "normalized"
                        / f"correlation-{capture['id']}.json",
                        exists=False,
                    )
                    path.parent.mkdir(exist_ok=True)
                    try:
                        with path.open("xb") as stream:
                            stream.write(serialized)
                            stream.flush()
                            os.fsync(stream.fileno())
                        with self.db.connect() as conn:
                            artifact_id = self.register(
                                conn,
                                case_id,
                                path,
                                "correlation_observations",
                                capture["sha256"],
                            )
                            conn.execute(
                                "UPDATE artifacts SET capture_id=? WHERE id=?",
                                (capture["id"], artifact_id),
                            )
                    except BaseException:
                        path.unlink(missing_ok=True)
                        raise
                if not isinstance(observations, list):
                    continue
            except Exception:
                # Cross-capture work is optional; ordinary per-capture evidence remains usable.
                continue
            captures.append(
                {
                    **capture,
                    "evidence_ids": sorted(evidence_by_capture.get(capture["id"], []))[:8],
                    "observations": observations,
                }
            )
        return correlate_tcp(captures, [])

    def update_capture(self, case_id, capture_id, **changes):
        before = self.get_capture(case_id, capture_id)
        result = super().update_capture(case_id, capture_id, **changes)
        changed = any(
            before.get(field) != result.get(field)
            for field in ("vantage_type", "vantage_subtype")
            if field in changes
        )
        if changed and self.get(case_id)["state"] == "COMPLETE":
            from .models import State

            self.transition(case_id, State.BASELINE_ANALYSIS)
            self.transition(case_id, State.INVESTIGATING)
            self._assemble_report(case_id)
            return self.get_capture(case_id, capture_id)
        return result

    def remove_capture(self, case_id, capture_id):
        was_complete = self.get(case_id)["state"] == "COMPLETE"
        result = super().remove_capture(case_id, capture_id)
        if was_complete and self.get(case_id)["captures"]:
            from .models import State

            current_state = self.get(case_id)["state"]
            if current_state == State.COMPLETE:
                self.transition(case_id, State.BASELINE_ANALYSIS)
                current_state = State.BASELINE_ANALYSIS
            if current_state == State.BASELINE_ANALYSIS:
                self.transition(case_id, State.INVESTIGATING)
                self._assemble_report(case_id)
        return result

    def investigate(self, case_id):
        previous_session = getattr(self, "_reasoning_session_id", None)
        self._reasoning_session_id = persistence.new_session_id()
        try:
            from .models import State

            before = self.get(case_id)
            primary_id = before["captures"][0]["id"] if before["captures"] else None
            pending = [
                capture
                for capture in before["captures"]
                if capture["id"] != primary_id
                and capture["original_artifact_id"]
                and capture["status"] != "analyzed"
            ]
            already_complete = before["state"] == State.COMPLETE
            if pending and already_complete:
                # A newly added source needs analysis; preserve the completed primary run.
                pass
            elif pending:
                # Run primary analysis without assembling an intermediate report.
                Gate3Service.investigate(self, case_id)
            else:
                # Keep the established Gate 4 path for single capture and ordinary reruns.
                return Gate4Service.investigate(self, case_id)

            for capture in pending:
                try:
                    self.execute_capture_analysis(case_id, capture["id"])
                except ApiError as error:
                    with self.db.connect() as conn:
                        conn.execute(
                            "UPDATE captures SET status='needs_attention',last_error=?,updated=? "
                            "WHERE case_id=? AND id=?",
                            (error.code, now(), case_id, capture["id"]),
                        )
                else:
                    with self.db.connect() as conn:
                        conn.execute(
                            "UPDATE captures SET status='analyzed',last_error=NULL,updated=? "
                            "WHERE case_id=? AND id=?",
                            (now(), case_id, capture["id"]),
                        )

            if already_complete:
                self.transition(case_id, State.BASELINE_ANALYSIS)
                self.transition(case_id, State.INVESTIGATING)
            return self._assemble_report(case_id)
        finally:
            self._reasoning_session_id = previous_session

    def capability(self, case_id, request):
        case = self.get(case_id)
        if case["state"] != "COMPLETE":
            return Gate6Service.capability(self, case_id, request)
        previous_session = getattr(self, "_reasoning_session_id", None)
        self._reasoning_session_id = persistence.new_session_id()
        try:
            return Gate6Service.capability(self, case_id, request)
        finally:
            self._reasoning_session_id = previous_session

    def _assemble_report(self, case_id):
        session_id = getattr(self, "_reasoning_session_id", None) or persistence.new_session_id()
        case = self.get(case_id)
        evidence = self.evidence_records(case_id)
        correlations = self.correlation_records(case_id)
        deterministic = build_investigation_result(
            case_id=case_id,
            symptom=case["symptom"],
            evidence=evidence,
            analyzer_versions=self.analyzer_versions(case_id),
            max_display_filter_chars=self.policy.max_display_filter_chars,
            correlations=correlations,
            capture_count=len(case["captures"]),
        )
        try:
            reasoning, ranking, next_codes = run_loop(self, case_id, deterministic, session_id)
        except Exception:
            # Optional reasoning must not corrupt or suppress the deterministic report.
            reasoning, ranking, next_codes = (
                {
                    "mode": "model_fallback",
                    "status": "fallback",
                    "steps": len(persistence.steps(self, case_id, session_id)),
                    "failure_code": "provider_unavailable",
                },
                [],
                [],
            )
        if (
            self.policy.provider_mode.value == "embedded_local"
            and reasoning["mode"] == "model_fallback"
        ):
            # A provider failure after launcher readiness means the owned runtime is
            # no longer healthy for subsequent cases in this Wireclaw process.
            self._embedded_runtime_failure_code = "runtime-unhealthy"
        self._correlation_records_snapshot = correlations
        try:
            super()._assemble_report(case_id)
        finally:
            del self._correlation_records_snapshot
        report = self.report(case_id)
        if reasoning["mode"] == "model_fallback":
            report["limitations"] = list(
                dict.fromkeys(
                    [
                        *report["limitations"],
                        f"Optional model reasoning stopped ({reasoning['failure_code']}); the report uses deterministic evidence and findings.",
                    ]
                )
            )
        findings = report["findings"]
        priority = {category: index for index, category in enumerate(ranking)}
        report["findings"] = sorted(
            findings,
            key=lambda finding: (
                priority.get(finding["category"], len(priority)),
                findings.index(finding),
            ),
        )
        recommendations = [NEXT_EVIDENCE[code] for code in next_codes if code in NEXT_EVIDENCE]
        report["recommended_next_evidence"] = list(
            dict.fromkeys([*report.get("recommended_next_evidence", []), *recommendations])
        )
        embedded_status = self.ai_status()
        report["reasoning"] = {
            **reasoning,
            "provider_mode": self.policy.provider_mode.value,
            "model": self.policy.provider_model
            if self.policy.provider_mode.value != "none"
            else (
                EMBEDDED_MODEL_ID
                if embedded_status["embedded_availability"] == "unavailable"
                else None
            ),
            "embedded_availability": embedded_status["embedded_availability"],
            "embedded_failure_code": embedded_status["failure_code"],
        }
        self.save_report(case_id, report)
        return self.get(case_id)
