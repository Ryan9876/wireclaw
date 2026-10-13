"""Gate 7 provider loop layered over the accepted Gate 6 case/report service."""

from .gate4_service import Service as Gate4Service
from .gate6_service import Service as Gate6Service
from .investigation import build_investigation_result
from .reasoning import persistence
from .reasoning.loop import NEXT_EVIDENCE, run_loop


class Service(Gate6Service):
    def get(self, case_id):
        case = super().get(case_id)
        case["gate_boundary"] = (
            "Gate 7: deterministic evidence with bounded optional model reasoning"
        )
        case["provider_mode"] = self.policy.provider_mode.value
        return case

    def build_investigation_result(self, **kwargs):
        return build_investigation_result(**kwargs)

    def run_reasoning_capability(self, case_id, request):
        # This dispatch reaches the existing typed analyzer boundary only.
        return Gate6Service.capability(self, case_id, request)

    def investigate(self, case_id):
        case = self.get(case_id)
        if case["state"] in ("COMPLETE", "FAILED"):
            persistence.clear_steps(self, case_id)
        return Gate4Service.investigate(self, case_id)

    def capability(self, case_id, request):
        case = self.get(case_id)
        if case["state"] == "COMPLETE":
            persistence.clear_steps(self, case_id)
        return Gate6Service.capability(self, case_id, request)

    def _assemble_report(self, case_id):
        case = self.get(case_id)
        evidence = self.evidence_records(case_id)
        deterministic = build_investigation_result(
            case_id=case_id,
            symptom=case["symptom"],
            evidence=evidence,
            analyzer_versions=self.analyzer_versions(case_id),
            max_display_filter_chars=self.policy.max_display_filter_chars,
        )
        try:
            reasoning, ranking, next_codes = run_loop(self, case_id, deterministic)
        except Exception:
            # Optional reasoning must not corrupt or suppress the deterministic report.
            reasoning, ranking, next_codes = (
                {
                    "mode": "model_fallback",
                    "status": "fallback",
                    "steps": len(persistence.steps(self, case_id)),
                    "failure_code": "provider_unavailable",
                },
                [],
                [],
            )
        super()._assemble_report(case_id)
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
        report["reasoning"] = {
            **reasoning,
            "provider_mode": self.policy.provider_mode.value,
            "model": self.policy.provider_model
            if self.policy.provider_mode.value != "none"
            else None,
        }
        self.save_report(case_id, report)
        return self.get(case_id)
