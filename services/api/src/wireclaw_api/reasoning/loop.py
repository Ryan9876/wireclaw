"""Bounded provider loop; deterministic analyzer and report remain authoritative."""

import hashlib
import time

from pydantic import ValidationError

from ..config import ProviderMode
from ..models import CapabilityRequest
from ..providers.models import ReasoningRequest
from ..providers.openai_compatible import OpenAICompatibleProvider
from ..storage import ApiError, encode
from . import persistence
from .capabilities import REGISTRY, validate_request
from .context import SYSTEM_INSTRUCTION, build_context
from .contracts import ACTION_ADAPTER, CapabilityAction, FinalizeAction

NEXT_EVIDENCE = {
    "server_side_capture": "Collect a synchronized server-side capture for the same transaction.",
    "application_logs": "Compare application or load-balancer logs for the measured transaction interval.",
    "browser_har": "Capture a browser HAR for the same user-visible transaction.",
    "interface_counters": "Compare interface drop/error counters during a repeat reproduction.",
    "repeat_capture": "Repeat a complete bidirectional capture during a representative reproduction.",
}

NEXT_EVIDENCE_DOMAINS = {
    "server_side_capture": {"server_application", "network_path"},
    "application_logs": {"server_application"},
    "browser_har": {"client"},
    "interface_counters": {"local_network", "network_path"},
    "repeat_capture": {
        "client",
        "local_network",
        "network_path",
        "server_application",
        "dns",
        "capture_observability",
        "unknown",
    },
}

REMAINING_CATEGORY_DOMAINS = {
    "server.application_wait": {"server_application"},
    "dns.timing": {"dns"},
    "tcp.establishment_delay": {"local_network", "network_path", "server_application"},
    "tcp.retransmission": {"local_network", "network_path", "capture_observability"},
    "tcp.rtt": {"network_path"},
    "tcp.receive_window": {"client", "server_application"},
    "tls.handshake": {"network_path", "server_application"},
    "capture.quality": {"capture_observability"},
}


def make_provider(policy):
    if policy.provider_mode is ProviderMode.NONE:
        return None
    return OpenAICompatibleProvider(
        mode=policy.provider_mode,
        base_url=policy.provider_base_url,
        model=policy.provider_model,
        timeout_seconds=policy.provider_timeout_seconds,
        api_key=policy.provider_api_key,
    )


def _validated_proposals(
    action: FinalizeAction, report: dict, evidence: list[dict]
) -> tuple[list[str], list[str]]:
    evidence_by_id = {item["id"]: item for item in evidence}
    findings = {item["category"]: item for item in report["findings"]}
    ranking = []
    next_codes = []
    known_categories = set(findings) | {
        "server.application_wait",
        "dns.timing",
        "tcp.establishment_delay",
        "tcp.retransmission",
        "tcp.rtt",
        "tcp.receive_window",
        "tls.handshake",
        "capture.quality",
    }
    for proposal in action.hypotheses:
        finding = findings.get(proposal.category)
        if finding is None or not proposal.evidence_ids:
            continue
        if any(
            evidence_id not in evidence_by_id
            or evidence_by_id[evidence_id].get("epistemic_class") not in {"observed", "derived"}
            or evidence_id not in finding["evidence_ids"]
            for evidence_id in proposal.evidence_ids
        ):
            continue
        if any(domain not in finding.get("fault_domains", []) for domain in proposal.fault_domains):
            continue
        ranking.append(proposal.category)
    for item in action.remaining_hypotheses:
        if item.category not in known_categories:
            continue
        if any(
            evidence_id not in evidence_by_id
            or evidence_by_id[evidence_id].get("epistemic_class") not in {"observed", "derived"}
            for evidence_id in item.evidence_ids
        ):
            continue
        if any(
            domain
            not in {
                "client",
                "local_network",
                "network_path",
                "server_application",
                "dns",
                "capture_observability",
                "unknown",
            }
            for domain in item.fault_domains
        ):
            continue
        category_domains = set(
            findings.get(item.category, {}).get("fault_domains", [])
            or REMAINING_CATEGORY_DOMAINS.get(item.category, set())
        )
        proposed_domains = set(item.fault_domains)
        for deterministic in report["remaining_hypotheses"]:
            supported_domains = (
                category_domains & proposed_domains & set(deterministic.get("fault_domains", []))
            )
            if not supported_domains:
                continue
            next_codes.extend(
                code
                for code in item.next_evidence
                if code in NEXT_EVIDENCE and NEXT_EVIDENCE_DOMAINS[code] & supported_domains
            )
    return list(dict.fromkeys(ranking)), list(dict.fromkeys(next_codes))


def _report(service, case_id, evidence):
    case = service.get(case_id)
    return service.build_investigation_result(
        case_id=case_id,
        symptom=case["symptom"],
        evidence=evidence,
        analyzer_versions=service.analyzer_versions(case_id),
        max_display_filter_chars=service.policy.max_display_filter_chars,
    )


def run_loop(service, case_id, report, session_id=None):
    session_id = session_id or persistence.new_session_id()
    policy = service.policy
    mode = policy.provider_mode
    if mode is ProviderMode.NONE:
        return {"mode": "rules_only", "status": "complete", "steps": 0}, [], []

    provider = make_provider(policy)
    evidence = service.evidence_records(case_id)
    case = service.get(case_id)
    prior = persistence.steps(service, case_id, session_id)
    fingerprints = {
        item["request_fingerprint"]
        for item in prior
        if isinstance(item.get("request_fingerprint"), str)
    }
    if prior and prior[-1].get("status") == "finalized":
        return (
            {
                "mode": "model_assisted",
                "status": "complete",
                "steps": len(prior),
                "accepted_categories": prior[-1].get("accepted_categories", []),
                "rejected_proposals": prior[-1].get("rejected_proposals", 0),
            },
            prior[-1].get("accepted_categories", []),
            prior[-1].get("next_evidence_codes", []),
        )

    failure = None
    for sequence in range(len(prior), policy.max_reasoning_steps):
        started = time.monotonic()
        serialized, context_digest = build_context(
            case=case,
            evidence=evidence,
            report=report,
            capabilities=sorted(REGISTRY),
            max_items=policy.max_reasoning_evidence_items,
            limits={
                "max_reasoning_steps": policy.max_reasoning_steps,
                "max_identical_capability_request_count": policy.max_identical_capability_request_count,
            },
        )
        if (
            len(serialized.encode()) + len(SYSTEM_INSTRUCTION.encode())
            > policy.max_provider_request_bytes
        ):
            failure = "provider_request_too_large"
            break
        result = provider.propose(
            ReasoningRequest(
                model=policy.provider_model,
                context_json=serialized,
                system_instruction=SYSTEM_INSTRUCTION,
                max_request_bytes=policy.max_provider_request_bytes,
                max_response_bytes=policy.max_provider_response_bytes,
            )
        )
        base = {
            "provider_mode": mode.value,
            "model": policy.provider_model,
            "endpoint_class": "cloud" if mode is ProviderMode.CLOUD else "local",
            "context_digest": context_digest,
            "action_type": "unknown",
            "capability": None,
            "parameters": {},
            "request_fingerprint": None,
            "resulting_evidence_ids": [],
            "status": "failed",
            "failure_code": result.failure_code,
            "duration_ms": round((time.monotonic() - started) * 1000),
        }
        if result.failure_code:
            failure = result.failure_code
            persistence.append_step(service, case_id, session_id, base)
            break
        if (
            not isinstance(result.content, str)
            or len(result.content.encode()) > policy.max_provider_response_bytes
        ):
            base["failure_code"] = "provider_response_too_large"
            persistence.append_step(service, case_id, session_id, base)
            failure = base["failure_code"]
            break
        try:
            action = ACTION_ADAPTER.validate_json(result.content, strict=True)
        except (ValidationError, ValueError):
            base["failure_code"] = "provider_invalid_response"
            persistence.append_step(service, case_id, session_id, base)
            failure = base["failure_code"]
            break
        base["action_type"] = action.action
        if isinstance(action, CapabilityAction):
            base["capability"] = action.capability
            try:
                spec, parameters = validate_request(
                    action.capability,
                    action.parameters.model_dump(exclude_none=True),
                    evidence,
                )
            except ApiError as error:
                base["failure_code"] = error.code
                persistence.append_step(service, case_id, session_id, base)
                failure = error.code
                break
            fingerprint = hashlib.sha256(
                action.capability.encode() + encode(parameters).encode()
            ).hexdigest()
            base["parameters"] = parameters
            base["request_fingerprint"] = fingerprint
            if fingerprint in fingerprints:
                base["status"] = "duplicate"
                base["failure_code"] = "duplicate_capability_request"
                persistence.append_step(service, case_id, session_id, base)
                failure = base["failure_code"]
                break
            fingerprints.add(fingerprint)
            request = CapabilityRequest(
                artifact_id=case["original_id"], capability=spec.name, **parameters
            )
            try:
                result_set = service.run_reasoning_capability(case_id, request)
            except ApiError as error:
                base["failure_code"] = error.code
                persistence.append_step(service, case_id, session_id, base)
                failure = error.code
                break
            base["resulting_evidence_ids"] = [item["id"] for item in result_set["evidence"]]
            base["status"] = "complete"
            base["failure_code"] = None
            base["duration_ms"] = round((time.monotonic() - started) * 1000)
            persistence.append_step(service, case_id, session_id, base)
            evidence = service.evidence_records(case_id)
            report = _report(service, case_id, evidence)
            continue

        ranking, next_codes = _validated_proposals(action, report, evidence)
        proposed = len(action.hypotheses)
        accepted = len(ranking)
        base.update(
            {
                "status": "finalized",
                "failure_code": None,
                "accepted_categories": ranking,
                "next_evidence_codes": next_codes,
                "rejected_proposals": proposed - accepted,
            }
        )
        persistence.append_step(service, case_id, session_id, base)
        return (
            {
                "mode": "model_assisted",
                "status": "complete",
                "steps": sequence + 1,
                "accepted_categories": ranking,
                "rejected_proposals": proposed - accepted,
            },
            ranking,
            next_codes,
        )

    if failure is None:
        failure = "reasoning_step_limit"
    return (
        {
            "mode": "model_fallback",
            "status": "fallback",
            "steps": len(persistence.steps(service, case_id, session_id)),
            "failure_code": failure,
        },
        [],
        [],
    )
