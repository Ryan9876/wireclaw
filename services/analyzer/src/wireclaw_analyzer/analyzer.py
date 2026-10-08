"""Deterministic capabilities; directly callable without an API or model provider."""

from pathlib import Path

from jsonschema import Draft202012Validator

from . import diagnostics, normalize
from .capture_headers import pcapng_metadata
from .errors import AnalyzerError
from .runner import FIELDS, Operation, Runner
from .storage import Limits, Store


class Analyzer:
    def __init__(
        self,
        data_root: Path,
        *,
        limits: Limits | None = None,
        schema: Path | None = None,
        diagnostic_limits: diagnostics.DiagnosticLimits | None = None,
    ):
        self.diagnostic_limits = diagnostic_limits or diagnostics.DiagnosticLimits()
        self.store = Store(data_root, limits or Limits())
        self.runner = Runner(self.store)
        # Source checkout default; installed consumers explicitly supply the shared contract.
        schema = schema or Path(__file__).resolve().parents[4] / "contracts/evidence.schema.json"
        import json

        self.validator = Draft202012Validator(json.loads(schema.read_text(encoding="utf-8")))
        self.versions = self.runner.versions()

    def _metadata(self, path: Path) -> dict:
        with path.open("rb") as stream:
            magic = stream.read(4)
        if magic not in (
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\xc3\xd4",
            b"\x4d\x3c\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x0a\x0d\x0d\x0a",
        ):
            raise AnalyzerError("unsupported_capture_format")
        result = normalize.metadata(self.runner.run(Operation.METADATA, path))
        if result["format"] == "pcapng":
            result.update(pcapng_metadata(path))
        if result["packet_count"] > self.store.limits.max_packets:
            raise AnalyzerError("packet_result_limit")
        return result

    def ingest_capture(self, source: Path) -> str:
        def validate(path):
            meta = self._metadata(path)
            rows = normalize.packets(
                self.runner.run(Operation.PACKETS, path), self.store.limits.max_packets
            )
            if len(rows) != meta["packet_count"]:
                raise AnalyzerError("packet_count_mismatch")

        return self.store.ingest(source, validate)

    def _item(
        self, capture_id: str, capability: str, tool: str, value: dict, derived=False
    ) -> dict:
        tool_state = self.versions[tool]
        if not tool_state["available"]:
            raise AnalyzerError("tool_unavailable", capability, tool)
        item = normalize.evidence_item(
            capture_id, capability, tool, tool_state["version"], value, derived=derived
        )
        self.validator.validate(item)
        return item

    def get_capture_metadata(self, capture_id: str) -> dict:
        return self._item(
            capture_id,
            "get_capture_metadata",
            "capinfos",
            self._metadata(self.store.verify(capture_id)),
        )

    def _baseline(self, capture_id: str) -> dict:
        path = self.store.verify(capture_id)
        meta = self._metadata(path)
        rows = normalize.packets(
            self.runner.run(Operation.PACKETS, path), self.store.limits.max_packets
        )
        if len(rows) != meta["packet_count"]:
            raise AnalyzerError("packet_count_mismatch")
        conv = normalize.conversations(rows)
        quality = normalize.quality(meta, rows, conv)
        evidence = [
            self._item(capture_id, "get_capture_metadata", "capinfos", meta),
            self._item(capture_id, "assess_capture_quality", "tshark", quality, True),
            self._item(capture_id, "list_protocols", "tshark", normalize.protocols(rows), True),
            self._item(capture_id, "list_endpoints", "tshark", normalize.endpoints(rows), True),
            self._item(capture_id, "list_conversations", "tshark", conv, True),
        ]
        self.store.verify(capture_id)
        result = {
            "schema_version": "1.0",
            "capture_sha256": capture_id,
            "analyzer_version": "0.2.0",
            "tool_versions": self.versions,
            "configuration": {
                **vars(self.store.limits),
                "name_resolution": False,
                "checksum_validation": True,
                "fields": list(FIELDS),
            },
            "evidence": evidence,
        }
        self.store.persist(capture_id, result)
        return result

    def analyze(self, capture_id: str) -> dict:
        return self._baseline(capture_id)

    def assess_capture_quality(self, capture_id: str) -> dict:
        return self._baseline(capture_id)["evidence"][1]

    def list_protocols(self, capture_id: str) -> dict:
        return self._baseline(capture_id)["evidence"][2]

    def list_endpoints(self, capture_id: str) -> dict:
        return self._baseline(capture_id)["evidence"][3]

    def list_conversations(self, capture_id: str) -> dict:
        return self._baseline(capture_id)["evidence"][4]

    def diagnose(self, capture_id: str) -> dict:
        """Run Gate 1 first, then all fixed Gate 2 capabilities; preserve baseline on failure."""
        return self._diagnose(capture_id)

    def run_diagnostic(self, request: diagnostics.DiagnosticRequest) -> dict:
        if not isinstance(request, diagnostics.DiagnosticRequest):
            raise AnalyzerError("invalid_diagnostic_request")
        return self._diagnose(request.capture_id, request)

    def _diagnose(self, capture_id, request=None):
        baseline = self._baseline(capture_id)
        path = self.store.verify(capture_id)
        rows = diagnostics.packets(
            self.runner.run(Operation.DIAGNOSTICS, path),
            self.store.limits.max_packets,
            self.diagnostic_limits,
            capture_id,
        )
        if len(rows) != baseline["evidence"][0]["value"]["packet_count"]:
            raise AnalyzerError("packet_count_mismatch")
        quality = baseline["evidence"][1]
        evidence = diagnostics.build(
            capture_id,
            rows,
            self.versions["tshark"]["version"],
            quality["value"],
            self.diagnostic_limits,
            self.validator,
            request,
        )
        self.store.verify(capture_id)
        result = {
            "schema_version": "1.0",
            "capture_sha256": capture_id,
            "analyzer_version": "0.2.0",
            "tool_versions": self.versions,
            "capture_quality_evidence_id": quality["id"],
            "capture_quality_state": quality["value"]["state"],
            "configuration": {
                **baseline["configuration"],
                "diagnostic_limits": vars(self.diagnostic_limits),
                "diagnostic_fields": list(FIELDS + diagnostics.EXTRA_FIELDS),
                "two_pass": True,
                "decryption": False,
            },
            "request": {"capability": request.capability.value, "tcp_stream": request.tcp_stream}
            if request
            else {"capability": "all"},
            "evidence": evidence,
        }
        diagnostics.ensure_bytes(result, self.diagnostic_limits)
        self.store.persist(capture_id, result, name="diagnostics.json")
        return result
