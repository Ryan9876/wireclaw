import json
from decimal import Decimal
from pathlib import Path

import pytest
from jsonschema import Draft202012Validator, ValidationError
from wireclaw_analyzer import AnalyzerError, normalize
from wireclaw_analyzer.runner import FIELDS


def test_hostile_protocol_text_rejected():
    columns = {key: "" for key in FIELDS}
    columns.update(
        {
            "frame.number": "1",
            "frame.time_epoch": "1",
            "frame.len": "1",
            "frame.cap_len": "1",
            "frame.protocols": "$(touch injected)",
        }
    )
    with pytest.raises(AnalyzerError, match="invalid_packet_output"):
        normalize.packets("\t".join(columns.values()), 10)


@pytest.mark.parametrize("text", ["\x00", "incomplete\tcolumns", "a\n" * 10])
def test_malformed_tool_output(text):
    with pytest.raises(AnalyzerError):
        normalize.packets(text, 1)


def test_decimal_timestamp_duration():
    rows = [
        {
            "src": "192.0.2.1",
            "dst": "192.0.2.2",
            "src_port": 1,
            "dst_port": 2,
            "transport": "tcp",
            "stream": 0,
            "wire_bytes": 1,
            "frame": i + 1,
            "time": Decimal(time),
        }
        for i, time in enumerate(("1700000000.000000001", "1700000000.000000002"))
    ]
    assert normalize.conversations(rows)["conversations"][0]["duration_seconds"] == 1e-9


def test_evidence_schema_rejects_inferred_packet_facts():
    schema = json.loads(
        (Path(__file__).resolve().parents[2] / "contracts/evidence.schema.json").read_text()
    )
    validator = Draft202012Validator(schema)
    Draft202012Validator.check_schema(schema)
    with pytest.raises(ValidationError):
        validator.validate({"epistemic_class": "inferred"})
