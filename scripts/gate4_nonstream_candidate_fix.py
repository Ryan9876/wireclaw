from pathlib import Path
import re


def replace_once(path, old, new):
    p = Path(path)
    text = p.read_text()
    if old not in text:
        raise SystemExit(f"missing replacement target in {path}: {old[:80]!r}")
    p.write_text(text.replace(old, new, 1))


def regex_once(path, pattern, replacement):
    p = Path(path)
    text = p.read_text()
    updated, count = re.subn(pattern, replacement, text, count=1, flags=re.S)
    if count != 1:
        raise SystemExit(f"regex target count {count} in {path}: {pattern[:80]!r}")
    p.write_text(updated)


inv = "services/api/src/wireclaw_api/investigation.py"

replace_once(
    inv,
    '''@dataclass(frozen=True)\nclass Candidate:\n    transport: str\n    stream: int\n    score: int\n    reasons: tuple[str, ...]\n\n    @property\n    def tcp_stream(self) -> int | None:\n        return self.stream if self.transport == "tcp" else None\n''',
    '''@dataclass(frozen=True)\nclass Candidate:\n    transport: str\n    stream: int | None\n    conversation_index: int\n    score: int\n    reasons: tuple[str, ...]\n\n    @property\n    def tcp_stream(self) -> int | None:\n        return self.stream if self.transport == "tcp" and isinstance(self.stream, int) else None\n''',
)

regex_once(
    inv,
    r'''def _conversations\(\n    evidence: Iterable\[dict\[str, Any\]\],\n\) -> dict\[tuple\[str, int\], dict\[str, Any\]\]:.*?\n    return conversations\n''',
    '''def _conversations(\n    evidence: Iterable[dict[str, Any]],\n) -> list[tuple[int, dict[str, Any]]]:\n    conversations: list[tuple[int, dict[str, Any]]] = []\n    index = 0\n    for item in evidence:\n        if item.get("category") != "list_conversations":\n            continue\n        value = item.get("value") if isinstance(item.get("value"), dict) else {}\n        records = value.get("conversations") if isinstance(value.get("conversations"), list) else []\n        for record in records:\n            if not isinstance(record, dict):\n                continue\n            transport = record.get("transport")\n            if not isinstance(transport, str) or not transport:\n                continue\n            conversations.append((index, record))\n            index += 1\n    return conversations\n''',
)

regex_once(
    inv,
    r'''def _rank_candidates_all\(symptom: str, evidence: list\[dict\[str, Any\]\]\) -> list\[Candidate\]:.*?\n\n\ndef rank_candidates''',
    '''def _rank_candidates_all(symptom: str, evidence: list[dict[str, Any]]) -> list[Candidate]:\n    families = _families(symptom)\n    addresses, ports = _explicit_context(symptom)\n    stream_items = _by_stream(evidence)\n    conversations = _conversations(evidence)\n    candidates = []\n    represented_tcp_streams: set[int] = set()\n\n    for conversation_index, conversation in conversations:\n        transport = conversation.get("transport")\n        stream = conversation.get("stream")\n        stream = stream if isinstance(stream, int) and stream >= 0 else None\n        if transport == "tcp" and stream is not None:\n            represented_tcp_streams.add(stream)\n            anomaly_score, anomaly_reasons = _candidate_signals(\n                stream_items.get(stream, []), families\n            )\n        else:\n            anomaly_score, anomaly_reasons = 0, []\n        context_score, context_reasons = _conversation_signals(\n            conversation, families, addresses, ports\n        )\n        reasons = tuple(sorted(set(anomaly_reasons + context_reasons)))\n        candidates.append(\n            Candidate(\n                transport,\n                stream,\n                conversation_index,\n                anomaly_score + context_score,\n                reasons,\n            )\n        )\n\n    next_index = len(conversations)\n    for offset, stream in enumerate(sorted(set(stream_items) - represented_tcp_streams)):\n        anomaly_score, anomaly_reasons = _candidate_signals(stream_items.get(stream, []), families)\n        candidates.append(\n            Candidate("tcp", stream, next_index + offset, anomaly_score, tuple(anomaly_reasons))\n        )\n\n    return sorted(\n        candidates,\n        key=lambda candidate: (\n            -candidate.score,\n            candidate.transport,\n            candidate.stream is None,\n            candidate.stream if candidate.stream is not None else -1,\n            candidate.conversation_index,\n        ),\n    )\n\n\ndef rank_candidates''',
)

replace_once(
    inv,
    '''    tcp_candidate = next(\n        (candidate for candidate in candidates if candidate.transport == "tcp"), None\n    )\n    if tcp_candidate is not None:\n        stream = tcp_candidate.stream\n''',
    '''    tcp_candidate = next((candidate for candidate in candidates if candidate.tcp_stream is not None), None)\n    if tcp_candidate is not None:\n        stream = tcp_candidate.tcp_stream\n''',
)

unit = Path("tests/unit/test_investigation.py")
with unit.open("a") as stream:
    stream.write(r'''


def test_candidate_ranking_includes_nonstream_ip_conversation():
    evidence = [
        quality(),
        ev(
            "ev_conv_other",
            "list_conversations",
            {
                "conversations": [
                    {
                        "transport": "tcp",
                        "stream": 0,
                        "a": {"address": "192.0.2.1", "port": 51000},
                        "b": {"address": "192.0.2.20", "port": 443},
                        "wire_bytes": 900000,
                        "duration_seconds": 10.0,
                        "a_to_b_packets": 100,
                        "b_to_a_packets": 100,
                    },
                    {
                        "transport": "other",
                        "stream": None,
                        "a": {"address": "192.0.2.1", "port": None},
                        "b": {"address": "198.51.100.77", "port": None},
                        "network_protocol": {"number": 1},
                        "wire_bytes": 84,
                        "duration_seconds": 0.0,
                        "a_to_b_packets": 1,
                        "b_to_a_packets": 1,
                    },
                ]
            },
            filt="ip",
        ),
    ]
    ranked = rank_candidates("failure involving 198.51.100.77", evidence)
    assert ranked[0].transport == "other"
    assert ranked[0].stream is None
    assert ranked[0].tcp_stream is None
    assert "explicit_endpoint_match" in ranked[0].reasons
''')

verification = Path("docs/gate4-verification.md")
text = verification.read_text()
old = "Normalized inventoried conversations are ranked deterministically across available transports using bounded combinations of:"
new = "All normalized inventoried conversations, including transport records without a tool stream ID, are ranked deterministically using bounded combinations of:"
if old not in text:
    raise SystemExit("verification ranking sentence not found")
verification.write_text(text.replace(old, new, 1))

readme = Path("services/api/README.md")
text = readme.read_text()
old = "- ranks normalized TCP, UDP, and other inventoried conversations using explicit endpoint/port context, protocol relevance, anomalies where available, timing, and weak volume signals without excluding small flows solely for low byte count"
new = "- ranks all normalized inventoried conversations, including non-TCP/UDP records without a tool stream ID, using explicit endpoint/port context, protocol relevance, anomalies where available, timing, and weak volume signals without excluding small flows solely for low byte count"
if old not in text:
    raise SystemExit("README ranking sentence not found")
readme.write_text(text.replace(old, new, 1))

# Trigger a push after the registered validation driver was updated; this file is temporary closeout machinery.
