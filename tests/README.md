# Tests

Wireclaw uses packet fixtures and requirement-traceable tests as diagnostic evidence.

```text
tests/
├── fixtures/      # PCAP/PCAPNG and generated deterministic inputs
├── golden/        # expected normalized evidence and RCA outcomes
├── integration/   # analyzer/API/storage/report integration
└── acceptance/    # end-to-end V1 scenarios
```

Mandatory principles:
- test healthy traffic so Wireclaw can say no material issue is supported
- test ambiguous traffic so Wireclaw returns `insufficient_evidence` when appropriate
- test similar-looking fault pairs such as high RTT vs server delay and reordering vs loss
- every fixed diagnostic defect gains a regression fixture
- model prose alone never determines test success
- packaged Wireshark launch behavior must eventually cover all three supported host OS families

## Gate 4 RCA goldens

`tests/integration/test_gate4_golden.py` runs the real deterministic analyzer against generated Gate 1/2 packet captures, assembles a rules-only Gate 4 report, validates the investigation-result schema, repeats the report for determinism, verifies the immutable original capture, and compares a semantic RCA summary with:

`tests/golden/gate4/rules_cases.json`

The Gate 4 corpus currently covers healthy TCP, retransmission/loss indicators, pure reordering, high RTT, server-wait ambiguity, receive-window stall, reset, DNS delay, TLS delay, failed establishment, PMTUD signals, and a midstream/limited capture.

Two boundaries are deliberately golden-tested as unresolved:
- reordering without sufficient discriminating evidence must not be promoted to packet-loss root cause
- server-wait-looking idle time without deterministic application request/response timing must remain `insufficient_evidence`

`tests/integration/test_gate4_report.py` covers persisted report integrity, schema validation, recorded packet-tool versions, restart/rerun stability, report artifact reuse, optional capability failure isolation, and report-assembly failure preservation of prior evidence/original input.

See `docs/testing.md`, `docs/gate4-verification.md`, and Gate 9 in `specs/v1/tasks.md`.
