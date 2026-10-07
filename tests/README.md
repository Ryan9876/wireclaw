# Tests

Wireclaw uses packet fixtures and requirement-traceable tests as diagnostic evidence.

Planned structure:

```text
tests/
├── fixtures/      # PCAP/PCAPNG and generated inputs
├── golden/        # expected normalized evidence/results
├── integration/   # API/analyzer/storage integration
└── acceptance/    # end-to-end diagnostic scenarios
```

Mandatory principles:
- test healthy traffic so Wireclaw learns to say no material issue is supported
- test ambiguous traffic so Wireclaw returns insufficient evidence when appropriate
- test similar-looking fault pairs such as high RTT vs server delay and reordering vs loss
- every fixed diagnostic defect should gain a regression fixture
- model prose alone never determines test success
- test all three supported host OS families for packaged Wireshark launch behavior

See `docs/testing.md` and Gate 9 in `specs/v1/tasks.md`.
