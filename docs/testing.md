# Testing and Acceptance Strategy

Wireclaw diagnostics must be validated against reproducible packet evidence. Passing UI tests or plausible model prose is not sufficient.

## Test layers

### 1. Unit tests

Test pure logic such as:
- parsers
- normalization
- timing calculations
- evidence indexing
- path validation
- confidence policy
- state transitions

### 2. Golden analyzer tests

Use small committed fixture captures or generated fixtures with known expected observations.

For each analyzer capability, compare normalized output against stable expected evidence rather than raw CLI formatting where possible.

Record analyzer version expectations so upgrades are deliberate.

### 3. Integration tests

Exercise:
- capture ingest
- analyzer process runner
- artifact registry
- SQLite persistence
- evidence capture generation
- API lifecycle
- provider adapter fallback

### 4. Host bridge tests

Test logical artifact resolution and process-launch planning separately from actually opening a GUI.

Security cases include:
- invalid auth
- invalid case/artifact ID
- traversal
- symlink escape
- non-Wireshark executable attempt
- excessive/malformed display filter
- launch storm/rate limit

Platform smoke tests then verify actual native Wireshark launch.

### 5. End-to-end acceptance

A packaged build should be tested from a clean user perspective on macOS, Windows, and Linux.

## Required diagnostic fixture classes

### Healthy baseline

Expected:
- no material transport fault
- system does not fabricate a root cause

### DNS delay/failure

Expected:
- Wireclaw identifies name-resolution contribution when supported
- affected queries/responses are traceable

### TCP loss/retransmission

Expected:
- relevant stream is identified
- retransmission/duplicate-ACK evidence is quantified
- result does not overstate where along the path loss physically occurred unless capture topology proves it

### High RTT

Expected:
- RTT evidence is quantified
- high RTT is distinguished from server response wait when transaction timing allows

### Receiver constraint

Expected:
- zero-window/window limitation is identified when present
- throughput impact is explained

### Reset/reconnect

Expected:
- reset origin/direction is reported as observed from capture perspective
- reconnection behavior is correlated with user-visible interruption where possible

### TLS delay

Expected:
- TCP establishment and TLS establishment are separated
- payload encryption does not prevent timing analysis from being useful

### Server/application wait

Expected:
- request completion to first response data is measured where protocol evidence permits
- network RTT/loss evidence is considered before attributing wait to server/application domain
- result acknowledges that delay may be behind the observed server boundary (for example database/downstream dependency)

### MTU/PMTUD

Expected:
- strong conclusion requires direct/supporting indicators
- absence of relevant ICMP or fragmentation signals lowers confidence rather than forcing diagnosis

### Incomplete/one-sided capture

Expected:
- capture-quality limitation is raised
- unsupported fault-location claims are suppressed
- next recommended evidence is concrete

### Malformed/adversarial capture

Expected:
- analysis fails safely or partially
- application remains responsive
- untrusted field strings do not become instructions/commands

## Ambiguity tests

These are mandatory.

Create pairs of scenarios that can look similar at a superficial level, for example:

1. high RTT vs slow server response
2. packet loss vs packet reordering
3. zero-window receiver stall vs server think time
4. DNS delay vs TCP connect delay
5. MTU problem vs generic retransmission
6. capture loss vs network loss

Wireclaw should identify which observable evidence distinguishes the pair and return `insufficient_evidence` when that evidence is absent.

## Model evaluation

Do not score a model merely on whether its final text matches an expected paragraph.

Evaluate:
- capability selection quality
- unnecessary/repeated tool requests
- whether it references existing evidence IDs
- unsupported claim rate
- correct use of uncertainty
- fault-domain classification
- whether next-evidence recommendations would discriminate remaining hypotheses

Run the same cases in rules-only mode to measure whether the model adds value over deterministic baseline.

## Privacy tests

Capture/inspect outbound model requests in tests.

Under default cloud policy, verify absence of:
- raw PCAP bytes
- raw payload blocks
- extracted credentials/tokens/cookies
- unrelated packet contents

## Performance/resource tests

Measure:
- bounded memory behavior
- analyzer timeout behavior
- large-capture summarization
- maximum query-row enforcement
- evidence-capture size enforcement
- cancellation/cleanup
- concurrent-case limits

A large input must degrade by limiting/summarizing work, not by exhausting the workstation.

## Regression policy

Every confirmed diagnostic defect should produce a fixture or reproducible synthetic capture before or with the fix.

Once added, the case becomes a permanent regression test.

## Release acceptance record

A release candidate should produce a machine-readable test record containing:
- Wireclaw version
- analyzer versions
- fixture-set revision
- platform
- pass/fail by requirement/scenario
- known limitations

The release is not accepted solely because CI is green; the diagnostic acceptance corpus and cross-platform launch behavior must pass.
