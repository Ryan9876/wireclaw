# Acceptance Tests

Acceptance tests validate complete diagnostic scenarios against the V1 requirements and release gates.

Each scenario should identify:
- requirement IDs
- fixture(s)
- symptom statement
- expected capture-quality assessment
- expected evidence/finding class
- acceptable confidence range
- required uncertainty/limitations
- expected Wireshark actions
- platform applicability

The acceptance suite is the product-level release oracle for diagnostic behavior.

## Native embedded-AI qualification evidence

`scripts/native_embedded_ai_qualification.py` runs fixed local EAI.14 and
sandbox-isolation handlers and records evidence for one frozen release archive. Candidate
freezing verifies the signed app before creating its immutable archive and
records the app tree, nested executable hashes, signing mode, signer identity,
Hardened Runtime mode, and exact parent/helper entitlement identities.

Evidence must be collected only after exact-head CI and freezing the exact
candidate. The tool verifies that the frozen archive contains the exact bundle
tree bytes and modes, checks signatures and candidate identity before and after
the run, and writes each check as a separate JSON file alongside a summary.
Fixed handlers verify packaged model/runtime hashes, exact signed parent/helper
entitlements, and the opt-in Task 9/10 native probes. Source pytest suites are
recorded as source-regression evidence only; they cannot pass an EAI.14
candidate check. Candidate-bound persistence and space-path checks are limited
to observations made by the Task 10 packaged-copy run. The UI, representative
cases, Wireshark actions, rules-only fallback, port-conflict/hash-tamper
fallback, and privacy sentinel checks accept only a fixed-schema,
candidate-bound operator evidence package. It requires the readiness
screenshot; three named scenario reports plus a human-reviewed comparison;
separate screenshots for both Wireshark actions; and exact JSON receipts for
the helper-loss, conflict/tamper, and privacy-sentinel procedures. The runner
checks the operator attestation, exact assertion sets, bounded file sizes, PNG
chunk framing/CRCs, case-report schema/candidate/model/runtime identities,
original-capture hash equality, evidence-ID references, hashes, and safe
relative paths before copying evidence into the private output directory.
Visual and behavioral meaning of operator-attested artifacts is not machine
validated; evidence rows state their operator-attested basis. Missing evidence
remains `NOT_RUN`; raw result JSON or arbitrary PASS text is not imported. Its
`--print-operator-procedure` option prints the fixed interaction steps.

The Task 9 isolation probe uses a separate signed fixture. Its evidence records
that fixture scope and script/source provenance and explicitly says it is not
runtime evidence for the frozen candidate. It is paired with an independent
signature/entitlement check against the candidate itself.

Every check records its fixed handler or a bounded `NOT_RUN` reason. Contract
tests exercise handlers with fakes only; they do not launch the native probes.
Destructive tamper and port-conflict checks must use a private copy created by
`copy_destructive_fixture`; never mutate the frozen candidate.

The tool does not infer PASS from signing metadata or missing checks. Source
test evidence is collected only when the candidate source commit is the exact,
clean checkout; the checkout is rechecked after collection. Ad-hoc development
signing records Developer ID, production Hardened
Runtime, notarization, stapling, and production qualification as `NOT_RUN`.
