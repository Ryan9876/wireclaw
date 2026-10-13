# Gate 6 verification record

Date: 2026-10-13

Status: **Accepted and merged for the macOS-first V1 scope**

Implementation branch: `gate6-wireshark-evidence-bridge`

Pull request: [#8](https://github.com/Ryan9876/wireclaw/pull/8) — merged

Final Gate 6 branch SHA: `d5118dc58cfaa62bb206f2b703162259a5c93249`

Gate 6 merge commit on `main`: `7a197f44b836377abfb90f5b131763446182211d`

Final Gate 6 branch validation: GitHub Actions run `38447844903` — **success**

The subsequent Gate 7–9 specification merge is `011a03a759eeafb45f6dcf688dacb0ec270c7556`; it does not change the accepted Gate 6 implementation.

## V1 platform scope

ADR-0006 changes the V1 release target to macOS only. Windows and Linux are post-V1 release-qualification targets and no longer block Gate 6, Gate 8, or Gate 9.

Existing Windows/Linux bridge implementation and CI coverage are retained as portability groundwork. They must not be described as supported release platforms until a future release completes native Wireshark, packaging, launcher/install, and end-to-end acceptance on those hosts.

Under the current authoritative V1 scope, Gate 6 native acceptance is required on macOS and has passed.

## Scope and requirements

Gate 6 implements bounded evidence-capture extraction and native Wireshark integration. It addresses R-F018, R-F019, R-F020, R-D003, R-D004, and R-U003 while preserving the security, immutability, resource-bound, auditability, and safe-degradation requirements.

## G6.1–G6.13 disposition

| Task | Evidence | Result |
| --- | --- | --- |
| G6.1 Evidence extraction | Analyzer extraction plus API orchestration; bounded parse/failure integration tests | Complete |
| G6.2 Provenance | Parent SHA-256, extraction mode/rule, display filter, finding/evidence IDs, tool versions; integrity-verified reuse | Complete |
| G6.3 Bridge protocol | Go bridge exposes only health and approved-open behavior | Complete |
| G6.4 Loopback/auth/origin/replay | Numeric loopback, strict configured origin, bounded JSON, one-use grants, hashed token | Complete |
| G6.5 Path confinement | Logical IDs, case confinement, traversal/symlink/cross-case/hash checks | Complete |
| G6.6 Wireshark selection | Trusted admin configuration or OS discovery; request cannot choose executable | Complete |
| G6.7 macOS | Native executable discovery/direct argv plus real GUI acceptance | **Complete and V1 accepted** |
| G6.8 Windows | Build/discovery/argv CI retained as portability groundwork | Complete as non-release groundwork; native qualification deferred post-V1 |
| G6.9 Linux | Build/discovery/argv CI retained as portability groundwork | Complete as non-release groundwork; native qualification deferred post-V1 |
| G6.10 Full Capture | Immutable original plus finding-specific backend-approved filter | Complete |
| G6.11 Evidence Capture | Bounded derived PCAPNG plus validated/reused artifact | Complete |
| G6.12 Copy Filter / Show Evidence | Remain usable under bridge degradation; UI health states isolated | Complete |
| G6.13 Bridge security | Traversal, symlink, case isolation, tamper, origin, token, filter, argv, spaces, reaping, no generic exec | Complete |

## Automated implementation validation

The latest code-changing Gate 6 head before the macOS-first documentation/spec scope update was:

`b9c686266c6e47576a383e294bbf1701f17bd6db`

PR Actions run `38444749751` passed all jobs on that SHA. The final Gate 6 documentation/spec head `d5118dc58cfaa62bb206f2b703162259a5c93249` then passed run `38447844903` before merge.

Validated results:

- Ubuntu 24.04 full validation used real TShark/capinfos.
- Python: **409 passed, 1 warning**.
- Ruff, format, compileall, and Gate 3 live validation passed.
- Gate 3 reported 447 schema checks plus successful live API/repeat/evidence/grant/deletion checks.
- Go test, vet, and build passed on Ubuntu 24.04, macOS 14, and Windows 2025.
- Web lint, format, and production build passed.
- Web unit tests: **41 passed**.
- Production Playwright: **9 passed**, retries disabled.
- Generated OpenAPI/web contracts matched checked-in files.

The Windows/Linux jobs above demonstrate portability of bridge compilation/discovery/argv behavior only. They are not native release acceptance and are not represented as such.

## Local macOS validation

On the macOS ARM64 workstation:

- Gate 6 integration tests: **5 passed**.
- Go format/test/vet/build passed.
- Web lint/format/build/unit tests passed.
- Production Playwright: **9 passed**.
- OpenAPI/generated web contracts matched.

The full local Python suite with TShark/capinfos 4.6.9 produced **404 passed, 5 failed, 1 warning**. One failure was a child-process startup timing threshold and four were Gate 2/4 TShark classification differences for reordered/PMTUD fixtures. The pinned Ubuntu CI toolchain passed all 409 tests. No Gate 2/4 implementation was changed in Gate 6.

This tool-version difference is a Gate 8 reproducibility concern and is one reason the release analyzer image must pin deterministic tool versions.

## Native macOS acceptance

| Platform | Full | Evidence | Filter | Spaces | Degraded | V1 result |
| --- | --- | --- | --- | --- | --- | --- |
| macOS 27.0.1 arm64, Wireshark 4.6.9 | Pass | Pass | Pass | Pass | Pass | **ACCEPTED** |

Acceptance record:

```text
OS/version: macOS 27.0.1
Architecture: arm64
Wireshark version: 4.6.9
Fixture: high_rtt.pcap, uploaded as "trace with spaces.pcap"
Finding ID/category: finding_001 / tcp.rtt
Display filter: tcp.stream == 0
Original SHA before/after: 72c8be5c65a54ecc74c53f33d7befb088028e5ced759f50d2341e7233904f22c (unchanged)
Full Capture: native Wireshark opened immutable original with -Y tcp.stream == 0
Evidence Capture: native Wireshark opened derived PCAPNG with -Y tcp.stream == 0
Derived capture: 5 packets / 584 bytes
Provenance: parent SHA, finding/evidence, tcp_stream extraction mode, and filter recorded
Path-with-spaces: passed for data root/uploaded filename
Bridge-down degradation: both native actions disabled while Copy Filter, Show Packet Evidence, and backend evidence generation remained usable with API healthy
GUI evidence: active native Wireshark window and process argv confirmed
```

## Post-V1 platform roadmap

Windows and Linux native qualification is intentionally deferred. Before either is described as supported in a future release, perform at least:

1. native bridge/Wireshark desktop acceptance;
2. Full Capture immutable-original verification;
3. Evidence Capture bounded-derived verification and provenance;
4. approved filter verification;
5. paths-with-spaces and native argument handling;
6. bridge/Wireshark degraded states;
7. packaged launcher and bridge install/uninstall flow;
8. Docker/core release smoke without a developer toolchain;
9. Gate 9-equivalent security/privacy/immutability/end-to-end acceptance;
10. exact environment and release-identity recording.

These items are tracked in `docs/roadmap.md` and are not V1 Gate 6 exit criteria.

## Gate 6 exit decision

V1 Gate 6 exit criteria are satisfied:

- both Wireshark actions are visible together when applicable;
- both actions have been manually accepted in a real native macOS desktop session;
- immutable original and bounded evidence behavior are verified;
- paths-with-spaces and degraded behavior are verified;
- automated security tests show no generic/arbitrary command-execution path;
- Windows/Linux release qualification is explicitly deferred by ADR-0006 rather than falsely claimed complete.

Gate 6 was accepted and merged through PR #8. Stage 6 is closed under the current macOS-first V1 specification.

Gate 7 implementation begins from the merged V1 authority on `main`, including `AGENTS.md` and `specs/v1/gate7-execution.md`.
