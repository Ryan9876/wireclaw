# Gate 7 verification record

Status: **implementation and CI validation complete; automated security scan unavailable**

## Source and branch

- Starting `main` SHA: `128c508443a4dd6606fce3b2c2faf5773d387012`
- Branch: `gate7-reasoning-provider`
- Validated implementation commit SHA: `9609b4d9614687b48edf78f6c09d8e6b7384d6cf`.
- Audit-cycle correction code/test SHA: `52a7fd6acb70e5cfa28e3669d3a2da92e7c4ff93`.
- Gate 8: not started.

## Audit-history finding and correction

- Finding: the Gate 7 service cleared all reasoning rows when re-investigating a complete/failed case or rebuilding a report after a capability on a complete case. The loop also counted all case rows as active-cycle steps.
- Correction: each investigation/report rebuild now gets an opaque 32-character reasoning session ID stored in each bounded step's metadata. The loop queries only that session for step limits, duplicate fingerprints, and finalized-state reuse. The existing per-case database sequence remains globally increasing, and no schema migration was needed.
- Earlier rows are never deleted by a new cycle. Case deletion still removes all cycle history through the existing `reasoning_steps.case_id → cases.id ON DELETE CASCADE` relationship.
- Reports expose only the current cycle's status and step count; session IDs and historical step details are not added to the browser report contract.
- Regression coverage verifies two investigations, repeated fingerprints across cycles, independent step limits, post-completion capability rebuild, historical secret/prompt/response exclusion, reconstructable audit fields, and case-deletion cascade.

## Task matrix

| Task | Implementation and evidence |
| --- | --- |
| G7.1 | Provider protocol and normalized request/result/failure types; Python suite passes. |
| G7.2 | HTTPS-only cloud configuration, bounded OpenAI-compatible request/response, auth header, no redirects; mock endpoint privacy and redirect tests pass. |
| G7.3 | Local mode accepts HTTP/HTTPS and uses the same adapter; mock local HTTP chat-completions test passes. |
| G7.4 | Deterministic allowlist context projection; payload, path, credential, bridge-token sentinels excluded; injection text remains inert data. |
| G7.5 | Strict discriminated action schema; rejects unknown fields/actions, paths, shell/host commands, unsupported capabilities and malformed JSON. |
| G7.6 | Eight-step default and hard maximum of 32; canonical SHA-256 request fingerprints and one execution per identical request. |
| G7.7 | Typed registry and same-case TCP stream validation; invalid/unavailable requests stop before analyzer dispatch. |
| G7.8 | Final proposals checked against current-case deterministic evidence IDs and the existing finding evidence/scope. |
| G7.9 | Provider prose is not copied into findings; only existing deterministic categories can be ranked, and next-evidence text comes from fixed server-side codes. |
| G7.10 | Normalized timeout/connection/response failures fall back to deterministic findings and bounded audit metadata. |
| G7.11 | Adversarial capture-derived strings and unsafe model action cases are covered by deterministic tests. |
| G7.12 | HTTP/1.x timing capability and positive/opaque fixture assertions pass in CI with real TShark/capinfos. |

## Provider, privacy, and fallback

- Provider modes exercised: `none`, cloud with an HTTPS mock endpoint, and local with an HTTP mock endpoint. No real provider account or service was used.
- The controlled cloud mock inspected the exact request body and verified that packet payload, absolute path, credential, bridge-token, and API-key sentinels were absent. Authorization was sent only in its header and was not persisted.
- Redirects were rejected. The client disables environment proxy trust and follows no redirects.
- Scripted provider coverage includes a valid capability request/finalize, unknown capability, invalid parameters, duplicate request, fabricated evidence, malformed/unknown/privileged actions, oversized response, timeout, connection failure, prompt injection, unsupported prose, and shell/path/Wireshark requests.
- `provider_mode=none` remains rules-only. Timeout and connection failure preserve the deterministic report; audit persistence excludes credentials and raw provider content.

## HTTP timing boundary

- Positive `http_server_wait` fixture contains a decodable HTTP/1.x request and delayed response; unit/integration assertions expect an approximately 2.1 second request-to-first-response interval and frame references.
- The existing `server_wait` fixture remains transport-only. Assertions require it to remain insufficient for application-wait attribution.
- Fixture generation and TShark-backed integration pass in CI on Linux with real TShark/capinfos. The local macOS environment lacks those tools, so the local suite skipped packet-tool integration cases.

## Validation results

- Local Python: `295 passed, 147 skipped, 1 warning`.
- Ruff check: passed.
- Ruff format check: 63 files already formatted.
- Python compileall: passed.
- Go: gofmt, `go test ./...`, `go vet ./...`, and `go build ./...` passed.
- Web: `npm ci`, lint, format check, production build, and tests passed (`2` files, `41` tests).
- GitHub Actions: [run 38490638854, run number 80](https://github.com/Ryan9876/wireclaw/actions/runs/38490638854), triggered for PR #10 at branch head `52a7fd6acb70e5cfa28e3669d3a2da92e7c4ff93`; all four jobs succeeded (linux-full, macOS bridge, Linux bridge, Windows bridge).
- CI Linux Python validation: `442 passed, 1 warning`; real packet tools were installed, and Gate 3 validation passed.
- CI production browser tests: `9 passed`; web unit tests: `41 passed` across 2 files. Contract regeneration check, Go validation, web lint/format/build, and Python lint/format/compile all passed in the full job.
- Local-only limitations: the macOS workstation lacks TShark/capinfos, so local Python had 147 packet-tool skips and local Gate 3/browser-fixture commands could not run. CI covered those checks successfully.

## Security review and limitations

- Manual source review covered provider URL/configuration boundaries, redirect handling, context projection, strict action parsing, capability dispatch, proposal evidence checks, persistence, and fallback. No confirmed vulnerability was identified in this review.
- The Codex Security diff scan did not start: its launcher failed before issuing a scan ID because the security backend Python runtime could not import `tomllib` or `tomli`. No canonical scan artifact or scan result exists; this is not represented as a clean automated scan.
- CI acceptance criteria passed. The automated scan is the sole outstanding review limitation; manual review found no confirmed issue. No real provider service was exercised, by design; provider behavior was tested with controlled mocks.
- All Gate 7 execution-spec exit criteria, including reasoning audit retention across cycles, were demonstrated by implementation/tests and successful CI. The missing automated scanner result is recorded as a security-review limitation, not as a clean scan.
