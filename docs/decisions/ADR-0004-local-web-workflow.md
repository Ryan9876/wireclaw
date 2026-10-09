# ADR-0004: Same-origin web workflow over persisted deterministic reports

Status: Accepted

Date: 2026-10-09

## Context

Gate 5 needs a browser workflow without weakening Gate 3 host/origin checks or
duplicating Gate 4 diagnosis. The existing API uses synchronous bounded mutations
and persisted case history; there is no job queue, event stream, symptom-update
endpoint, or host bridge.

## Decision

Primary journey:

Create case → select/drop PCAP → describe symptom → analyze → show progress →
show conclusion + confidence + fault domain + capture quality → inspect
findings/evidence/time attribution → delete case.

The intake form collects capture and symptom before committing the case. Submit
creates the case with its symptom, uploads the File as an octet stream, then
invokes investigation. Case creation is implicit in this one primary action.

Use React/TypeScript, Vite, semantic HTML, and repository-owned CSS. No component
framework, remote fonts, CDN, telemetry, model adapter, or remote endpoint is
needed. The API serves the compiled UI and fixed assets at its existing loopback
origin. No CORS exception or configurable browser API URL is introduced. Docker
and release launchers remain Gate 8.

Generate browser types from the API OpenAPI and report/evidence schemas. Validate
reports and evidence against those schemas at the browser boundary. Render text
as text, never markup. All requests use fixed same-origin API resources.

Poll persisted case state/history and running analyzer records. Fast stages may
only appear in history; do not manufacture progress percentages or durations.
Retain only a logical case ID in the URL fragment. Reload reads state; it never
automatically resubmits an upload or investigation. An idle post-upload case has
an explicit Continue action. Recovery failures remain visible and retryable.

Clear results on mutations, lost status connectivity, and case revision changes.
Retrieve a report between two matching COMPLETE snapshots (including report
artifact hashes) before publishing it. Continue polling completed cases so a
later evidence-changing execution cannot leave an old report displayed.

Per-finding fault domains already exist internally in Gate 4 rules. Expose them
and the required inferred epistemic class in the report contract for G5.7; no
diagnostic rule changes. The additive fields remain optional in schema version
1.0 for persisted Gate 4 reports. Legacy missing fields display Unknown / Inferred
without inventing a domain.

Both required Wireshark actions remain visible together for applicable findings,
disabled with an explicit Gate 6 integration-unavailable explanation. Display
filters and normalized evidence remain readable. No launch/extraction endpoint
or alternate host integration is introduced.

Deletion requires a modal confirmation identifying the case and explicitly naming
the stored original, normalized evidence, and report. Respect cleanup_pending;
metadata deletion does not justify claiming all files are removed.

## Consequences

Development builds require Node and the existing Python API; release packaging
remains deferred. No case-list API exists; recovery uses the bookmarked/current
case fragment and the UI offers a logical-ID recovery field. Stage transitions
are eventually observed through polling rather than an event stream. Separate
polling and mutation request generations prevent late responses from restoring
obsolete results or a deleted case. Core offline analysis remains rules-only.
