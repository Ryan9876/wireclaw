# Wireclaw Case Manager and Multi-Capture Investigation Design

## Purpose

Wireclaw currently treats a case as a single capture. The next version should treat a case as one troubleshooting problem that can contain multiple packet captures collected from different points in the path. Users must be able to add, remove, and label captures without creating separate cases, while Wireclaw preserves each capture's provenance, analyzes each capture independently, correlates matching traffic across capture points, and uses that cross-vantage evidence to increase or decrease support for a fault location.

The UI anchor for this capability is a persistent **Case Manager** in the lower-left of the application.

## User outcome

A network engineer investigating one incident can:

1. Create or recover one case for the problem.
2. Drag/drop or add multiple `.pcap`/`.pcapng` files to that case.
3. See every capture and its analysis status in a persistent Case Manager.
4. Label each capture's vantage point as Client, Network, Server, Other, or Unknown.
5. Refine Network captures as Firewall, Router, Switch, Load balancer, Proxy, Wireless, or Other network device.
6. Change a capture's label without re-extracting packet evidence.
7. Remove one capture without deleting the case.
8. See conclusions update when captures are added, relabeled, or removed.
9. Benefit from stronger deterministic conclusions when the same flow is observed at more than one vantage point.
10. Trace every cross-vantage conclusion back to the contributing source captures and packet/frame evidence.

## Product principles

- **One problem, many viewpoints.** A case contains multiple captures; captures do not become separate cases.
- **Never merge away provenance.** Wireclaw must not physically combine PCAP files into a synthetic capture and pretend they came from one sensor.
- **Analyze locally first, correlate second.** Every capture gets the normal deterministic analysis independently before cross-vantage correlation runs.
- **Deterministic facts remain authoritative.** Cross-vantage localization and support levels come from deterministic correlation. The embedded AI only explains those results in plain language.
- **Unknown is valid.** A capture may remain unlabeled/Unknown. Wireclaw must not force the user to guess its location.
- **Confidence is evidence-driven.** More captures do not automatically mean higher support; support rises only when correlated observations constrain the possible fault location.
- **Ruling out is useful.** Cross-vantage evidence should explicitly identify path segments or endpoints that are inconsistent with the observed delay/loss when the evidence supports doing so.

## Scope for the first implementation

The first implementation supports:

- 1-4 captures per case.
- User-supplied capture-location labels.
- TCP correlation first.
- SYN/SYN-ACK/ACK and established TCP-stream correlation.
- Exact tuple matching when the tuple is preserved.
- Packet/flow matching using TCP sequence/acknowledgment values, flags, payload length, ordering, and timing where needed.
- Basic clock-offset estimation when matching packets are visible in two captures.
- Cross-vantage deterministic evidence and case-level report updates.
- Existing single-capture cases through schema migration/backward compatibility.

The first implementation does **not** need to solve every NAT, asymmetric-routing, load-balancer, packet-broker, or long-duration clock-drift case. When correlation is not strong enough, Wireclaw must say so rather than infer a path.

## Case Manager UI

### Desktop

A persistent floating dock is anchored to the lower-left of the app. It should preserve the conversational main column instead of becoming a full-height dashboard sidebar.

Target expanded width: approximately 320-360 px.

Header:

- `Case Manager`
- active case display name
- capture count
- collapse control

The expanded panel contains:

- a compact drag/drop target (`Drop PCAP files here` / `click to add files`)
- one row per capture
- capture filename
- size when known
- current processing status
- capture-location selector
- overflow menu for rename/remove

The panel is collapsible. During a session, remember the user's expanded/collapsed choice. When a case first gains multiple captures, default to expanded unless the user already chose otherwise in the current session.

### Capture row states

Each capture can display:

- `Waiting`
- `Preparing…`
- `Analyzing…`
- `Analyzed`
- `Correlating…`
- `Needs attention`

Once correlation exists, a secondary line may show a concise status such as:

- `4 flows matched with other captures`
- `No matching flow found`
- `Clock alignment uncertain`

### Capture-location control

Primary values:

- Unknown
- Client
- Network
- Server
- Other

When Network is selected, allow an optional subtype:

- Firewall
- Router
- Switch
- Load balancer
- Proxy
- Wireless
- Other network device

Changing the location is metadata-only. It must not re-ingest or re-run packet extraction for that capture. It invalidates/re-runs only cross-capture correlation and any case-level conclusions that depend on capture placement.

### Adding captures

Users can:

- drag/drop on the Case Manager
- click `Add capture`

Adding a capture to a completed case preserves the existing case and source captures. The case may enter a processing state while the new capture is analyzed and correlated, but the UI should not discard the prior report while work is in progress.

### Removing captures

The row overflow menu exposes `Remove from case`. Removing a capture:

- does not delete the case
- removes that capture's source artifact and derived evidence from active case reasoning
- invalidates cross-vantage evidence that depended on it
- recomputes the report/support level
- requires confirmation when removal would discard stored capture data

The application should explain when support drops after evidence is removed.

### Responsive behavior

- Wide desktop: persistent lower-left dock.
- Narrow desktop/tablet: compact/collapsed dock that expands over the page.
- Mobile: bottom sheet/full-width case manager instead of covering most of the report.

## Data model

The current schema stores capture identity directly on `cases` (`capture_sha`, `original_id`, `capture_name`). Move to an explicit capture entity while retaining compatibility during migration.

### `captures`

Add a table conceptually equivalent to:

- `id` - 32-character logical ID, primary key
- `case_id` - owning case
- `capture_name` - original filename / safe display label
- `display_name` - optional user rename
- `original_artifact_id` - immutable source artifact
- `sha256`
- `bytes`
- `vantage_type` - `unknown|client|network|server|other`
- `vantage_subtype` - nullable network subtype/free bounded label
- `status`
- `last_error`
- `created`
- `updated`

Existing single-capture cases migrate to exactly one capture row using their existing source artifact and capture metadata.

### Runs, evidence, and artifacts

Add `capture_id` scoping where appropriate:

- per-capture analyzer runs reference the capture they analyzed
- per-capture evidence records reference their source capture
- source/derived artifacts can reference their capture
- case-level correlation runs/evidence use `capture_id = NULL`

The case remains the ownership/security boundary.

### Cross-vantage evidence

Do not introduce synthetic packet facts. Cross-vantage evidence is derived from already-stored deterministic evidence/packet observations and must contain explicit provenance:

- contributing capture IDs
- contributing evidence IDs
- matched flow/packet identifiers
- estimated clock offsets/uncertainty where used
- correlation limitations
- support level

Case-level correlation evidence should remain traceable through the normal Technical Evidence UI.

## API design

Prefer a two-step capture lifecycle rather than overloading the legacy singular upload endpoint:

1. `POST /api/cases/{case_id}/captures`
   - creates capture metadata
   - accepts bounded JSON metadata such as capture name and vantage type
   - returns a capture ID

2. `PUT /api/cases/{case_id}/captures/{capture_id}/data`
   - raw octet-stream PCAP upload
   - preserves existing upload size/time/security boundaries

Additional endpoints:

- `PATCH /api/cases/{case_id}/captures/{capture_id}` - rename/change vantage metadata
- `DELETE /api/cases/{case_id}/captures/{capture_id}` - remove capture after confirmation at the UI layer
- case responses expose capture summaries and statuses

Keep the current singular `/api/cases/{case_id}/capture` route during migration as a compatibility wrapper that creates/uploads the first capture when no explicit capture exists. New UI code should use the plural capture API.

All existing host/origin, size, confinement, and safe-error rules remain in force.

## Processing model

### Phase 1: per-capture analysis

Each source capture is analyzed independently using the existing deterministic capabilities. Evidence produced in this phase is capture-scoped.

### Phase 2: flow correlation

For TCP in v1, build direction-normalized candidate flow identities and match observations across captures using the strongest available combination of:

- source/destination IP and port tuple
- TCP SYN/SYN-ACK/ACK flags
- sequence and acknowledgment values
- payload lengths
- packet ordering
- capture-relative timing

Exact tuple matching is preferred. If NAT or another transformation prevents reliable matching, do not force a correlation.

### Phase 3: clock alignment

When the same packets are confidently matched in two captures, estimate capture clock offset from multiple shared observations. Use a robust median/trimmed approach and report uncertainty rather than treating timestamps as perfectly synchronized.

Cross-vantage timing claims require sufficient matched observations and bounded uncertainty. If the estimated uncertainty is too large relative to the claimed delay, timing localization must remain inconclusive.

### Phase 4: deterministic localization

Produce case-level evidence only when the observations constrain the fault location. Examples:

- client and server both see the SYN almost immediately, then the server's SYN-ACK appears ~3.2 s later: supports server/listener-side delay and makes the client-to-server network path unlikely
- client sees SYN, firewall sees SYN, server capture never sees matching SYN while capture windows overlap with adequate quality: supports a path segment after the firewall and before the server, subject to capture limitations
- server sees SYN-ACK promptly, client sees it much later, and an intermediate capture narrows the transition: supports return-path delay on the corresponding segment

Do not translate `retransmission` into physical loss without corroborating cross-vantage evidence.

## Support/confidence presentation

Do not raise support merely because more captures exist. The report should expose why cross-vantage evidence changes support.

Example:

`High support · observed from 3 capture points`

- Client sent connection request
- Firewall observed request immediately
- Server received request immediately
- Server response occurred ~3.2 s later
- Firewall/client observed the response immediately afterward

This allows the report to say both where evidence points and which areas are unlikely.

## Report behavior

The existing conversational report remains the primary surface.

When multiple captures materially improve the conclusion, add a concise `Observed from N capture points` explanation and make source capture names available through Technical Evidence.

OSI cards continue to represent protocol-layer conclusions; the Case Manager represents evidence sources, not a second analysis dashboard.

If captures cannot be correlated, say so plainly and keep per-capture conclusions separate rather than averaging them.

## AI follow-up behavior

The embedded AI receives only the normalized case report and bounded evidence as today, extended with approved cross-vantage evidence. It must not perform packet matching itself.

Visible AI prose stays plain-language and should explain cross-vantage facts, for example:

`The request reached the server within a few milliseconds, but the server did not respond for about 3.2 seconds. That makes the client-to-server network path unlikely to be the source of the delay.`

Raw evidence IDs remain structured metadata/Technical Evidence, not visible conversational prose.

## Security and privacy

- All captures remain local.
- Do not send raw packet payloads to the model.
- Do not physically merge source captures.
- Preserve immutable source hashes.
- Keep path confinement and symlink protections.
- Keep bounded provider context and evidence allowlists.
- Removing a capture must clean only case-owned data for that capture and must never traverse arbitrary paths.

## Migration and backward compatibility

Bump the SQLite schema version and migrate existing v3 cases.

For every existing case with `original_id`/capture metadata:

1. Create one capture row.
2. Link existing per-capture artifacts/runs/evidence to that capture where deterministically attributable.
3. Preserve existing case IDs, histories, findings, and source hashes.
4. Continue to recover old cases through the UI.

The migration must be transactional and covered by an upgrade regression test.

## Failure behavior

- One failed capture must not corrupt other captures in the case.
- A failed capture row shows `Needs attention` and a safe error.
- Correlation failure is not case failure; the report falls back to per-capture evidence.
- Unsupported/ambiguous correlation must be represented as unknown, never guessed.
- Removing the last capture leaves the case available for another upload rather than deleting the case automatically.

## Test strategy

### Backend

- v3 -> new schema migration preserves a legacy single-capture case
- create/upload/list/patch/delete capture lifecycle
- maximum 4 captures enforced
- capture ownership and case isolation
- removal invalidates only dependent capture/correlation evidence
- role changes do not rerun per-capture extraction
- per-capture evidence provenance
- exact TCP flow correlation
- ambiguous flow correlation fails closed
- clock offset estimation and uncertainty bounds
- case-level cross-vantage evidence provenance
- report support rises only when deterministic correlation warrants it
- report degrades correctly when contributing capture is removed

### Web

- persistent Case Manager shows active case/captures
- drag/drop and Add capture
- capture status transitions
- role selector and Network subtype
- remove confirmation
- collapsed/expanded session behavior
- mobile bottom-sheet behavior
- adding/removing/relabeling updates report without creating a new case
- keyboard and screen-reader accessibility

### End-to-end qualification

Use synthetic captures representing the same TCP connection from client, middle, and server viewpoints. Include cases where:

1. server delays SYN-ACK
2. request disappears between middle and server
3. response disappears between server and middle/client
4. timestamps have a known offset
5. captures do not contain enough common evidence to correlate

Verify that conclusions localize only when the deterministic evidence supports it and remain inconclusive otherwise.

## Non-goals for v1

- automatic inference of capture vantage point
- arbitrary PCAP count
- generic arbitrary-topology reconstruction
- guaranteed NAT/load-balancer correlation
- UDP/DNS cross-vantage localization beyond existing per-capture analysis
- AI-driven correlation
- cloud upload/storage

## Acceptance criteria

The feature is ready when a user can keep one case open, add up to four captures, label their positions, remove/relabel them, and see deterministic report support update from independently analyzed and safely correlated evidence without losing source provenance. Existing single-capture cases must continue to work after migration.
