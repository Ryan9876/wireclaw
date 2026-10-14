# Gate 9 macOS Candidate Handoff

Use the exact frozen bundle identified by `wireclaw-release/gate9-candidate-metadata.json`.
Do not rebuild it during handoff. A rebuilt image or bridge is a different candidate.

## Verify the candidate

From the unpacked candidate directory, verify the bundle SHA-256 against the
sidecar metadata, then verify the source SHA and core image ID recorded in
`wireclaw-release/release-metadata.json`. Before startup, load the image archive
with the macOS launcher and confirm the running image config ID equals
`core_image_id`. Record the macOS version, architecture, Docker/runtime version,
Compose version, native Wireshark version, and bridge binary SHA-256 alongside
those identities.

Keep the candidate under a path containing spaces for this acceptance. Install
the packaged bridge with `launch/macos/install-host-bridge.sh`, then start with
`launch/macos/start.sh`. Keep provider mode set to `none` for the deterministic
corpus. Confirm the web URL and bridge health use `127.0.0.1`; do not expose
either listener on another interface.

## Exercise the release

1. Ingest each corpus capture with its scenario symptom. Save the case ID,
   original SHA-256, final report, and evidence IDs with the acceptance record.
2. For every packet-level finding, confirm both **Open Full Capture in
   Wireshark** and **Open Evidence Capture in Wireshark** are visible together.
3. Open each action for DNS delay, high RTT, positive HTTP server wait, and an
   incomplete capture. Record the native process arguments, selected capture
   path, and applied display filter. Confirm the evidence capture is a distinct
   PCAPNG with registered provenance and the original SHA-256 is unchanged.
4. Restart the packaged release and confirm the case, report, evidence, and
   original hash persist. Stop the bridge alone and confirm evidence remains
   accessible while native actions degrade safely.
5. Delete one designated test case through the UI/API and verify only that
   case's original and derived artifacts are removed. Preserve another case as
   a deletion-isolation control.
6. Stop with `launch/macos/stop.sh`. Confirm the case data remains on disk.

Capture screenshots and exact command/process evidence under
`artifacts/gate9/macos/`. Record failures as `FAIL`; unavailable desktop or
release prerequisites are `BLOCKED`. Neither result can be reported as `PASS`.
Windows and Linux are post-V1 targets and are outside this handoff.
