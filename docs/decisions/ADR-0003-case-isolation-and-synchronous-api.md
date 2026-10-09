# ADR-0003: Isolated case stores and bounded synchronous API work

Status: Accepted

Date: 2026-10-08

## Context

Gate 1 uses a content-addressed analyzer store. Application cases additionally
have independent symptoms, lifecycle and deletion. Sharing writable analyzer
directories between cases would make deleting one case affect another.

## Decision

Use generated application case IDs and an isolated Gate 1 store beneath each
`cases/<case-id>/analyzer/`. Register its original and normalized outputs using
logical artifact IDs and relative paths. Reuse Gate 1 ingest and integrity checks
unchanged. Identical uploads in different cases have the same capture SHA but
independent originals. Accept one immutable capture per application case.

Gate 3 uses synchronous, bounded work and rejects concurrent mutations rather
than accumulating a work queue. A process-wide admission lock and a lifetime OS
file lock enforce one service process per data root. All metadata mutations use
SQLite transactions. Successful repeated requests return persisted evidence
without rerunning analyzers; failed requests consume a bounded run budget.
Transient lifecycle states found after restart become FAILED with a safe
interruption record; prior evidence remains. Explicit investigation retries from
FAILED/COMPLETE retain immutable input and evidence.

Deletion atomically renames the complete confined case directory to a generated
trash directory, commits metadata deletion plus a cleanup journal, then removes
the renamed tree. Failed cleanup remains journaled and retried on restart; it
does not restore a partially removed case or touch another case. A crash before
metadata commit is recovered by restoring the renamed directory. Directory trees
are checked for symlinks before destructive operations. The data root must be
private to Wireclaw, as required by Gate 1.

The API streams a raw capture request body (PCAP/PCAPNG octet stream), avoiding
multipart spool behavior and caller-controlled filenames. JSON bodies are bounded
before parsing. Gate 3 investigation runs capture quality/baseline followed by
existing diagnostics, ending at INVESTIGATING; no findings/report are fabricated.
Optional capability failures retain case state and prior evidence.

## Consequences

Per-case originals cost additional disk space, bounded by case/capture quotas.
There is no asynchronous job queue or multi-worker support. Disk and database
cannot share an atomic transaction, so recovery journaling is explicit. Parser
OS sandboxing and Docker packaging remain Gate 8. Privileged filesystem races
are outside the existing private-data-root threat boundary.
