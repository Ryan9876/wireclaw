# ADR-0006: macOS-First V1 Platform Scope

Status: Accepted

Date: 2026-10-13

## Context

Wireclaw's original V1 plan required equivalent release behavior on macOS, Windows, and Linux. Gate 6 has complete native desktop acceptance on macOS, while Windows and Linux have automated bridge build/discovery/argv coverage but have not completed real native Wireshark GUI acceptance.

Requiring all three host operating systems before proceeding would delay the V1 product validation work in Gates 7–9 without improving the macOS release path. The codebase already isolates host-specific integration behind interfaces, so Windows and Linux can remain portability targets without being V1 release blockers.

This is a product-scope change, not a claim that Windows/Linux are complete. Automated CI on those platforms remains useful engineering evidence, but does not constitute release support.

## Decision

Wireclaw V1 is a **macOS-supported release**.

For V1:

- macOS is the only release-qualified host platform;
- native Wireshark integration must be accepted on macOS;
- Docker packaging, launchers/installers, release smoke tests, and Gate 9 end-to-end acceptance are required on macOS;
- Windows and Linux native release qualification are explicitly deferred to a future post-V1 release;
- existing Windows/Linux bridge implementations and CI build/discovery/argv tests are retained as portability groundwork, not as a support promise;
- Gates 7–9 must not be blocked on Windows/Linux desktop acceptance.

The product architecture must continue to isolate platform-specific code so future Windows/Linux support does not require redesigning the analyzer, API, evidence model, or host-bridge protocol.

## Support terminology

For V1 documentation:

- **Supported** means release-qualified and covered by required native acceptance.
- **Portability groundwork** means code may compile or pass non-GUI CI on another platform, but the platform is not a supported V1 release target.
- **Future target** means planned for post-V1 work and not part of the V1 release gate.

Do not describe Windows or Linux as supported V1 platforms merely because CI passes there.

## Consequences

Positive:

- Gate 6 can close against demonstrated macOS native behavior;
- Gate 7 model/reasoning work can begin without waiting for additional desktop environments;
- Gate 8 packaging can focus on one release-qualified host;
- Gate 9 can validate the V1 product deeply on the actual release target;
- existing Windows/Linux portability work is preserved for a future release.

Negative:

- V1 is not a cross-platform end-user release;
- Windows/Linux users must wait for a later release before support is claimed;
- future platform qualification still requires native Wireshark GUI acceptance, packaging/launcher work, and end-to-end release smoke testing on each added OS.

## Superseded scope statements

This decision supersedes earlier V1 statements in ADR-0001 and other planning documents that required macOS, Windows, and Linux as simultaneous V1 release targets.

The V1 constitution, requirements, solution, tasks, verification records, and roadmap are updated alongside this ADR so the current authoritative documents agree.

## Future release qualification

Before either Windows or Linux is promoted from roadmap target to supported platform, that release must include at least:

- native host-bridge behavior accepted in a real desktop session;
- Full Capture and Evidence Capture verified in native Wireshark;
- paths-with-spaces and degraded-state behavior;
- packaged start/stop and bridge install/uninstall flow;
- Docker/core workflow on that host;
- release smoke tests without a developer toolchain;
- Gate 9-equivalent end-to-end and security acceptance;
- documentation that names the tested OS/version, architecture, Wireshark version, source SHA, image digest, and bridge binary hash.
