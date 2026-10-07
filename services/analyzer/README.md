# Deterministic Analyzer

This directory will contain Python wrappers and derivations for packet-analysis capabilities.

Initial tools:
- TShark
- capinfos
- editcap
- mergecap where needed
- Zeek

Responsibilities:
- safe subprocess execution without a shell
- tool-version discovery
- capture validation/quality assessment
- endpoint/protocol/conversation inventory
- DNS/TCP/TLS analysis
- timing and transport calculations
- normalized evidence generation
- evidence-capture extraction

Constraints:
- all capabilities are named and typed
- executable names/flags are controlled by code
- user/model input is validated as data parameters only
- resource/time/result limits are enforced
- original captures are never modified

Implementation begins at Gate 1 in `specs/v1/tasks.md`.
