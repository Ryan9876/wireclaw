# Task 1 implementation report

## Status

Complete. Implemented and committed the app bundle layout and exact entitlement contract for Task 1.

## Changes

- Added `ai/macos/Info.plist` with fixed identifier `com.wireclaw.WireclawAI`, executable `WireclawAI`, and headless app metadata.
- Added exact parent and inherited-helper entitlement templates. Parent grants only App Sandbox and network server; helper grants only App Sandbox and inheritance.
- Added `scripts/build_macos_ai_app.py` to assemble the fixed executable, helper, nested runtime code, and model/manifests into `WireclawAI.app`. Resources are read-only in the generated staging bundle. Signing remains a later packaging responsibility.
- Added focused tests for layout, bundle identity, exact entitlement sets, and rejection of network-client, filesystem, user-selected-file, and other extra entitlements.

## Validation

- RED confirmed before implementation: the focused test could not load the missing builder module.
- `.venv/bin/pytest tests/packaging/test_macos_ai_bundle.py -q` — 10 passed.
- `plutil -lint` on all three plist templates — all OK.
- `git diff --check` — clean.

## Self-review and limits

The builder emits an unsigned staging bundle; it does not sign code or inspect signed entitlements. Those actions are assigned to later signing and native qualification tasks. The bundle identifier is fixed here as `com.wireclaw.WireclawAI`, since the approved design and plan require a fixed identifier but do not spell out its string value.

## Commit

`build: define sandboxed WireclawAI app bundle`

## Review fix: require model and manifests

Added pre-assembly checks for `Resources/ai/model.gguf`, `Resources/ai/runtime-manifest.json`, and `Resources/ai/model-manifest.json`. Missing or symlinked inputs now raise `ValueError` before the staging bundle is created or replaced. Added one parameterized regression case for each required file and asserted no bundle is left behind.

RED command: `.venv/bin/pytest tests/packaging/test_macos_ai_bundle.py -q` — 3 failed (the assembler did not raise for each absent model/manifest); 10 passed.

Passing validation:

- `.venv/bin/pytest tests/packaging/test_macos_ai_bundle.py -q` — 13 passed in 0.05s.
- `plutil -lint ai/macos/Info.plist ai/macos/parent.entitlements.plist ai/macos/helper.entitlements.plist` — all three `OK`.
- `git diff --check` — clean.
