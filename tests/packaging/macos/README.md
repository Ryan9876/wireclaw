# Native App Sandbox qualification fixture

`ai/macos/WireclawAI/native_isolation_darwin_test.go` builds a disposable C
probe in a temporary signed `WireclawAI.app`, then starts it through the real
fd-3 wrapper launch path. It emits bounded fixed results and operation errno
values. Unified sandbox logs are supplemental; the current host account cannot
read the unified log store. A denial is classified only when the operation
returns `EPERM` or `EACCES` and the actual signed entitlements support that
classification. Ambiguous errors fail or remain inconclusive. The probe does
not communicate with `vmnetd`. It also checks the actual signed parent and
inherited-helper entitlement dictionaries.
The approved parent `network.server` entitlement remains a capability residual;
the probe verifies the actual helper listener stays on numeric loopback and
does not treat that signed entitlement as a test failure.
The two known Docker Desktop socket paths are checked independently. An
active socket must be denied; an absent or host-unreachable endpoint is
reported as `NOT_RUN`, not as a passing denial.
The denial probes cover the fixed Core API listener at `127.0.0.1:8767`, the
host bridge listener on `127.0.0.1:8766`, and an arbitrary documentation-range
destination. Compose continues to use `host.docker.internal:8767` to reach the
loopback-only runtime from Core; that name is not a host-side listener target.

Run on Apple Silicon outside the enclosing command sandbox with:

```sh
python3 scripts/qualify_macos_embedded_ai.py
```

The disposable helper binds only `127.0.0.1:8767` and accepts one bounded
fixture request. It does not run llama.cpp or access production model files.
On test failure, cleanup preserves the host receipt and unique fixture path
unless trusted recovery, identity-verified stop, wrapper cleanup, receipt
removal, and private-state cleanup all succeed. Before starting, the test skips
if any private-state output it would create or truncate already exists.
