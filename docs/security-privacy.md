# Security and Privacy Design

Wireclaw processes untrusted packet captures that may contain sensitive data. Security boundaries are part of the product design, not post-release hardening.

## Threat model

Assume a capture may contain:

- malformed protocol fields intended to trigger parser bugs
- very large packet counts or payloads
- adversarial text intended to manipulate a reasoning model
- credentials, cookies, tokens, personal data, internal hostnames, or URLs
- values that resemble filesystem paths or command-line fragments

Also assume a malicious local webpage/process may attempt to call the host bridge.

## Primary controls

### Analyzer execution

- use fixed executable allowlists
- invoke subprocesses without a shell
- use argument arrays
- enforce timeouts
- enforce output/result limits
- constrain reads/writes to approved case directories
- sanitize/normalize tool output before passing it upward

### Model boundary

Model output is untrusted.

The model may request only typed capabilities. The application validates all parameters before execution.

The model may propose hypotheses/findings only by referencing evidence IDs already present in case state. Unsupported claims are rejected or marked as unsupported, never silently promoted into facts.

### Prompt-injection resistance

Strings extracted from packet contents, DNS names, URLs, HTTP fields, certificates, and other capture material are data, not instructions.

When constructing model context:
- label capture-derived strings as untrusted data
- use structured JSON where possible
- do not concatenate capture text into system/developer instructions
- cap lengths and counts
- strip/control non-printable content where appropriate

### Raw data policy

Default cloud reasoning excludes:
- raw PCAP/PCAPNG bytes
- full packet payloads
- extracted secrets
- arbitrary file contents

Cloud requests should favor aggregated/normalized measurements.

### Logging

Do not log:
- packet payloads
- API keys
- bearer tokens
- cookies
- host-bridge secrets
- full prompts containing sensitive capture fields

Logs may contain case IDs, capability names, durations, statuses, safe numeric metrics, and bounded sanitized errors.

## Host bridge

The bridge is intentionally narrow.

Required properties:
- loopback bind only
- per-installation or per-session authentication token
- strict allowed origin policy where applicable
- request body schema validation
- logical artifact ID, not arbitrary caller path
- data-root path confinement after canonicalization
- configured Wireshark executable only
- direct process spawn, no shell
- bounded display-filter length
- reject NUL/control characters and malformed requests
- rate limiting sufficient to prevent launch storms

The bridge must never provide:
- arbitrary command execution
- arbitrary executable selection
- arbitrary filesystem browsing
- shell command passthrough

## Container security

Target posture:
- non-root application users where practical
- minimal images
- pinned dependencies in releases
- only required bind mounts
- application port published to `127.0.0.1` by default
- no Docker socket mount
- no privileged container
- no host networking requirement
- read-only mounts where feasible
- explicit writable case/work directories

## File handling

Original capture:
- hash on ingest
- preserve immutable copy
- never overwrite in place

Generated artifacts:
- use generated internal names
- keep beneath case directory
- store provenance to parent capture and extraction rule

Reject:
- absolute output paths from clients/models
- `..` traversal
- symlink escapes from managed roots

## Dependency risk

Wireshark/TShark and Zeek parse hostile binary input and therefore are security-sensitive dependencies.

Release process should:
- pin versions
- rebuild regularly for security updates
- record versions in cases
- maintain regression fixtures across upgrades
- avoid silently upgrading analyzer versions within a published release

## Security acceptance tests

At minimum:
- path traversal attempts
- shell metacharacters in symptom/capture-derived fields
- hostile display-filter strings
- malformed PCAP/PCAPNG
- oversized analyzer output
- analyzer timeout
- repeated model tool requests
- prompt-injection strings embedded in DNS/HTTP/TLS fields
- host-bridge request without/with invalid auth
- attempt to launch non-Wireshark executable
- attempt to escape configured data root
- attempt to send raw payload to cloud provider under default policy

## Privacy UX

The UI should clearly state:
- analysis runs locally
- whether a model provider is configured
- whether that provider is local or remote
- what class of information may be sent to it

Do not claim "nothing leaves your machine" when a cloud model is configured. Instead state precisely that raw captures remain local by default and normalized evidence may be sent to the configured provider.
