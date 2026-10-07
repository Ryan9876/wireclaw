# Wireshark Integration Design

Wireshark is both a validation surface and an escalation path. Wireclaw does not attempt to replace it.

## Required user actions

For every applicable packet-level finding, always show both:

1. **Open Full Capture in Wireshark**
2. **Open Evidence Capture in Wireshark**

Also show:
- Copy Display Filter
- Show Packet Evidence

Both open actions remain simultaneously visible; Wireclaw does not remember one as a preferred replacement for the other.

## Full capture

Purpose:
- preserve complete surrounding context
- let an engineer independently validate the finding

Behavior:
- open the immutable original PCAP/PCAPNG
- apply the finding's validated display filter where supported

## Evidence capture

Purpose:
- provide a small focused artifact for quick review/sharing/escalation

Possible extraction scopes:
- full TCP stream
- 5-tuple conversation
- DNS transaction set
- bounded time window around anomaly
- explicit frame set plus required protocol context

Evidence artifacts must record provenance:
- parent capture SHA-256
- related case/finding/evidence IDs
- extraction mode/rule
- display filter
- creation time

## Bridge protocol concept

The browser should not send an arbitrary filesystem path or executable command.

Preferred request shape:

```json
{
  "case_id": "case_...",
  "artifact_id": "artifact_...",
  "display_filter": "tcp.stream == 37"
}
```

The host bridge:

1. authenticates the local request
2. validates request schema/filter bounds
3. resolves artifact ID to a canonical path below configured Wireclaw data root
4. verifies file exists and is an approved capture artifact
5. resolves configured Wireshark executable
6. launches Wireshark with direct argument passing

Conceptual process arguments:

```text
<wireshark executable>
-r
<canonical capture path>
-Y
<display filter>
```

No shell is involved.

## Platform behavior

### macOS

Target native application path can be discovered/configured, then the actual executable launched with direct arguments.

### Windows

Resolve configured/common Wireshark executable location. Use native process creation with separate argument values.

### Linux

Resolve configured Wireshark executable path/PATH candidate, validate it, and launch in the user's graphical session.

## Unavailable bridge

If the bridge is not installed/running:
- do not hide the two actions
- render them disabled/unavailable with a clear reason
- keep Copy Display Filter available
- permit evidence artifact generation
- provide the artifact location/export path through the local application as appropriate

## Filter safety

A Wireshark display filter is data, not shell code, but it still must be bounded/validated to protect bridge stability.

Controls:
- maximum length
- reject NUL/control characters
- filters generated primarily from Wireclaw's internal filter builder
- model-proposed filters must be parsed/validated by the application before use
- no model output is passed directly to process execution

## Example finding behavior

```text
Finding: Packet loss is materially affecting stream 37
Confidence: High

Evidence
- 31 retransmissions / 642 data packets (4.83%)
- duplicate ACK sequences precede most retransmissions
- RTT baseline ~24 ms

Filter
  tcp.stream == 37

[ Open Full Capture in Wireshark ]
[ Open Evidence Capture in Wireshark ]
[ Copy Display Filter ]
[ Show Packet Evidence ]
```
