# Gate 1 normalized golden evidence

Eleven JSON files hold the complete semantic evidence for accepted generated fixtures.
`tests/integration/test_baseline.py` compares every value, stable ID, scope, summary,
limitation, calculation and capability/tool name, while excluding only host-specific
tool version fields. Tool versions remain required in the actual evidence and case
record. Reference toolchain: TShark/capinfos 4.2.2; fixture format revision 1.

Tests separately assert independently known frame/byte/duration/protocol counts,
quality flags and frame references so the analyzer is not its own sole oracle.
There are no generated timestamps, temporary paths or random identifiers in goldens.

Do not automatically regenerate goldens when tests fail. Review differences against
fixture construction and recorded analyzer versions. Analyzer upgrades require
explicit review of semantic changes. Malformed inputs have rejection assertions,
not successful-evidence golden files.

PR #1 review follow-up preserves nine original goldens byte-for-byte. Only the
truncated conversation inventory gains its previously missing network-protocol
discriminator, and the mixed-protocol regression adds a new golden. TCP/UDP values
and all original capture-quality values remain unchanged.

## Gate 2

`gate2/` contains twenty-nine complete semantic diagnostic goldens from the
standard-library Gate 2 generator, using actual TShark/capinfos 4.2.2. They are
checked by `tests/integration/test_gate2.py`, excluding only source tool version
strings while retaining capability, tool, IDs, scopes, all values, formulas,
filters, frame references and limitations. Actual output remains schema-validated
and records versions. Fixture timestamps, sequence unions, expert event frames,
byte counts and causal ambiguity are separately asserted before goldens are accepted.

The eleven Gate 1 goldens remain byte-for-byte unchanged. Analyzer provenance is
now 0.2.0; the baseline envelope version expectation changed deliberately, not its
semantic evidence. These are evidence goldens, not RCA/final-report goldens.


The engine completion deliberately adds DNS per-capture identities and sequence groups,
DNS filters and supporting frames excluding ICMP quotes, TCP expert fractions with explicit denominator, and
observed reset/reconnect references. A structural comparison against the earlier draft
confirmed every other value in its fifteen goldens unchanged before accepting updates.
Eight additional goldens have separate independent frame/timing/identity assertions.
All eleven Gate 1 goldens remain byte-for-byte unchanged against main.

The independent PR #3 review remediation changes only DNS/reset/network limitations,
exact capture-level references and generated filters, IPv4 fragment identification,
and the first minimum-size frame in PMTUD patterns. Capture-level not-observable
TCP records now have no unrelated packet references. The existing 23 Gate 2
goldens were compared structurally to reviewed head `6518af6`; all other values
remain identical. Six new goldens cover DNS/nested isolation, outer ICMP fragments,
quoted fragments, PTB code validation and an independent same-service SYN after reset.
Separate real-tool tests assert these packet facts before golden comparison.
The eleven Gate 1 golden files remain byte-for-byte unchanged.
