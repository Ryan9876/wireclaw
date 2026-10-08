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
