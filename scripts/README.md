# Scripts

Repository automation and developer/release scripts will live here.

Rules:
- scripts must not become an alternate implementation path around the API/analyzer safety model
- release/startup scripts must preserve loopback-only defaults
- secrets must not be embedded in scripts
- platform-specific user launchers belong here or under release packaging when implemented in Gate 8

## Gate 9 candidate freeze

`python scripts/gate9_freeze.py OUTPUT_DIRECTORY` requires a clean committed
source tree and an available macOS arm64 Docker release environment. It calls
the accepted `package_release.py`, writes `gate9-candidate.tar` beside the
staged `wireclaw-release` directory, and records that archive's SHA-256 and
size in `wireclaw-release/gate9-candidate-metadata.json`. The archive contains
the staged source, packaged image archive, image identity, and native bridge.
Keep the sidecar metadata with the archive; it identifies the exact archive
hash without recursively embedding its own hash.
