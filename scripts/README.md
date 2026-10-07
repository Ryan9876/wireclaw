# Scripts

Repository automation and developer/release scripts will live here.

Rules:
- scripts must not become an alternate implementation path around the API/analyzer safety model
- release/startup scripts must preserve loopback-only defaults
- secrets must not be embedded in scripts
- platform-specific user launchers belong here or under release packaging when implemented in Gate 8
