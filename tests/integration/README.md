# Integration Tests

Integration tests cover component boundaries such as:
- API to analyzer
- artifact registry and filesystem confinement
- SQLite persistence/migrations
- evidence capture generation
- model-provider fallback
- host-bridge request/response planning without requiring GUI automation

Use temporary isolated data roots. Tests must not rely on a developer's personal captures, Wireshark configuration, or model credentials.
