# Web Application

This directory will contain the React + TypeScript localhost UI.

Responsibilities:
- capture selection/drop
- symptom input
- investigation progress
- result/finding presentation
- time-attribution visualization
- evidence inspection
- case deletion
- Wireshark action controls

Constraints:
- do not invoke analyzers directly
- do not call model providers directly
- do not construct shell commands
- do not accept arbitrary host paths for Wireshark launch
- every applicable packet-level finding must show both full-capture and evidence-capture Wireshark actions

Implementation begins at Gate 5 in `specs/v1/tasks.md`.
