# Native Host Bridge

This directory will contain the Go host bridge used for native integrations that cannot safely occur inside Docker.

V1 responsibility:
- launch native Wireshark with an approved Wireclaw capture artifact and validated display filter

Required behavior:
- loopback only when using HTTP
- authenticated requests
- logical case/artifact identifiers rather than arbitrary process commands
- canonical path resolution beneath configured Wireclaw data root
- configured Wireshark executable only
- direct process spawn with separate arguments
- no shell
- no general-purpose command execution
- equivalent behavior on macOS, Windows, and Linux

Implementation begins at Gate 6 in `specs/v1/tasks.md`.
