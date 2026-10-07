# API / Orchestrator

This directory will contain the FastAPI local service and investigation orchestration.

Responsibilities:
- case lifecycle/state
- capture intake coordination
- artifact registry
- SQLite persistence
- analyzer capability authorization
- deterministic baseline workflow
- model-provider abstraction
- investigation-step limits
- finding validation against evidence IDs
- report assembly
- bridge launch-plan generation

Security boundary:
- bind to loopback by default
- accept logical artifact IDs instead of arbitrary filesystem paths
- never execute user/model text as a command
- never allow model adapters to invoke subprocesses directly

Implementation begins at Gate 3 in `specs/v1/tasks.md`.
