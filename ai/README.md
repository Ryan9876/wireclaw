# Embedded AI release inputs

`embedded-ai.lock.json` pins the model source, llama.cpp source, and runtime policy. The Qwen source snapshot, converted GGUF, compiled native runtime, staged manifests, and release bundle are generated release assets. Keep them outside tracked source paths; the release builder verifies their identities and hashes before packaging.

Normal Wireclaw startup consumes already staged assets and never fetches a model or runtime. Run `scripts/build_embedded_ai.py` only as release engineering on macOS arm64 with the pinned build tools available.
