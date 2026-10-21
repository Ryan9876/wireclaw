# WireclawAI bundle verification

The wrapper requires macOS with CGO enabled to call Security.framework. Builds
without that binding fail verification and cannot authorize helper execution.
The production entry point derives `WireclawAI.app` from its own executable;
there is no command or environment override for bundle, runtime, or model paths.

`verifyBundle()` returns a `VerifiedBundle` only after checking the app signature,
the running wrapper's code identity, exact parent/helper entitlements, nested
code signatures and identifiers, pinned manifests, policy, hashes, sizes, and
the complete bundle file inventory. The start boundary consumes and closes fd 3
before verification, then writes the private key only after verification succeeds.
Helper launch accepts the verified value and the private key-file path.

## Manifest and packaging interface

`scripts/build_embedded_ai.py:prepare_app_resources(ai_root, resources_dir)`
validates existing staged source assets and creates input resources for the app
assembler. It leaves source manifests unchanged and adds
`"bundle_identifier": "com.wireclaw.WireclawAI"` to each copied manifest.

Manifest paths retain their pinned source identities. Verification maps only:

| Manifest path | Bundle path under Contents |
| --- | --- |
| `macos-arm64/llama-server` | `MacOS/llama-server` |
| `macos-arm64/lib*.dylib` | `Frameworks/` with the same basename |
| `models/qwen3-4b-instruct-2507-q4_k_m.gguf` | `Resources/ai/model.gguf` |
| Fixed model/runtime license paths | `Resources/ai/licenses/` |

The runtime must include `libggml-metal.dylib`. Library names accept ASCII
letters, digits, underscores, hyphens, and numeric version suffixes. Symlinks,
alternate paths, extra files, and executable data resources are rejected.
Manifests are limited to 1 MiB each, runtime records to 128 files of at most
512 MiB each, and the model to the existing 3,758,096,384-byte cap. These limits
bound verification reads without loading the model into memory.

The signing pipeline must use these signing identifiers:

- App: `com.wireclaw.WireclawAI`.
- Helper: `llama-server`.
- Each nested library: its exact filename, including any version suffix.

After relocating and signing nested code, the signing pipeline must update
`files[].sha256` and `files[].size_bytes` in the app's copied runtime manifest
from the final signed bytes at the mapped locations. It must preserve the pinned
source paths, provenance, policy, model manifest, and external source manifests.
It then signs the enclosing app, sealing the updated manifests and model. This
post-sign hash update and the complete release signing pipeline are separate
from resource preparation. Reusing pre-sign runtime hashes fails verification.

## Validation scope

Go tests include a disposable ad-hoc signed app that verifies itself through
Security.framework. They cover valid code, tampered resources/helper/library,
wrong app identity, excess entitlements, and signed-but-invalid hashes/policy.
Run macOS tests outside an enclosing tool sandbox so the app can initialize its
own App Sandbox. Native tests compile only fixture code and never launch the
fixture inference helper.

Ad-hoc signatures support development tests only. These checks do not establish
Developer ID trust, Hardened Runtime release acceptance, or notarization. The
release pipeline and native qualification must establish those properties.
The verifier checks the files before execution; it does not claim atomic
filesystem protection against a separate process concurrently rewriting the
installed bundle.
