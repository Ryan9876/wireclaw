package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func fixtureBundle(t *testing.T) (string, string) {
	t.Helper()
	temp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	root := filepath.Join(temp, "WireclawAI.app")
	put := func(rel string, data []byte, mode os.FileMode) {
		t.Helper()
		p := filepath.Join(root, "Contents", rel)
		if err := os.MkdirAll(filepath.Dir(p), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, mode); err != nil {
			t.Fatal(err)
		}
	}
	put("MacOS/WireclawAI", []byte("wrapper"), 0500)
	put("MacOS/llama-server", []byte("helper"), 0500)
	put("Frameworks/libggml-metal.dylib", []byte("metal"), 0400)
	put("Resources/ai/model.gguf", []byte("model"), 0400)
	put("Resources/ai/licenses/Qwen-Apache-2.0.txt", []byte("Apache"), 0400)
	put("Resources/ai/licenses/llama.cpp-MIT.txt", []byte("MIT"), 0400)
	record := func(path, content string) map[string]any {
		h := sha256.Sum256([]byte(content))
		return map[string]any{"path": path, "size_bytes": len(content), "sha256": hex.EncodeToString(h[:])}
	}
	model := map[string]any{"schema_version": 1, "bundle_identifier": bundleID, "model_id": modelIdentity, "repository": "Qwen/Qwen3-4B-Instruct-2507", "revision": modelRevision, "license": "Apache-2.0", "quantization": "Q4_K_M", "architecture": "qwen3", "architecture_validation": map[string]any{"metadata_field": "general.architecture", "reader": "gguf-py from pinned llama.cpp source"}, "artifact": record(modelArtifact, "model"), "source_files": []any{record("config.json", "source")}, "license_path": "licenses/Qwen-Apache-2.0.txt"}
	runtime := map[string]any{"schema_version": 1, "bundle_identifier": bundleID, "repository": "ggml-org/llama.cpp", "revision": runtimeRevision, "tag": "v0.6.0", "tag_commit": runtimeTagRevision, "platform": "macos", "architecture": "arm64", "build_settings": map[string]any{"metal": true, "server": true, "cmake_version": "cmake fixture"}, "entrypoint": "macos-arm64/llama-server", "files": []any{record("macos-arm64/llama-server", "helper"), record("macos-arm64/libggml-metal.dylib", "metal")}, "license_paths": []string{"licenses/llama.cpp-MIT.txt"}, "policy": json.RawMessage(pinnedPolicy)}
	for name, v := range map[string]any{"model": model, "runtime": runtime} {
		data, _ := json.Marshal(v)
		put("Resources/ai/"+name+"-manifest.json", data, 0400)
	}
	return root, filepath.Join(root, "Contents/MacOS/WireclawAI")
}

func mutateManifest(t *testing.T, root, name string, mutate func(map[string]any)) {
	t.Helper()
	p := filepath.Join(root, "Contents/Resources/ai/"+name+"-manifest.json")
	data, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err = json.Unmarshal(data, &v); err != nil {
		t.Fatal(err)
	}
	mutate(v)
	data, _ = json.Marshal(v)
	if err = os.Chmod(p, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(p, data, 0600); err != nil {
		t.Fatal(err)
	}
}
func permitSignature(string, string) error { return nil }

func TestVerifyBundleFixedPaths(t *testing.T) {
	root, self := fixtureBundle(t)
	var calls []string
	bundle, err := verifyBundleAt(root, self, func(path, role string) error { calls = append(calls, role); return nil })
	if err != nil {
		t.Fatal(err)
	}
	if bundle.helperPath != filepath.Join(root, "Contents/MacOS/llama-server") || bundle.modelPath != filepath.Join(root, "Contents/Resources/ai/model.gguf") || bundle.modelID != modelIdentity {
		t.Fatal("paths are not fixed")
	}
	if strings.Join(calls, ",") != "app,helper,library" {
		t.Fatalf("signature checks: %v", calls)
	}
}

func TestVerifyBundleRejectsInvalidAssets(t *testing.T) {
	cases := []struct {
		name   string
		change func(*testing.T, string, *string)
	}{
		{"model identity", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "model", func(v map[string]any) { v["model_id"] = "other" })
		}},
		{"bundle identity", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "runtime", func(v map[string]any) { v["bundle_identifier"] = "other" })
		}},
		{"schema", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "model", func(v map[string]any) { v["schema_version"] = 2 })
		}},
		{"policy", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "runtime", func(v map[string]any) { v["policy"].(map[string]any)["parallel"] = 2 })
		}},
		{"runtime revision", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "runtime", func(v map[string]any) { v["revision"] = "other" })
		}},
		{"helper substitution", func(t *testing.T, r string, _ *string) { replaceFixture(t, r, "MacOS/llama-server", []byte("attack")) }},
		{"model substitution", func(t *testing.T, r string, _ *string) {
			replaceFixture(t, r, "Resources/ai/model.gguf", []byte("attack"))
		}},
		{"library substitution", func(t *testing.T, r string, _ *string) {
			replaceFixture(t, r, "Frameworks/libggml-metal.dylib", []byte("attack"))
		}},
		{"hash", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "model", func(v map[string]any) { v["artifact"].(map[string]any)["sha256"] = strings.Repeat("0", 64) })
		}},
		{"size", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "model", func(v map[string]any) { v["artifact"].(map[string]any)["size_bytes"] = 1 })
		}},
		{"model path", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "model", func(v map[string]any) { v["artifact"].(map[string]any)["path"] = "../../outside" })
		}},
		{"source provenance path", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "model", func(v map[string]any) { v["source_files"].([]any)[0].(map[string]any)["path"] = ".." })
		}},
		{"runtime path", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "runtime", func(v map[string]any) { v["files"].([]any)[1].(map[string]any)["path"] = "macos-arm64/../outside" })
		}},
		{"unmanifested library", func(t *testing.T, r string, _ *string) {
			replaceFixture(t, r, "Frameworks/libextra.dylib", []byte("extra"))
		}},
		{"unmanifested executable", func(t *testing.T, r string, _ *string) {
			p := filepath.Join(r, "Contents/Resources/evil")
			if err := os.WriteFile(p, []byte("evil"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"duplicate record", func(t *testing.T, r string, _ *string) {
			mutateManifest(t, r, "runtime", func(v map[string]any) { v["files"] = append(v["files"].([]any), v["files"].([]any)[0]) })
		}},
		{"symlink", func(t *testing.T, r string, _ *string) {
			p := filepath.Join(r, "Contents/Resources/ai/model.gguf")
			if err := os.Remove(p); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink("/etc/passwd", p); err != nil {
				t.Fatal(err)
			}
		}},
		{"executable outside Contents", func(t *testing.T, r string, _ *string) {
			if err := os.WriteFile(filepath.Join(r, "extra"), []byte("code"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"executable data resource", func(t *testing.T, r string, _ *string) {
			if err := os.Chmod(filepath.Join(r, "Contents/Resources/ai/model.gguf"), 0700); err != nil {
				t.Fatal(err)
			}
		}},
		{"wrong self", func(_ *testing.T, r string, self *string) { *self = filepath.Join(r, "Contents/MacOS/other") }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			root, self := fixtureBundle(t)
			c.change(t, root, &self)
			if _, err := verifyBundleAt(root, self, permitSignature); err == nil {
				t.Fatal("accepted invalid bundle")
			}
			launched := false
			result := startVerified(io.NopCloser(strings.NewReader(strings.Repeat("a", 64)+"\n")), filepath.Join(root, "unused-state"), func() (VerifiedBundle, error) {
				return verifyBundleAt(root, self, permitSignature)
			}, func(VerifiedBundle, string) commandResult {
				launched = true
				return commandResult{"running", ""}
			})
			if launched || result.reason != "verification_failed" {
				t.Fatal("invalid bundle reached launch")
			}
		})
	}
}
func replaceFixture(t *testing.T, root, rel string, b []byte) {
	t.Helper()
	p := filepath.Join(root, "Contents", rel)
	_ = os.Chmod(p, 0600)
	if err := os.WriteFile(p, b, 0600); err != nil {
		t.Fatal(err)
	}
}

func TestSignatureFailureStopsVerification(t *testing.T) {
	for _, bad := range []string{"app", "helper", "library"} {
		t.Run(bad, func(t *testing.T) {
			root, self := fixtureBundle(t)
			_, err := verifyBundleAt(root, self, func(_, role string) error {
				if role == bad {
					return errors.New("invalid signature")
				}
				return nil
			})
			if err == nil {
				t.Fatal("accepted bad signature")
			}
		})
	}
}
func TestStartVerifiesBeforePersistingKeyOrLaunching(t *testing.T) {
	root, self := fixtureBundle(t)
	temp, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(temp, "state")
	closed := false
	launched := false
	fd := &closeReader{Reader: bytes.NewBufferString(strings.Repeat("a", 64) + "\n"), closed: &closed}
	verify := func() (VerifiedBundle, error) {
		if !closed {
			t.Fatal("fd still open")
		}
		if _, err := os.Stat(dir); !os.IsNotExist(err) {
			t.Fatal("state written before verification")
		}
		return verifyBundleAt(root, self, permitSignature)
	}
	launch := func(bundle VerifiedBundle, keyPath string) commandResult {
		launched = true
		if bundle.helperPath == "" {
			t.Fatal("unverified path")
		}
		if _, err := os.Stat(keyPath); err != nil {
			t.Fatal(err)
		}
		return commandResult{"unavailable", "launch_failed"}
	}
	result := startVerified(fd, dir, verify, launch)
	if !launched || result.reason != "launch_failed" {
		t.Fatal(result)
	}
	launched = false
	fd = &closeReader{Reader: bytes.NewBufferString(strings.Repeat("a", 64) + "\n"), closed: &closed}
	result = startVerified(fd, dir, func() (VerifiedBundle, error) { return VerifiedBundle{}, errBundleVerification }, launch)
	if launched || result.reason != "verification_failed" {
		t.Fatal("launch occurred before verification")
	}
}

type closeReader struct {
	io.Reader
	closed *bool
}

func (r *closeReader) Close() error { *r.closed = true; return nil }
