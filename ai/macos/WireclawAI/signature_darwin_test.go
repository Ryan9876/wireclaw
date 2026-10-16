//go:build darwin && cgo

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The copied test executable runs this probe under the real app signature and
// sandbox. It verifies only; it never starts the fixture helper.
func TestNativeVerificationProbe(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	if filepath.Base(self) != "WireclawAI" {
		t.Skip("signed app subprocess only")
	}
	_, err = verifyBundle()
	if err != nil {
		os.Exit(1)
	}
	os.Exit(0)
}

func TestNativeSecurityRejectsTamperedBundle(t *testing.T) {
	for _, mutation := range []string{"valid", "model", "helper", "library", "wrong identity", "extra entitlement", "resigned model", "resigned manifest"} {
		t.Run(mutation, func(t *testing.T) {
			root, self := fixtureBundle(t)
			run := func(argv ...string) {
				t.Helper()
				cmd := exec.Command(argv[0], argv[1:]...)
				if out, err := cmd.CombinedOutput(); err != nil {
					t.Fatalf("%s failed: %v: %s", argv[0], err, out)
				}
			}
			copyFile := func(source, target string) {
				t.Helper()
				b, err := os.ReadFile(source)
				if err != nil {
					t.Fatal(err)
				}
				_ = os.Chmod(target, 0700)
				if err = os.WriteFile(target, b, 0700); err != nil {
					t.Fatal(err)
				}
			}
			current, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			copyFile(current, self)
			info, err := os.ReadFile("../Info.plist")
			if err != nil {
				t.Fatal(err)
			}
			if mutation == "wrong identity" {
				info = []byte(strings.ReplaceAll(string(info), bundleID, "com.wireclaw.Other"))
			}
			if err = os.WriteFile(filepath.Join(root, "Contents/Info.plist"), info, 0600); err != nil {
				t.Fatal(err)
			}
			source := filepath.Join(filepath.Dir(root), "fixture.c")
			if err = os.WriteFile(source, []byte("int main(void) { return 0; }"), 0600); err != nil {
				t.Fatal(err)
			}
			helper := filepath.Join(root, "Contents/MacOS/llama-server")
			library := filepath.Join(root, "Contents/Frameworks/libggml-metal.dylib")
			_ = os.Chmod(helper, 0700)
			_ = os.Chmod(library, 0700)
			run("/usr/bin/clang", source, "-o", helper)
			run("/usr/bin/clang", "-dynamiclib", source, "-o", library)
			run("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "llama-server", "--entitlements", "../helper.entitlements.plist", helper)
			run("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "libggml-metal.dylib", library)
			mutateManifest(t, root, "runtime", func(v map[string]any) {
				for _, item := range v["files"].([]any) {
					r := item.(map[string]any)
					rel, _ := runtimeLocation(r["path"].(string))
					b, err := os.ReadFile(filepath.Join(root, "Contents", rel))
					if err != nil {
						t.Fatal(err)
					}
					hash := sha256.Sum256(b)
					r["sha256"] = hex.EncodeToString(hash[:])
					r["size_bytes"] = len(b)
				}
			})
			entitlements := "../parent.entitlements.plist"
			if mutation == "extra entitlement" {
				b, err := os.ReadFile(entitlements)
				if err != nil {
					t.Fatal(err)
				}
				b = []byte(strings.Replace(string(b), "</dict>", "<key>com.apple.security.network.client</key><true/></dict>", 1))
				entitlements = filepath.Join(filepath.Dir(root), "extra.plist")
				if err = os.WriteFile(entitlements, b, 0600); err != nil {
					t.Fatal(err)
				}
			}
			run("/usr/bin/codesign", "--force", "--sign", "-", "--entitlements", entitlements, root)
			switch mutation {
			case "model":
				replaceFixture(t, root, "Resources/ai/model.gguf", []byte("tampered"))
			case "helper":
				copyFile("/usr/bin/true", helper)
			case "library":
				replaceFixture(t, root, "Frameworks/libggml-metal.dylib", []byte("tampered"))
			}
			if mutation == "resigned model" {
				replaceFixture(t, root, "Resources/ai/model.gguf", []byte("tampered"))
				run("/usr/bin/codesign", "--force", "--sign", "-", "--entitlements", entitlements, root)
			}
			if mutation == "resigned manifest" {
				mutateManifest(t, root, "runtime", func(v map[string]any) { v["policy"].(map[string]any)["parallel"] = 2 })
				run("/usr/bin/codesign", "--force", "--sign", "-", "--entitlements", entitlements, root)
			}
			cmd := exec.Command(self, "-test.run=^TestNativeVerificationProbe$")
			out, err := cmd.CombinedOutput()
			if mutation == "valid" && err != nil {
				t.Fatalf("valid signed bundle rejected: %v: %s", err, out)
			}
			if mutation != "valid" && err == nil {
				t.Fatalf("tampered signed bundle accepted: %s", out)
			}
		})
	}
}
