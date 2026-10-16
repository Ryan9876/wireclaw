//go:build darwin && cgo

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// This opt-in test must run as its own native invocation outside the enclosing
// command sandbox. It uses an ad-hoc signed fixture, never release evidence.
func TestNativeTask6Lifecycle(t *testing.T) {
	if os.Getenv("WIRECLAW_NATIVE_TASK6") != "1" {
		t.Skip("opt-in native Task 6 probe")
	}
	stateDir, err := productionStateDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"api-key", "process.json"} {
		if _, err := os.Lstat(filepath.Join(stateDir, name)); err == nil {
			t.Skip("existing AI private state must not be disturbed")
		}
	}
	accountHome, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	receiptDir := filepath.Join(accountHome, "Library", "Application Support", "Wireclaw", "run")
	if err := os.MkdirAll(receiptDir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(receiptDir, 0700); err != nil {
		t.Fatal(err)
	}
	receipt := filepath.Join(receiptDir, "task6-native-probe-receipt.json")
	if _, err := os.Lstat(receipt); err == nil {
		t.Skip("native probe receipt already exists")
	}
	if err := os.WriteFile(receipt, []byte("probe\n"), 0600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(receipt)
	root, self := fixtureBundle(t)
	info, err := os.ReadFile("../Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Contents/Info.plist"), info, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(argv ...string) {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("%s: %v: %s", argv[0], err, out)
		}
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(self); err != nil {
		t.Fatal(err)
	}
	run(goTool, "build", "-o", self, ".")
	source := filepath.Join(filepath.Dir(root), "helper.c")
	// The inherited sandbox must deny both host-receipt operations. The helper
	// prints only denial booleans to its bounded sandbox-private diagnostic log.
	cSource := fmt.Sprintf(`#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
int main(void) {
 const char *p=%q;
 int a=open(p,O_RDONLY); int b=open(p,O_WRONLY);
 char output[1024]; snprintf(output,sizeof(output),"%%s/task6-denial.log",getenv("HOME"));
 FILE *log=fopen(output,"w"); if(log){fprintf(log,"HOST_RECEIPT_READ_DENIED=%%d WRITE_DENIED=%%d\n",a<0,b<0);fclose(log);}
 if(a>=0)close(a); if(b>=0)close(b);
 for(;;) pause();
}`, receipt)
	if err := os.WriteFile(source, []byte(cSource), 0600); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(root, "Contents/MacOS/llama-server")
	library := filepath.Join(root, "Contents/Frameworks/libggml-metal.dylib")
	if err := os.Remove(helper); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(library); err != nil {
		t.Fatal(err)
	}
	run("/usr/bin/clang", source, "-o", helper)
	if err := os.WriteFile(source, []byte("int wireclaw_fixture(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	run("/usr/bin/clang", "-dynamiclib", source, "-o", library)
	run("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "llama-server", "--entitlements", "../helper.entitlements.plist", helper)
	run("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "libggml-metal.dylib", library)
	mutateManifest(t, root, "runtime", func(v map[string]any) {
		for _, item := range v["files"].([]any) {
			r := item.(map[string]any)
			rel, _ := runtimeLocation(r["path"].(string))
			b, e := os.ReadFile(filepath.Join(root, "Contents", rel))
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(b)
			r["sha256"] = hex.EncodeToString(sum[:])
			r["size_bytes"] = len(b)
		}
	})
	run("/usr/bin/codesign", "--force", "--sign", "-", "--entitlements", "../parent.entitlements.plist", root)
	if _, err := verifyBundleAt(root, self, permitSignature); err != nil {
		t.Fatalf("fixture manifest verification: %v", err)
	}
	for _, target := range []struct{ path, role string }{{helper, "helper"}, {library, "library"}} {
		if err := verifyCodeSignature(target.path, target.role); err != nil {
			t.Fatalf("%s signature: %v", target.role, err)
		}
	}
	run("/usr/bin/codesign", "--verify", "--deep", "--strict", root)
	keyReader, keyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyWriter.Write([]byte(strings.Repeat("a", 64) + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = keyWriter.Close()
	start := exec.Command(self, "start")
	start.ExtraFiles = []*os.File{keyReader}
	startOutput, startErr := start.CombinedOutput()
	_ = keyReader.Close()
	if startErr != nil {
		t.Fatalf("signed start: %v: %s", startErr, startOutput)
	}
	var startResult map[string]any
	if err := json.Unmarshal(startOutput, &startResult); err != nil || startResult["state"] != "running" {
		t.Fatalf("start receipt: %s (%v)", startOutput, err)
	}
	helperPID := int(startResult["pid"].(float64))
	defer func() {
		if helperPID > 0 {
			_ = exec.Command("/bin/kill", "-TERM", fmt.Sprint(helperPID)).Run()
		}
	}()
	status := exec.Command(self, "status")
	statusOutput, err := status.CombinedOutput()
	if err != nil {
		t.Fatalf("fresh signed status: %v: %s", err, statusOutput)
	}
	if !bytes.Contains(statusOutput, []byte(`"state":"running"`)) {
		t.Fatalf("status receipt: %s", statusOutput)
	}
	stopLive := exec.Command(self, "stop")
	stopLiveOutput, err := stopLive.CombinedOutput()
	if err == nil || !bytes.Contains(stopLiveOutput, []byte(`"state":"unavailable"`)) {
		t.Fatalf("wrapper stop signaled or cleaned live helper: %v %s", err, stopLiveOutput)
	}
	if _, err := processIdentityForPID(helperPID); err != nil {
		t.Fatalf("helper lost after wrapper stop: %v", err)
	}
	logPath := filepath.Join(stateDir, "task6-denial.log")
	defer os.Remove(logPath)
	for attempt := 0; attempt < 30; attempt++ {
		b, _ := os.ReadFile(logPath)
		if bytes.Contains(b, []byte("HOST_RECEIPT_READ_DENIED=1 WRITE_DENIED=1")) {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	logData, _ := os.ReadFile(logPath)
	if !bytes.Contains(logData, []byte("HOST_RECEIPT_READ_DENIED=1 WRITE_DENIED=1")) {
		t.Fatalf("sandbox host-receipt denial absent: %s", logData)
	}
	if err := os.Remove(receipt); err != nil {
		t.Fatal(err)
	}
	hostTool := filepath.Join("..", "..", "..", "launch", "macos", "ai_lifecycle.py")
	create := exec.Command("/usr/bin/python3", hostTool, "create", receipt, helper)
	create.Stdin = bytes.NewReader(statusOutput)
	if out, err := create.CombinedOutput(); err != nil {
		t.Fatalf("host receipt create: %v: %s", err, out)
	}
	hostStop := exec.Command("/usr/bin/python3", hostTool, "stop", receipt, helper)
	if out, err := hostStop.CombinedOutput(); err != nil {
		t.Fatalf("verified host stop: %v: %s", err, out)
	}
	_, identityErr := processIdentityForPID(helperPID)
	t.Logf("host-observed helper after stop: %v", identityErr)
	afterStatus := exec.Command(self, "status")
	afterOutput, afterErr := afterStatus.CombinedOutput()
	t.Logf("fresh status after host stop: %v %s", afterErr, afterOutput)
	helperPID = 0
	cleanup := exec.Command(self, "stop")
	if out, err := cleanup.CombinedOutput(); err != nil || !bytes.Contains(out, []byte(`"state":"stopped"`)) {
		t.Fatalf("wrapper cleanup: %v: %s", err, out)
	}
	remove := exec.Command("/usr/bin/python3", hostTool, "remove", receipt, helper)
	if out, err := remove.CombinedOutput(); err != nil {
		t.Fatalf("host receipt removal: %v: %s", err, out)
	}
	for _, path := range []string{receipt, filepath.Join(stateDir, "api-key"), filepath.Join(stateDir, "process.json")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("state remains: %s: %v", path, err)
		}
	}
}
