package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func lifecycleFixture(t *testing.T) (string, VerifiedBundle, processRecord) {
	t.Helper()
	dir := t.TempDir()
	dir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	helper := filepath.Join(dir, "llama-server")
	if err := os.WriteFile(helper, []byte("fixed-helper"), 0700); err != nil {
		t.Fatal(err)
	}
	hash, err := hashFile(helper)
	if err != nil {
		t.Fatal(err)
	}
	bundle := VerifiedBundle{helperPath: helper, helperHash: hash, modelPath: filepath.Join(dir, "model"), modelID: modelIdentity}
	record := processRecord{PID: 4321, ProcessStart: "123:456", Executable: helper, ExecutableSHA256: hash, Model: modelIdentity}
	data, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(dir, "process.json"), append(data, '\n'), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "api-key"), []byte(strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	return dir, bundle, record
}

func TestStatusReceiptIsBoundedVerifiedAndSecretFree(t *testing.T) {
	dir, bundle, record := lifecycleFixture(t)
	result := statusWith(dir, bundle, func(int) (processIdentity, error) {
		return processIdentity{record.ProcessStart, record.Executable}, nil
	})
	if result.state != "running" {
		t.Fatalf("status: %#v", result)
	}
	var out bytes.Buffer
	if err := writeResult(&out, result); err != nil {
		t.Fatal(err)
	}
	if out.Len() > 1024 || strings.Contains(out.String(), strings.Repeat("a", 64)) || strings.Contains(out.String(), "api-key") {
		t.Fatalf("unsafe receipt: %q", out.String())
	}
	if !strings.Contains(out.String(), `"pid":4321`) || !strings.Contains(out.String(), record.ExecutableSHA256) {
		t.Fatalf("identity missing: %q", out.String())
	}
}

func TestStatusRejectsSymlinkMalformedAndChangedIdentityWithoutSignaling(t *testing.T) {
	dir, bundle, record := lifecycleFixture(t)
	calls := 0
	identify := func(int) (processIdentity, error) {
		calls++
		return processIdentity{record.ProcessStart, record.Executable}, nil
	}
	if err := os.Remove(filepath.Join(dir, "process.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "api-key"), filepath.Join(dir, "process.json")); err != nil {
		t.Fatal(err)
	}
	if got := statusWith(dir, bundle, identify); got.state != "unavailable" || calls != 0 {
		t.Fatalf("symlink accepted: %#v", got)
	}
	if err := os.Remove(filepath.Join(dir, "process.json")); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "process.json"), bytes.Repeat([]byte("x"), 2048), 0600); err != nil {
		t.Fatal(err)
	}
	if got := statusWith(dir, bundle, identify); got.state != "unavailable" || calls != 0 {
		t.Fatalf("oversize accepted: %#v", got)
	}
	data, _ := json.Marshal(record)
	_ = os.WriteFile(filepath.Join(dir, "process.json"), data, 0600)
	if got := statusWith(dir, bundle, func(int) (processIdentity, error) { return processIdentity{"123:999", record.Executable}, nil }); got.reason != "identity_mismatch" {
		t.Fatalf("reused PID accepted: %#v", got)
	}
	_ = os.WriteFile(bundle.helperPath, []byte("replacement"), 0700)
	if got := statusWith(dir, bundle, identify); got.state != "unavailable" {
		t.Fatalf("changed helper accepted: %#v", got)
	}
}

func TestStopOnlyCleansAfterConfirmedExitAndIsIdempotent(t *testing.T) {
	dir, bundle, record := lifecycleFixture(t)
	live := func(int) (processIdentity, error) {
		return processIdentity{record.ProcessStart, record.Executable}, nil
	}
	if got := stopWith(dir, bundle, live); got.state != "unavailable" {
		t.Fatalf("live cleanup: %#v", got)
	}
	for _, name := range []string{"process.json", "api-key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err != nil {
			t.Fatalf("%s removed while live", name)
		}
	}
	mismatch := func(int) (processIdentity, error) { return processIdentity{"changed", record.Executable}, nil }
	if got := stopWith(dir, bundle, mismatch); got.state != "unavailable" {
		t.Fatalf("mismatch cleanup: %#v", got)
	}
	missing := func(int) (processIdentity, error) { return processIdentity{}, errProcessMissing }
	if got := stopWith(dir, bundle, missing); got.state != "stopped" {
		t.Fatalf("exit cleanup: %#v", got)
	}
	for _, name := range []string{"process.json", "api-key"} {
		if _, err := os.Stat(filepath.Join(dir, name)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("%s remains: %v", name, err)
		}
	}
	if got := stopWith(dir, bundle, missing); got.state != "stopped" {
		t.Fatalf("repeat cleanup: %#v", got)
	}
}

func TestStopPreservesLifecycleStateWhenKeyCleanupIsUnsafe(t *testing.T) {
	dir, bundle, _ := lifecycleFixture(t)
	key := filepath.Join(dir, "api-key")
	if err := os.Remove(key); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "process.json"), key); err != nil {
		t.Fatal(err)
	}
	result := stopWith(dir, bundle, func(int) (processIdentity, error) { return processIdentity{}, errProcessMissing })
	if result.state != "unavailable" || result.reason != "state_unavailable" {
		t.Fatalf("unsafe cleanup: %#v", result)
	}
	if _, err := os.Lstat(filepath.Join(dir, "process.json")); err != nil {
		t.Fatalf("state removed: %v", err)
	}
}

func TestStatusDistinguishesMissingFromUnverifiableProcess(t *testing.T) {
	dir, bundle, _ := lifecycleFixture(t)
	missing := statusWith(dir, bundle, func(int) (processIdentity, error) { return processIdentity{}, errProcessMissing })
	if missing.reason != "process_missing" {
		t.Fatalf("missing: %#v", missing)
	}
	denied := statusWith(dir, bundle, func(int) (processIdentity, error) { return processIdentity{}, errProcessIdentity })
	if denied.reason != "state_unavailable" {
		t.Fatalf("unverifiable: %#v", denied)
	}
}

func TestStopRetriesAfterKeyRemovalAndProcessRecordRemovalFailure(t *testing.T) {
	dir, bundle, _ := lifecycleFixture(t)
	missing := func(int) (processIdentity, error) { return processIdentity{}, errProcessMissing }
	processPath := filepath.Join(dir, "process.json")
	failed := false
	first := stopWithRemove(dir, bundle, missing, func(path string) error {
		if path == processPath && !failed {
			failed = true
			return errors.New("injected process record removal failure")
		}
		return os.Remove(path)
	})
	if first.state != "unavailable" || first.reason != "state_unavailable" {
		t.Fatalf("first cleanup: %#v", first)
	}
	if _, err := os.Lstat(filepath.Join(dir, "api-key")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("key not removed: %v", err)
	}
	if _, err := os.Lstat(processPath); err != nil {
		t.Fatalf("process record lost: %v", err)
	}
	if got := stopWith(dir, bundle, missing); got.state != "stopped" {
		t.Fatalf("retry cleanup: %#v", got)
	}
	if _, err := os.Lstat(processPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("process record remains: %v", err)
	}
}

func TestPrivateRecordRejectsRegularReplacementBetweenLstatAndOpen(t *testing.T) {
	dir, _, _ := lifecycleFixture(t)
	path := filepath.Join(dir, "process.json")
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.json")
	if err := os.WriteFile(replacement, original, 0600); err != nil {
		t.Fatal(err)
	}
	_, err = readPrivateRecordWithOpen(dir, func(name string) (*os.File, error) {
		if err := os.Rename(replacement, name); err != nil {
			return nil, err
		}
		return os.Open(name)
	})
	if !errors.Is(err, errKeyState) {
		t.Fatalf("regular replacement accepted: %v", err)
	}
}

func TestExecutableMismatchRejectsStatusAndCleanup(t *testing.T) {
	for _, kind := range []string{"stored", "observed"} {
		t.Run(kind, func(t *testing.T) {
			dir, bundle, record := lifecycleFixture(t)
			current := processIdentity{started: record.ProcessStart, executable: record.Executable}
			if kind == "stored" {
				record.Executable = filepath.Join(dir, "other-helper")
				data, _ := json.Marshal(record)
				if err := os.WriteFile(filepath.Join(dir, "process.json"), data, 0600); err != nil {
					t.Fatal(err)
				}
			} else {
				current.executable = filepath.Join(dir, "other-helper")
			}
			identify := func(int) (processIdentity, error) { return current, nil }
			if got := statusWith(dir, bundle, identify); got.reason != "identity_mismatch" {
				t.Fatalf("status accepted mismatch: %#v", got)
			}
			if got := stopWith(dir, bundle, identify); got.reason != "identity_mismatch" {
				t.Fatalf("stop accepted mismatch: %#v", got)
			}
			for _, name := range []string{"api-key", "process.json"} {
				if _, err := os.Lstat(filepath.Join(dir, name)); err != nil {
					t.Fatalf("%s removed: %v", name, err)
				}
			}
		})
	}
}

func TestStatusAndStopLeaveLiveSignalSentinelRunning(t *testing.T) {
	dir, bundle, record := lifecycleFixture(t)
	child := exec.Command("/bin/sleep", "10")
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	exited := make(chan error, 1)
	go func() { exited <- child.Wait() }()
	exitConsumed := false
	defer func() {
		_ = child.Process.Signal(syscall.SIGKILL)
		if !exitConsumed {
			<-exited
		}
	}()
	record.PID = child.Process.Pid
	data, _ := json.Marshal(record)
	if err := os.WriteFile(filepath.Join(dir, "process.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	identify := func(int) (processIdentity, error) {
		return processIdentity{started: record.ProcessStart, executable: record.Executable}, nil
	}
	if got := statusWith(dir, bundle, identify); got.state != "running" {
		t.Fatalf("status: %#v", got)
	}
	if got := stopWith(dir, bundle, identify); got.state != "unavailable" {
		t.Fatalf("live stop: %#v", got)
	}
	select {
	case err := <-exited:
		exitConsumed = true
		t.Fatalf("status/stop signaled sentinel: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
}

func TestStopPreservesStateReplacedAfterAbsenceCheck(t *testing.T) {
	for _, kind := range []string{"new_live_record", "identical_replacement"} {
		t.Run(kind, func(t *testing.T) {
			dir, bundle, old := lifecycleFixture(t)
			path := filepath.Join(dir, "process.json")
			replacement := old
			if kind == "new_live_record" {
				replacement.PID = 5432
				replacement.ProcessStart = "987:654"
			}
			data, _ := json.Marshal(replacement)
			identify := func(pid int) (processIdentity, error) {
				if pid != old.PID {
					return processIdentity{started: replacement.ProcessStart, executable: replacement.Executable}, nil
				}
				tmp := filepath.Join(dir, "replacement.json")
				if err := os.WriteFile(tmp, data, 0600); err != nil {
					t.Fatal(err)
				}
				if err := os.Rename(tmp, path); err != nil {
					t.Fatal(err)
				}
				return processIdentity{}, errProcessMissing
			}
			got := stopWith(dir, bundle, identify)
			if got.state != "unavailable" || got.reason != "state_unavailable" {
				t.Fatalf("replaced state cleaned: %#v", got)
			}
			if _, err := os.Lstat(filepath.Join(dir, "api-key")); err != nil {
				t.Fatalf("key removed: %v", err)
			}
			stored, err := readPrivateRecord(dir)
			if err != nil || stored != replacement {
				t.Fatalf("replacement lost: %#v (%v)", stored, err)
			}
		})
	}
}
