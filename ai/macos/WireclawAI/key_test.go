package main

import (
	"bytes"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const testKey = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"

type observedReader struct {
	io.Reader
	closed bool
}

func (r *observedReader) Close() error { r.closed = true; return nil }

func TestKeyRecordAndDescriptorClosure(t *testing.T) {
	dir := t.TempDir()
	r := &observedReader{Reader: strings.NewReader(testKey + "\n")}
	path, err := bootstrapKey(r, dir)
	if err != nil || !r.closed {
		t.Fatalf("bootstrap failed or fd not closed: %v, %v", err, r.closed)
	}
	if path != filepath.Join(dir, "api-key") {
		t.Fatalf("unexpected private path: %q", path)
	}
	data, err := os.ReadFile(path)
	if err != nil || string(data) != testKey+"\n" {
		t.Fatalf("key file incorrect: %v", err)
	}
	if info, err := os.Stat(path); err != nil || info.Mode().Perm() != 0o600 {
		t.Fatalf("key file permissions incorrect: %v", err)
	}
	if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("private directory permissions incorrect: %v", err)
	}
}

func TestKeyRecordRejectsInvalidInput(t *testing.T) {
	for name, record := range map[string]string{
		"partial": testKey[:30], "missing_newline": testKey,
		"uppercase": "A" + testKey[1:] + "\n", "nonhex": "g" + testKey[1:] + "\n",
		"extra_byte": testKey + "\nx", "extra_record": testKey + "\n" + testKey + "\n",
		"too_long": strings.Repeat("a", 10000), "empty": "",
	} {
		t.Run(name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "private")
			r := &observedReader{Reader: strings.NewReader(record)}
			_, err := bootstrapKey(r, dir)
			if err == nil || !r.closed {
				t.Fatalf("invalid input accepted or fd left open: %v, %v", err, r.closed)
			}
			if strings.Contains(err.Error(), testKey) {
				t.Fatal("key leaked in error")
			}
			if _, err := os.Stat(filepath.Join(dir, "api-key")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("invalid record created key state")
			}
		})
	}
}

func TestKeyMissingFDAndWriteFailure(t *testing.T) {
	if _, err := bootstrapKey(nil, t.TempDir()); err == nil {
		t.Fatal("missing fd accepted")
	}
	r := &observedReader{Reader: strings.NewReader(testKey + "\n")}
	path := filepath.Join(t.TempDir(), "occupied")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := bootstrapKey(r, path); err == nil || !r.closed {
		t.Fatal("write failure accepted or fd left open")
	}
}

func TestPrivateStateLocation(t *testing.T) {
	home := filepath.Join(t.TempDir(), "user")
	want := filepath.Join(home, "Library", "Containers", "com.wireclaw.WireclawAI", "Data", "Library", "Application Support", "WireclawAI")
	if got := privateStateDir(home); got != want {
		t.Fatalf("private path = %q; want %q", got, want)
	}
	containerHome := filepath.Join(home, "Library", "Containers", bundleID, "Data")
	if got := privateStateDir(containerHome); got != want {
		t.Fatalf("container home private path = %q; want %q", got, want)
	}
}

func TestPublicResultNeverContainsKey(t *testing.T) {
	var out bytes.Buffer
	if err := writeResult(&out, commandResult{state: "unavailable", reason: testKey}); err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out.Bytes(), []byte(testKey)) {
		t.Fatal("key leaked to public output")
	}
}

func TestFD3BootstrapKeepsSentinelOutOfProcessSurfaces(t *testing.T) {
	if os.Getenv("WIRECLAW_TEST_FD3_CHILD") == "1" {
		if strings.Contains(strings.Join(os.Args, " "), testKey) || strings.Contains(strings.Join(os.Environ(), " "), testKey) {
			t.Fatal("key appeared in child arguments or environment")
		}
		fd := os.NewFile(3, "test-key-pipe")
		if _, err := bootstrapKey(fd, os.Getenv("WIRECLAW_TEST_PRIVATE_DIR")); err != nil {
			t.Fatal("bootstrap failed")
		}
		if _, err := fd.Stat(); err == nil {
			t.Fatal("fd 3 remained open after bootstrap")
		}
		return
	}
	readEnd, writeEnd, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(t.TempDir(), "private")
	cmd := exec.Command(os.Args[0], "-test.run=^TestFD3BootstrapKeepsSentinelOutOfProcessSurfaces$")
	cmd.ExtraFiles = []*os.File{readEnd}
	cmd.Env = append(os.Environ(), "WIRECLAW_TEST_FD3_CHILD=1", "WIRECLAW_TEST_PRIVATE_DIR="+dir)
	if _, err := writeEnd.Write([]byte(testKey + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = writeEnd.Close()
	output, err := cmd.CombinedOutput()
	_ = readEnd.Close()
	if err != nil {
		t.Fatalf("fd 3 child failed: %v; output: %s", err, output)
	}
	if bytes.Contains(output, []byte(testKey)) || bytes.Contains([]byte(strings.Join(cmd.Args, " ")), []byte(testKey)) || bytes.Contains([]byte(strings.Join(cmd.Env, " ")), []byte(testKey)) {
		t.Fatal("key appeared in argv, environment, stdout, or stderr")
	}
	if data, err := os.ReadFile(filepath.Join(dir, "api-key")); err != nil || string(data) != testKey+"\n" {
		t.Fatal("fd 3 did not deliver the expected key")
	}
}
