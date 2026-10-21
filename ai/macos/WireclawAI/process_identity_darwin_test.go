//go:build darwin && cgo

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestProcessIdentityReportsMissingPID(t *testing.T) {
	_, err := processIdentityForPID(999999)
	if !errors.Is(err, errProcessMissing) {
		t.Fatalf("missing PID classified as %v", err)
	}
}

func TestProcessIdentityForCurrentProcess(t *testing.T) {
	identity, err := processIdentityForPID(os.Getpid())
	if err != nil {
		t.Fatal("process identity unavailable")
	}
	if identity.started == "" {
		t.Fatal("process start identity is empty")
	}
	path, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	resolved, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	if identity.executable != resolved {
		t.Fatalf("executable = %q, want %q", identity.executable, resolved)
	}
}
