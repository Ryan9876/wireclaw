//go:build darwin && cgo

package main

import (
	"os"
	"path/filepath"
	"testing"
)

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
