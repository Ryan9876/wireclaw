//go:build darwin && cgo

package main

import (
	"errors"
	"reflect"
	"testing"
)

func TestNativeIsolationCleanupPreservesReceiptWhenRecoveryFails(t *testing.T) {
	var calls []string
	ops := nativeIsolationCleanupOps{
		status:              func() ([]byte, error) { calls = append(calls, "status"); return []byte("receipt"), nil },
		recover:             func([]byte) error { calls = append(calls, "recover"); return errors.New("unverified") },
		hostStop:            func() error { calls = append(calls, "host-stop"); return nil },
		wrapperStop:         func() error { calls = append(calls, "wrapper-stop"); return nil },
		removeReceipt:       func() error { calls = append(calls, "remove-receipt"); return nil },
		privateStateRemoved: func() bool { calls = append(calls, "private-clean"); return true },
		removeFixture:       func() error { calls = append(calls, "remove-fixture"); return nil },
		preserve:            func(string) { calls = append(calls, "preserve") },
	}
	if cleanupNativeIsolationFixture(ops) {
		t.Fatal("failed recovery must preserve the host receipt and fixtures")
	}
	if want := []string{"status", "recover", "preserve"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup after failed recovery: got %v, want %v", calls, want)
	}
}

func TestNativeIsolationCleanupPreservesReceiptWhenVerifiedStopFails(t *testing.T) {
	var calls []string
	ops := nativeIsolationCleanupOps{
		status:              func() ([]byte, error) { calls = append(calls, "status"); return []byte("receipt"), nil },
		recover:             func([]byte) error { calls = append(calls, "recover"); return nil },
		hostStop:            func() error { calls = append(calls, "host-stop"); return errors.New("identity mismatch") },
		wrapperStop:         func() error { calls = append(calls, "wrapper-stop"); return nil },
		removeReceipt:       func() error { calls = append(calls, "remove-receipt"); return nil },
		privateStateRemoved: func() bool { calls = append(calls, "private-clean"); return true },
		removeFixture:       func() error { calls = append(calls, "remove-fixture"); return nil },
		preserve:            func(string) { calls = append(calls, "preserve") },
	}
	if cleanupNativeIsolationFixture(ops) {
		t.Fatal("failed verified stop must preserve the host receipt and fixtures")
	}
	if want := []string{"status", "recover", "host-stop", "preserve"}; !reflect.DeepEqual(calls, want) {
		t.Fatalf("cleanup after failed stop: got %v, want %v", calls, want)
	}
}
