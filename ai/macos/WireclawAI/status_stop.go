package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

var errProcessMissing = errors.New("process missing")

const maxIdentityReceipt = 1024

func validReceiptIdentity(r processRecord) bool {
	if r.PID <= 0 || r.PID > 999999 || len(r.ProcessStart) == 0 || len(r.ProcessStart) > 40 || len(r.Executable) == 0 || len(r.Executable) > 512 || !filepath.IsAbs(r.Executable) || filepath.Clean(r.Executable) != r.Executable || !validDigest(r.ExecutableSHA256) {
		return false
	}
	for _, c := range r.ProcessStart {
		if (c < '0' || c > '9') && c != ':' {
			return false
		}
	}
	return strings.Count(r.ProcessStart, ":") == 1
}

func hashFile(path string) (string, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Size() > 512<<20 {
		return "", errProcessIdentity
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return "", err
	}
	f := os.NewFile(uintptr(fd), path)
	defer f.Close()
	opened, err := f.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(info, opened) {
		return "", errProcessIdentity
	}
	sum := sha256.New()
	if _, err = io.Copy(sum, io.LimitReader(f, 512<<20+1)); err != nil {
		return "", err
	}
	return hex.EncodeToString(sum.Sum(nil)), nil
}

func readPrivateRecord(dir string) (processRecord, error) {
	return readPrivateRecordWithOpen(dir, openPrivateProcessRecord)
}

func openPrivateProcessRecord(path string) (*os.File, error) {
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}

func readPrivateRecordWithOpen(dir string, open func(string) (*os.File, error), capture ...func(os.FileInfo)) (processRecord, error) {
	var record processRecord
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return record, errKeyState
	}
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(dir, current), current) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil || !info.IsDir() {
			return record, errKeyState
		}
	}
	privateInfo, err := os.Lstat(dir)
	if err != nil || privateInfo.Mode().Perm() != 0700 {
		return record, errKeyState
	}
	path := filepath.Join(dir, "process.json")
	info, err := os.Lstat(path)
	if err != nil {
		return record, err
	}
	initialOwner, ok := info.Sys().(*syscall.Stat_t)
	if !info.Mode().IsRegular() || info.Mode().Perm() != 0600 || info.Size() < 0 || info.Size() > maxIdentityReceipt || !ok || initialOwner.Uid != uint32(os.Getuid()) {
		return record, errKeyState
	}
	f, err := open(path)
	if err != nil {
		return record, errKeyState
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return record, errKeyState
	}
	openedOwner, ok := opened.Sys().(*syscall.Stat_t)
	if !opened.Mode().IsRegular() || opened.Mode().Perm() != 0600 || opened.Size() != info.Size() || !ok || openedOwner.Uid != uint32(os.Getuid()) || !os.SameFile(info, opened) {
		return record, errKeyState
	}
	dec := json.NewDecoder(io.LimitReader(f, maxIdentityReceipt+1))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&record); err != nil {
		return record, errKeyState
	}
	var extra any
	if err := dec.Decode(&extra); err != io.EOF {
		return record, errKeyState
	}
	if !validReceiptIdentity(record) || record.Model != modelIdentity {
		return record, errKeyState
	}
	if len(capture) > 0 {
		capture[0](opened)
	}
	return record, nil
}

func validatePrivateRecord(record processRecord, bundle VerifiedBundle) error {
	if record.Executable != bundle.helperPath || record.ExecutableSHA256 != bundle.helperHash || record.Model != bundle.modelID || !validDigest(bundle.helperHash) {
		return errProcessIdentity
	}
	hash, err := hashFile(bundle.helperPath)
	if err != nil || hash != bundle.helperHash {
		return errProcessIdentity
	}
	return nil
}

func statusWith(dir string, bundle VerifiedBundle, identify func(int) (processIdentity, error)) commandResult {
	record, err := readPrivateRecord(dir)
	if err != nil {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if err = validatePrivateRecord(record, bundle); err != nil {
		return commandResult{state: "unavailable", reason: "identity_mismatch"}
	}
	current, err := identify(record.PID)
	if err != nil {
		if errors.Is(err, errProcessMissing) {
			return commandResult{state: "unavailable", reason: "process_missing"}
		}
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if current.started != record.ProcessStart || current.executable != record.Executable {
		return commandResult{state: "unavailable", reason: "identity_mismatch"}
	}
	return commandResult{state: "running", identity: &record}
}

// stopWith performs no process signaling. An unreadable or mismatched identity
// preserves private state; only an independently established absence cleans it.
func stopWith(dir string, bundle VerifiedBundle, identify func(int) (processIdentity, error)) commandResult {
	return stopWithRemove(dir, bundle, identify, os.Remove)
}

func stopWithRemove(dir string, bundle VerifiedBundle, identify func(int) (processIdentity, error), remove func(string) error) commandResult {
	var originalFile os.FileInfo
	record, err := readPrivateRecordWithOpen(dir, openPrivateProcessRecord, func(info os.FileInfo) { originalFile = info })
	if errors.Is(err, os.ErrNotExist) {
		if _, keyErr := os.Lstat(filepath.Join(dir, "api-key")); errors.Is(keyErr, os.ErrNotExist) {
			return commandResult{state: "stopped"}
		}
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if err != nil {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if validatePrivateRecord(record, bundle) != nil {
		return commandResult{state: "unavailable", reason: "identity_mismatch"}
	}
	current, err := identify(record.PID)
	if err == nil {
		if current.started == record.ProcessStart && current.executable == record.Executable {
			return commandResult{state: "unavailable", reason: "identity_mismatch"}
		}
		return commandResult{state: "unavailable", reason: "identity_mismatch"}
	}
	if !errors.Is(err, errProcessMissing) {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	// Private state is shared with the helper's sandbox. Re-read the pathname
	// after the absence observation so an observed replacement cannot be
	// mistaken for the record whose PID was checked.
	stateStillOriginal := func() bool {
		var currentFile os.FileInfo
		fresh, freshErr := readPrivateRecordWithOpen(dir, openPrivateProcessRecord, func(info os.FileInfo) { currentFile = info })
		return freshErr == nil && fresh == record && originalFile != nil && currentFile != nil && os.SameFile(originalFile, currentFile)
	}
	if !stateStillOriginal() {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	keyPath := filepath.Join(dir, "api-key")
	keyInfo, keyErr := os.Lstat(keyPath)
	if keyErr != nil && !errors.Is(keyErr, os.ErrNotExist) {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if keyErr == nil {
		ownership, ok := keyInfo.Sys().(*syscall.Stat_t)
		if !keyInfo.Mode().IsRegular() || keyInfo.Mode().Perm() != 0600 || !ok || ownership.Uid != uint32(os.Getuid()) {
			return commandResult{state: "unavailable", reason: "state_unavailable"}
		}
	}
	// This is the final check before either private file is removed. POSIX
	// pathname unlink still has a race after this read; no atomic inode-bound
	// removal is claimed.
	if !stateStillOriginal() {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if keyErr == nil {
		if err := remove(keyPath); err != nil {
			return commandResult{state: "unavailable", reason: "state_unavailable"}
		}
	}
	if err := remove(filepath.Join(dir, "process.json")); err != nil {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	return commandResult{state: "stopped"}
}
