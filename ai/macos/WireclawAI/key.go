package main

import (
	"errors"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strings"
)

const bundleID = "com.wireclaw.WireclawAI"

var (
	errInvalidKey = errors.New("invalid key record")
	errKeyState   = errors.New("private key state unavailable")
)

// privateStateDir is derived from the OS account home, never from HOME or a
// command argument. The fixed container path is the only writable state root.
func privateStateDir(home string) string {
	containerSuffix := filepath.Join("Library", "Containers", bundleID, "Data")
	if strings.HasSuffix(filepath.Clean(home), string(filepath.Separator)+containerSuffix) {
		return filepath.Join(home, "Library", "Application Support", "WireclawAI")
	}
	return filepath.Join(home, "Library", "Containers", bundleID, "Data", "Library", "Application Support", "WireclawAI")
}

func productionStateDir() (string, error) {
	account, err := user.Current()
	if err != nil || account.HomeDir == "" || !filepath.IsAbs(account.HomeDir) {
		return "", errKeyState
	}
	return privateStateDir(account.HomeDir), nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

// readKeyRecord consumes at most 66 bytes. A successful record needs EOF
// immediately after its newline, so an extra byte or record is rejected.
func readKeyRecord(fd io.ReadCloser) ([65]byte, error) {
	var key [65]byte
	if fd == nil {
		return key, errInvalidKey
	}
	defer fd.Close()
	var record [66]byte
	defer wipe(record[:])
	n, err := io.ReadFull(fd, record[:])
	if n != 65 || err != io.ErrUnexpectedEOF || record[64] != '\n' {
		return key, errInvalidKey
	}
	for _, c := range record[:64] {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			return key, errInvalidKey
		}
	}
	copy(key[:], record[:65])
	return key, nil
}

// bootstrapKey closes the inherited descriptor before returning a file path
// to the later helper-launch step. No key material reaches argv or environment.
func bootstrapKey(fd io.ReadCloser, dir string) (string, error) {
	key, err := readKeyRecord(fd)
	if err != nil {
		return "", errInvalidKey
	}
	defer wipe(key[:])
	return storeKeyRecord(key, dir)
}

func storeKeyRecord(key [65]byte, dir string) (string, error) {
	defer wipe(key[:])
	if err := ensurePrivateDir(dir); err != nil {
		return "", errKeyState
	}
	tmp, err := os.CreateTemp(dir, ".api-key-")
	if err != nil {
		return "", errKeyState
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return "", errKeyState
	}
	if _, err := tmp.Write(key[:]); err != nil {
		_ = tmp.Close()
		return "", errKeyState
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return "", errKeyState
	}
	if err := tmp.Close(); err != nil {
		return "", errKeyState
	}
	path := filepath.Join(dir, "api-key")
	if err := os.Rename(tmpName, path); err != nil {
		return "", errKeyState
	}
	return path, nil
}

func ensurePrivateDir(dir string) error {
	if !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return errKeyState
	}
	// Walk each ancestor without following an existing symlink. MkdirAll
	// would follow an intermediate link before the final Lstat could see it.
	current := string(filepath.Separator)
	for _, part := range strings.Split(strings.TrimPrefix(dir, current), current) {
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if errors.Is(err, os.ErrNotExist) {
			if err := os.Mkdir(current, 0o700); err != nil && !errors.Is(err, os.ErrExist) {
				return err
			}
			info, err = os.Lstat(current)
		}
		if err != nil || !info.IsDir() {
			return errKeyState
		}
	}
	return os.Chmod(dir, 0o700)
}
