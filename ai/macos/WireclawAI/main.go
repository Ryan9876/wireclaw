package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
)

// commandResult contains only public lifecycle state. Process identity, paths,
// and the API key remain inside the later lifecycle implementation.
type commandResult struct {
	state  string
	reason string
}

type lifecycle interface {
	start() commandResult
	status() commandResult
	stop() commandResult
}

// These operations are filled in by the subsequent, separately reviewed
// verification and lifecycle tasks. Until then, the runtime is unavailable.
type lifecycleOps struct{}

func (lifecycleOps) start() commandResult {
	fd := os.NewFile(3, "key-bootstrap")
	dir, err := productionStateDir()
	if err != nil {
		if fd != nil {
			_ = fd.Close()
		}
		return commandResult{"unavailable", "state_unavailable"}
	}
	return startVerified(fd, dir, verifyBundle, func(VerifiedBundle, string) commandResult {
		// Task 5 supplies the fixed helper launch; no unverified path is accepted.
		return commandResult{"unavailable", "not_implemented"}
	})
}

// Read and close fd 3, verify every asset, then persist the private key and
// cross the launch boundary with a VerifiedBundle. Failure never launches.
func startVerified(fd io.ReadCloser, dir string, verify func() (VerifiedBundle, error), launch func(VerifiedBundle, string) commandResult) commandResult {
	key, err := readKeyRecord(fd)
	if err != nil {
		return commandResult{"unavailable", "invalid_key"}
	}
	defer wipe(key[:])
	bundle, err := verify()
	if err != nil || bundle.helperPath == "" || bundle.modelPath == "" {
		return commandResult{"unavailable", "verification_failed"}
	}
	path, err := storeKeyRecord(key, dir)
	if err != nil {
		return commandResult{"unavailable", "state_unavailable"}
	}
	result := launch(bundle, path)
	if result.state != "running" {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return commandResult{"unavailable", "state_unavailable"}
		}
	}
	return result
}

func (lifecycleOps) status() commandResult { return commandResult{"unavailable", "not_implemented"} }
func (lifecycleOps) stop() commandResult   { return commandResult{"unavailable", "not_implemented"} }

type publicResult struct {
	State  string `json:"state"`
	Reason string `json:"reason,omitempty"`
}

func allowedReason(reason string) bool {
	switch reason {
	case "invalid_command", "not_implemented", "invalid_key", "verification_failed",
		"launch_failed", "process_missing", "identity_mismatch", "state_unavailable",
		"internal_error":
		return true
	default:
		return false
	}
}

func normalize(result commandResult) publicResult {
	switch result.state {
	case "running", "stopped":
		if result.reason == "" {
			return publicResult{State: result.state}
		}
	case "unavailable":
		if allowedReason(result.reason) {
			return publicResult{State: result.state, Reason: result.reason}
		}
	}
	return publicResult{State: "unavailable", Reason: "internal_error"}
}

// writeResult serializes only allowlisted values, so output size and content
// cannot depend on command-line input or operational error text.
func writeResult(out io.Writer, result commandResult) error {
	data, err := json.Marshal(normalize(result))
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = out.Write(data)
	return err
}

func dispatch(args []string, out io.Writer, ops lifecycle) int {
	if len(args) != 1 {
		_ = writeResult(out, commandResult{state: "unavailable", reason: "invalid_command"})
		return 2
	}

	var result commandResult
	switch args[0] {
	case "start":
		result = ops.start()
	case "status":
		result = ops.status()
	case "stop":
		result = ops.stop()
	default:
		_ = writeResult(out, commandResult{state: "unavailable", reason: "invalid_command"})
		return 2
	}

	public := normalize(result)
	if err := writeResult(out, result); err != nil {
		return 1
	}
	if public.State == "unavailable" {
		return 1
	}
	return 0
}

func main() {
	os.Exit(dispatch(os.Args[1:], os.Stdout, lifecycleOps{}))
}
