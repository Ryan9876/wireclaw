package main

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"
)

const (
	modelAlias     = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
	contextSize    = "16384"
	maxTokens      = "2048"
	batchSize      = "128"
	microBatchSize = "32"
	logLimit       = 1 << 20
)

var errProcessIdentity = errors.New("process identity unavailable")

type childProcess interface {
	Start() error
	PID() int
	Release() error
	Kill() error
}

type osChild struct{ cmd *exec.Cmd }

func (c *osChild) Start() error { return c.cmd.Start() }
func (c *osChild) PID() int {
	if c.cmd.Process == nil {
		return 0
	}
	return c.cmd.Process.Pid
}
func (c *osChild) Release() error { return c.cmd.Process.Release() }
func (c *osChild) Kill() error    { return c.cmd.Process.Kill() }

type processRecord struct {
	PID              int    `json:"pid"`
	ProcessStart     string `json:"process_start"`
	Executable       string `json:"executable"`
	ExecutableSHA256 string `json:"executable_sha256"`
	Model            string `json:"model"`
}

// cappedLog is private, append-only for one launch, and discards writes after
// the fixed cap so a noisy or compromised helper cannot grow host state.
type cappedLog struct {
	mu        sync.Mutex
	file      *os.File
	remaining int
}

func (w *cappedLog) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.remaining <= 0 {
		return len(p), nil
	}
	write := p
	if len(write) > w.remaining {
		write = write[:w.remaining]
	}
	n, err := w.file.Write(write)
	w.remaining -= n
	if err != nil {
		return n, err
	}
	return len(p), nil
}

func helperArguments(bundle VerifiedBundle, keyPath string) []string {
	return []string{
		"--model", bundle.modelPath,
		"--alias", modelAlias,
		"--host", "127.0.0.1",
		"--port", "8767",
		"--ctx-size", contextSize,
		"--batch-size", batchSize,
		"--ubatch-size", microBatchSize,
		"--n-predict", maxTokens,
		"--parallel", "1",
		"--api-key-file", keyPath,
		"--no-agent",
		"--no-webui",
		"--cache-ram", "0",
	}
}

func launchHelper(bundle VerifiedBundle, keyPath string) commandResult {
	return launchVerified(bundle, keyPath, productionStateDirForLaunch, processIdentityForPID, func(path string, args, env []string, stdout, stderr io.Writer) childProcess {
		cmd := exec.Command(path, args...)
		cmd.Env, cmd.Stdout, cmd.Stderr = env, stdout, stderr
		return &osChild{cmd: cmd}
	})
}

// productionStateDirForLaunch derives the already-created sandbox container's
// private app-support path from the validated key location.
func productionStateDirForLaunch() (string, error) {
	return productionStateDir()
}

func launchVerified(bundle VerifiedBundle, keyPath string, stateDir func() (string, error), identify func(int) (processIdentity, error), makeChild func(string, []string, []string, io.Writer, io.Writer) childProcess) commandResult {
	if bundle.helperPath == "" || bundle.modelPath == "" || !validDigest(bundle.helperHash) || keyPath == "" || filepath.Base(keyPath) != "api-key" {
		return commandResult{state: "unavailable", reason: "launch_failed"}
	}
	dir, err := stateDir()
	if err != nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	logPath := filepath.Join(dir, "runtime.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if err = logFile.Chmod(0o600); err != nil {
		_ = logFile.Close()
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	log := &cappedLog{file: logFile, remaining: logLimit}
	env := []string{
		"HOME=" + dir,
		"TMPDIR=" + dir,
		"PATH=/usr/bin:/bin",
		"HF_HUB_OFFLINE=1",
		"HF_HUB_DISABLE_TELEMETRY=1",
	}
	child := makeChild(bundle.helperPath, helperArguments(bundle, keyPath), env, log, log)
	if child == nil || child.Start() != nil {
		_ = logFile.Close()
		return commandResult{state: "unavailable", reason: "launch_failed"}
	}
	record := processRecord{PID: child.PID(), Executable: bundle.helperPath, Model: bundle.modelID}
	if record.PID <= 0 {
		_ = child.Kill()
		_ = child.Release()
		_ = logFile.Close()
		return commandResult{state: "unavailable", reason: "launch_failed"}
	}
	identity, err := waitForProcessIdentity(record.PID, bundle.helperPath, identify)
	if err != nil {
		_ = child.Kill()
		_ = child.Release()
		_ = logFile.Close()
		return commandResult{state: "unavailable", reason: "launch_failed"}
	}
	record.ProcessStart = identity.started
	record.Executable = identity.executable
	record.ExecutableSHA256 = bundle.helperHash
	data, err := json.Marshal(record)
	if err != nil {
		_ = child.Kill()
		_ = child.Release()
		_ = logFile.Close()
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	statePath := filepath.Join(dir, "process.json")
	tmp, err := os.CreateTemp(dir, ".process-")
	if err == nil {
		err = tmp.Chmod(0o600)
	}
	if err == nil {
		_, err = tmp.Write(append(data, '\n'))
	}
	if err == nil {
		err = tmp.Sync()
	}
	if tmp != nil {
		name := tmp.Name()
		closeErr := tmp.Close()
		if err == nil {
			err = closeErr
		}
		if err == nil {
			err = os.Rename(name, statePath)
		}
		if err != nil {
			_ = os.Remove(name)
		}
	}
	if err != nil {
		_ = child.Kill()
		_ = child.Release()
		_ = logFile.Close()
		return commandResult{state: "unavailable", reason: "state_unavailable"}
	}
	if err = child.Release(); err != nil {
		_ = child.Kill()
		_ = logFile.Close()
		_ = os.Remove(statePath)
		return commandResult{state: "unavailable", reason: "launch_failed"}
	}
	_ = logFile.Close()
	return commandResult{state: "running", identity: &record}
}

func waitForProcessIdentity(pid int, expectedExecutable string, identify func(int) (processIdentity, error)) (processIdentity, error) {
	deadline := time.Now().Add(time.Second)
	for {
		identity, err := identify(pid)
		if err == nil {
			if identity.started == "" || identity.executable != expectedExecutable {
				return processIdentity{}, errProcessIdentity
			}
			return identity, nil
		}
		if time.Now().After(deadline) {
			return processIdentity{}, errProcessIdentity
		}
		time.Sleep(20 * time.Millisecond)
	}
}
