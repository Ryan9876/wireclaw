package main

import (
	"bytes"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"syscall"
	"testing"
)

type fakeChild struct {
	started, released, killed bool
	path                      string
	args, env                 []string
	stdout, stderr            io.Writer
}

type trackingChild struct {
	*osChild
	pid int
}

func (c *trackingChild) Release() error { c.pid = c.PID(); return c.osChild.Release() }

func (c *fakeChild) Start() error   { c.started = true; return nil }
func (c *fakeChild) PID() int       { return 4321 }
func (c *fakeChild) Release() error { c.released = true; return nil }
func (c *fakeChild) Kill() error    { c.killed = true; return nil }

func TestLaunchVerifiedUsesOnlyPinnedHelperArgumentsAndReleasesChild(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api-key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("a", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bundle := VerifiedBundle{helperPath: "/signed/WireclawAI.app/Contents/MacOS/llama-server", modelPath: "/signed/WireclawAI.app/Contents/Resources/ai/model.gguf", modelID: modelIdentity, helperHash: strings.Repeat("c", 64)}
	var got *fakeChild
	result := launchVerified(bundle, keyPath, func() (string, error) { return dir, nil }, func(int) (processIdentity, error) { return processIdentity{"123:456", bundle.helperPath}, nil }, func(path string, args, env []string, stdout, stderr io.Writer) childProcess {
		got = &fakeChild{path: path, args: args, env: env, stdout: stdout, stderr: stderr}
		return got
	})
	if result.state != "running" || result.reason != "" {
		t.Fatalf("result = %#v", result)
	}
	if got == nil || !got.started || !got.released {
		t.Fatalf("child lifecycle = %#v", got)
	}
	if got.path != bundle.helperPath {
		t.Fatalf("path = %q", got.path)
	}
	want := []string{"--model", bundle.modelPath, "--alias", modelAlias, "--host", "127.0.0.1", "--port", "8767", "--ctx-size", "16384", "--batch-size", "128", "--ubatch-size", "32", "--n-predict", "2048", "--parallel", "1", "--api-key-file", keyPath, "--no-agent", "--no-webui", "--cache-ram", "0"}
	if !reflect.DeepEqual(got.args, want) {
		t.Fatalf("args = %#v", got.args)
	}
	joined := strings.Join(got.args, " ")
	if strings.Contains(joined, strings.Repeat("a", 64)) {
		t.Fatal("key contents reached argv")
	}
	if strings.Contains(strings.Join(got.env, "\n"), strings.Repeat("a", 64)) || !reflect.DeepEqual(got.env, []string{"HOME=" + dir, "TMPDIR=" + dir, "PATH=/usr/bin:/bin", "HF_HUB_OFFLINE=1", "HF_HUB_DISABLE_TELEMETRY=1"}) {
		t.Fatalf("unexpected helper environment: %#v", got.env)
	}
	if _, err := os.Stat(filepath.Join(dir, "process.json")); err != nil {
		t.Fatalf("process state missing: %v", err)
	}
	state, err := os.ReadFile(filepath.Join(dir, "process.json"))
	if err != nil || !strings.Contains(string(state), `"process_start":"123:456"`) || !strings.Contains(string(state), `"executable_sha256":"`+bundle.helperHash+`"`) {
		t.Fatalf("process identity missing from state: %s (%v)", state, err)
	}
	if info, err := os.Stat(filepath.Join(dir, "runtime.log")); err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("log permissions: %v %v", info, err)
	}
}

func TestLaunchVerifiedRejectsIncompleteBundleBeforeChild(t *testing.T) {
	called := false
	result := launchVerified(VerifiedBundle{modelPath: "/model"}, "/state/api-key", func() (string, error) { return t.TempDir(), nil }, processIdentityForPID, func(string, []string, []string, io.Writer, io.Writer) childProcess {
		called = true
		return &fakeChild{}
	})
	if result.state != "unavailable" || result.reason != "launch_failed" || called {
		t.Fatalf("result=%#v called=%v", result, called)
	}
}

func TestLaunchVerifiedKillsChildWhenProcessStateCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, "process.json"), 0700); err != nil {
		t.Fatal(err)
	}
	keyPath := filepath.Join(dir, "api-key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("c", 64)+"\\n"), 0600); err != nil {
		t.Fatal(err)
	}
	bundle := VerifiedBundle{helperPath: "/signed/helper", modelPath: "/signed/model", modelID: modelIdentity, helperHash: strings.Repeat("d", 64)}
	child := &fakeChild{}
	result := launchVerified(bundle, keyPath, func() (string, error) { return dir, nil }, func(int) (processIdentity, error) {
		return processIdentity{"123:458", bundle.helperPath}, nil
	}, func(string, []string, []string, io.Writer, io.Writer) childProcess { return child })
	if result.state != "unavailable" || result.reason != "state_unavailable" {
		t.Fatalf("result = %#v", result)
	}
	if !child.started || !child.killed || !child.released {
		t.Fatalf("child lifecycle = %#v; expected started, killed, and released", child)
	}
}

func TestChildProcessPersistsAfterStartReturns(t *testing.T) {
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "api-key")
	if err := os.WriteFile(keyPath, []byte(strings.Repeat("b", 64)+"\n"), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command("/bin/sleep", "30")
	var child *trackingChild
	bundle := VerifiedBundle{helperPath: "/verified/helper", modelPath: "/verified/model", modelID: modelIdentity, helperHash: strings.Repeat("d", 64)}
	result := launchVerified(bundle, keyPath, func() (string, error) { return dir, nil }, func(pid int) (processIdentity, error) {
		if err := syscall.Kill(pid, 0); err != nil {
			return processIdentity{}, err
		}
		return processIdentity{"123:457", bundle.helperPath}, nil
	}, func(string, []string, []string, io.Writer, io.Writer) childProcess {
		child = &trackingChild{osChild: &osChild{cmd: cmd}}
		return child
	})
	if result.state != "running" {
		t.Fatalf("result = %#v", result)
	}
	if child.pid <= 0 {
		t.Fatalf("invalid child pid %d", child.pid)
	}
	if err := syscall.Kill(child.pid, 0); err != nil {
		t.Fatalf("child did not persist after launch returned: %v", err)
	}
	if err := syscall.Kill(child.pid, syscall.SIGKILL); err != nil {
		t.Fatalf("cleanup child: %v", err)
	}
}

func TestCappedLogDiscardsPastBound(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "log")
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	log := &cappedLog{file: file, remaining: 4}
	if n, err := log.Write([]byte("abcdef")); n != 6 || err != nil {
		t.Fatalf("write = %d, %v", n, err)
	}
	if _, err := file.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	if _, err := io.Copy(&output, file); err != nil {
		t.Fatal(err)
	}
	if output.String() != "abcd" {
		t.Fatalf("log = %q", output.String())
	}
}
