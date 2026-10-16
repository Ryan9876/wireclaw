package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

type fakeLifecycle struct {
	called []string
	result commandResult
}

func (f *fakeLifecycle) start() commandResult {
	f.called = append(f.called, "start")
	return f.result
}

func (f *fakeLifecycle) status() commandResult {
	f.called = append(f.called, "status")
	return f.result
}

func (f *fakeLifecycle) stop() commandResult {
	f.called = append(f.called, "stop")
	return f.result
}

func TestDispatchAcceptsExactlyThreeCommands(t *testing.T) {
	for _, command := range []string{"start", "status", "stop"} {
		t.Run(command, func(t *testing.T) {
			ops := &fakeLifecycle{result: commandResult{state: "running"}}
			var output bytes.Buffer
			if code := dispatch([]string{command}, &output, ops); code != 0 {
				t.Fatalf("exit code = %d; want 0", code)
			}
			if len(ops.called) != 1 || ops.called[0] != command {
				t.Fatalf("called = %v; want only %q", ops.called, command)
			}
			var result map[string]any
			if err := json.Unmarshal(output.Bytes(), &result); err != nil {
				t.Fatalf("invalid JSON: %v", err)
			}
			if result["state"] != "running" || len(result) != 1 {
				t.Fatalf("unexpected result: %v", result)
			}
		})
	}
}

func TestDispatchRejectsMissingUnknownAndExtraArguments(t *testing.T) {
	for _, args := range [][]string{
		nil,
		{""},
		{"restart"},
		{"start", "extra"},
		{"status", "extra"},
		{"stop", "extra"},
		{"start", "--model", "/secret/model.gguf"},
	} {
		t.Run(strings.Join(args, "_"), func(t *testing.T) {
			ops := &fakeLifecycle{}
			var output bytes.Buffer
			if code := dispatch(args, &output, ops); code != 2 {
				t.Fatalf("exit code = %d; want 2", code)
			}
			if len(ops.called) != 0 {
				t.Fatalf("rejected command invoked operation: %v", ops.called)
			}
			if output.String() != "{\"state\":\"unavailable\",\"reason\":\"invalid_command\"}\n" {
				t.Fatalf("unexpected rejection: %q", output.String())
			}
		})
	}
}

func TestDispatchNormalizesOperationOutput(t *testing.T) {
	for _, result := range []commandResult{
		{state: "running", reason: "unexpected"},
		{state: "running\",\"pid\":123", reason: ""},
		{state: "unavailable", reason: "secret=/tmp/key"},
		{state: "unavailable", reason: strings.Repeat("secret", 1000)},
	} {
		ops := &fakeLifecycle{result: result}
		var output bytes.Buffer
		if code := dispatch([]string{"status"}, &output, ops); code != 1 {
			t.Fatalf("exit code = %d; want 1", code)
		}
		if output.String() != "{\"state\":\"unavailable\",\"reason\":\"internal_error\"}\n" {
			t.Fatalf("unbounded/unexpected output: %q", output.String())
		}
		if output.Len() > 128 {
			t.Fatalf("output length = %d; want at most 128", output.Len())
		}
	}
}

func TestDispatchPreservesNormalizedUnavailableReason(t *testing.T) {
	ops := &fakeLifecycle{result: commandResult{state: "unavailable", reason: "process_missing"}}
	var output bytes.Buffer
	if code := dispatch([]string{"status"}, &output, ops); code != 1 {
		t.Fatalf("exit code = %d; want 1", code)
	}
	if output.String() != "{\"state\":\"unavailable\",\"reason\":\"process_missing\"}\n" {
		t.Fatalf("unexpected result: %q", output.String())
	}
}
