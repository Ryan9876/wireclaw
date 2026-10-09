package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"
	"time"
)

func writeGrant(t *testing.T, root, requestID, token, relative string, payload []byte) string {
	t.Helper()
	artifact := filepath.Join(root, filepath.FromSlash(relative))
	if err := os.MkdirAll(filepath.Dir(artifact), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(artifact, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256(payload)
	tokenDigest := sha256.Sum256([]byte(token))
	value := manifest{
		SchemaVersion:  1,
		RequestID:      requestID,
		TokenSHA256:    hex.EncodeToString(tokenDigest[:]),
		CaseID:         strings.Repeat("a", 32),
		ArtifactID:     strings.Repeat("b", 32),
		ArtifactKind:   "original",
		RelativePath:   relative,
		ArtifactSHA256: hex.EncodeToString(digest[:]),
		DisplayFilter:  "tcp.stream == 7",
		ExpiresUnix:    time.Now().Add(time.Minute).Unix(),
	}
	directory := filepath.Join(root, "bridge", "requests")
	if err := os.MkdirAll(directory, 0o700); err != nil {
		t.Fatal(err)
	}
	encoded, _ := json.Marshal(value)
	path := filepath.Join(directory, requestID+".json")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenUsesExactApprovedArgvAndConsumesGrant(t *testing.T) {
	root := t.TempDir()
	requestID := strings.Repeat("c", 32)
	token := strings.Repeat("x", 48)
	manifestPath := writeGrant(t, root, requestID, token, "cases/capture.pcapng", []byte("capture"))
	bridge, err := newServer(root, os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	var executable string
	var args []string
	bridge.launch = func(path string, values ...string) error {
		executable = path
		args = append([]string(nil), values...)
		return nil
	}
	body := `{"request_id":"` + requestID + `","token":"` + token + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/open", strings.NewReader(body))
	request.Header.Set("Origin", "http://127.0.0.1:8765")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	bridge.open(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	if executable == "" || !reflect.DeepEqual(args, []string{"-r", filepath.Join(root, "cases", "capture.pcapng"), "-Y", "tcp.stream == 7"}) {
		t.Fatalf("unexpected launch %q %#v", executable, args)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatal("grant was not consumed")
	}
}

func TestRejectsOriginTokenTraversalAndControlFilter(t *testing.T) {
	root := t.TempDir()
	bridge, err := newServer(root, os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	for name, origin, token, relative, filter, want := range []struct {
		name, origin, token, relative, filter string
		want                                  int
	}{
		{"origin", "http://evil.invalid", strings.Repeat("x", 48), "cases/capture", "tcp.stream == 1", http.StatusForbidden},
		{"token", "http://127.0.0.1:8765", strings.Repeat("y", 48), "cases/capture", "tcp.stream == 1", http.StatusUnauthorized},
		{"traversal", "http://127.0.0.1:8765", strings.Repeat("x", 48), "../escape", "tcp.stream == 1", http.StatusUnprocessableEntity},
		{"filter", "http://127.0.0.1:8765", strings.Repeat("x", 48), "cases/capture", "tcp.stream == 1\nframe", http.StatusUnauthorized},
	} {
		t.Run(name, func(t *testing.T) {
			requestID := strings.Repeat(string('a'+rune(len(name)%6)), 32)
			manifestPath := writeGrant(t, root, requestID, strings.Repeat("x", 48), relative, []byte("capture"))
			if filter != "tcp.stream == 7" {
				data, _ := os.ReadFile(manifestPath)
				var value manifest
				_ = json.Unmarshal(data, &value)
				value.DisplayFilter = filter
				data, _ = json.Marshal(value)
				_ = os.WriteFile(manifestPath, data, 0o600)
			}
			body := `{"request_id":"` + requestID + `","token":"` + token + `"}`
			request := httptest.NewRequest(http.MethodPost, "/v1/open", strings.NewReader(body))
			request.Header.Set("Origin", origin)
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			bridge.open(response, request)
			if response.Code != want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, want, response.Body.String())
			}
		})
	}
}

func TestResolveRejectsSymlinkEscape(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink permissions vary on Windows")
	}
	root := t.TempDir()
	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "capture")
	if err := os.WriteFile(outsideFile, []byte("capture"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte("capture"))
	bridge, _ := newServer(root, os.Args[0])
	_, err := bridge.resolveArtifact(manifest{RelativePath: "escape", ArtifactSHA256: hex.EncodeToString(digest[:])})
	if err == nil {
		t.Fatal("expected symlink escape rejection")
	}
}

func TestFilterBoundsAndIDs(t *testing.T) {
	if validFilter("ok\nno") || validFilter(strings.Repeat("a", maxFilterBytes+1)) || !validFilter("tcp.stream == 1") {
		t.Fatal("filter validation failure")
	}
	if !validID(strings.Repeat("a", 32)) || validID(strings.Repeat("g", 32)) || validID("short") {
		t.Fatal("id validation failure")
	}
}
