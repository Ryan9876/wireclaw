package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
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

func openRequestFor(requestID, token, origin string) *http.Request {
	body := `{"request_id":"` + requestID + `","token":"` + token + `"}`
	request := httptest.NewRequest(http.MethodPost, "/v1/open", strings.NewReader(body))
	request.Header.Set("Origin", origin)
	request.Header.Set("Content-Type", "application/json")
	return request
}

func TestOpenUsesExactApprovedArgvAndConsumesGrant(t *testing.T) {
	rootBase := t.TempDir()
	root := filepath.Join(rootBase, "data root with spaces")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	requestID := strings.Repeat("c", 32)
	token := strings.Repeat("x", 48)
	manifestPath := writeGrant(t, root, requestID, token, "cases/capture with spaces.pcapng", []byte("capture"))
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
	response := httptest.NewRecorder()
	bridge.open(response, openRequestFor(requestID, token, "http://127.0.0.1:8765"))
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		t.Fatal(err)
	}
	expectedArgs := []string{"-r", filepath.Join(canonicalRoot, "cases", "capture with spaces.pcapng"), "-Y", "tcp.stream == 7"}
	if executable == "" || !reflect.DeepEqual(args, expectedArgs) {
		t.Fatalf("unexpected launch %q %#v expected %#v", executable, args, expectedArgs)
	}
	if _, err := os.Stat(manifestPath); !os.IsNotExist(err) {
		t.Fatal("grant was not consumed")
	}
	response = httptest.NewRecorder()
	bridge.open(response, openRequestFor(requestID, token, "http://127.0.0.1:8765"))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("replay status=%d body=%s", response.Code, response.Body.String())
	}
}

func TestRejectsOriginTokenTraversalAndControlFilter(t *testing.T) {
	root := t.TempDir()
	bridge, err := newServer(root, os.Args[0])
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name     string
		origin   string
		token    string
		relative string
		filter   string
		want     int
	}{
		{"origin", "http://evil.invalid", strings.Repeat("x", 48), "cases/capture", "tcp.stream == 1", http.StatusForbidden},
		{"token", "http://127.0.0.1:8765", strings.Repeat("y", 48), "cases/capture", "tcp.stream == 1", http.StatusUnauthorized},
		{"traversal", "http://127.0.0.1:8765", strings.Repeat("x", 48), "../escape", "tcp.stream == 1", http.StatusUnprocessableEntity},
		{"filter", "http://127.0.0.1:8765", strings.Repeat("x", 48), "cases/capture", "tcp.stream == 1\nframe", http.StatusUnauthorized},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			requestID := strings.Repeat(string('a'+rune(len(tc.name)%6)), 32)
			manifestPath := writeGrant(t, root, requestID, strings.Repeat("x", 48), tc.relative, []byte("capture"))
			data, _ := os.ReadFile(manifestPath)
			var value manifest
			_ = json.Unmarshal(data, &value)
			value.DisplayFilter = tc.filter
			data, _ = json.Marshal(value)
			_ = os.WriteFile(manifestPath, data, 0o600)
			response := httptest.NewRecorder()
			bridge.open(response, openRequestFor(requestID, tc.token, tc.origin))
			if response.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tc.want, response.Body.String())
			}
		})
	}
}

func TestRejectsUnknownRequestFieldsAndOversize(t *testing.T) {
	root := t.TempDir()
	bridge, _ := newServer(root, os.Args[0])
	requestID := strings.Repeat("d", 32)
	token := strings.Repeat("x", 48)
	writeGrant(t, root, requestID, token, "cases/capture", []byte("capture"))
	tests := []struct {
		name string
		body string
		want int
	}{
		{"unknown", `{"request_id":"` + requestID + `","token":"` + token + `","path":"/tmp/x"}`, http.StatusUnprocessableEntity},
		{"oversize", `{"request_id":"` + requestID + `","token":"` + strings.Repeat("x", maxRequestBytes) + `"}`, http.StatusUnprocessableEntity},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "/v1/open", strings.NewReader(tc.body))
			request.Header.Set("Origin", "http://127.0.0.1:8765")
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			bridge.open(response, request)
			if response.Code != tc.want {
				t.Fatalf("status=%d want=%d body=%s", response.Code, tc.want, response.Body.String())
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

func TestPlatformDiscoveryCandidatesAreIsolated(t *testing.T) {
	getenv := func(name string) string {
		switch name {
		case "ProgramFiles":
			return `C:\Program Files`
		case "ProgramFiles(x86)":
			return `C:\Program Files (x86)`
		}
		return ""
	}
	lookPath := func(name string) (string, error) {
		if name == "wireshark" {
			return "/opt/bin/wireshark", nil
		}
		return "", errors.New("not found")
	}
	if got := wiresharkCandidates("darwin", getenv, lookPath, ""); !reflect.DeepEqual(got, []string{"/Applications/Wireshark.app/Contents/MacOS/Wireshark"}) {
		t.Fatalf("darwin candidates %#v", got)
	}
	windows := wiresharkCandidates("windows", getenv, lookPath, "")
	if len(windows) != 2 || !strings.Contains(windows[0], "Program Files") || !strings.HasSuffix(windows[0], filepath.Join("Wireshark", "Wireshark.exe")) {
		t.Fatalf("windows candidates %#v", windows)
	}
	linux := wiresharkCandidates("linux", getenv, lookPath, "")
	if !reflect.DeepEqual(linux, []string{"/opt/bin/wireshark", "/usr/bin/wireshark", "/usr/local/bin/wireshark"}) {
		t.Fatalf("linux candidates %#v", linux)
	}
	if got := wiresharkCandidates("linux", getenv, lookPath, "/approved/custom"); !reflect.DeepEqual(got, []string{"/approved/custom"}) {
		t.Fatalf("configured candidate %#v", got)
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
