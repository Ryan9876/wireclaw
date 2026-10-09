package main

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

const maxRequestBytes = 4096
const maxFilterBytes = 2048

type manifest struct {
	SchemaVersion  int    `json:"schema_version"`
	RequestID      string `json:"request_id"`
	TokenSHA256    string `json:"token_sha256"`
	CaseID         string `json:"case_id"`
	ArtifactID     string `json:"artifact_id"`
	ArtifactKind   string `json:"artifact_kind"`
	RelativePath   string `json:"relative_path"`
	ArtifactSHA256 string `json:"artifact_sha256"`
	DisplayFilter  string `json:"display_filter"`
	ExpiresUnix    int64  `json:"expires_unix"`
}

type openRequest struct {
	RequestID string `json:"request_id"`
	Token     string `json:"token"`
}

type launcher func(string, ...string) error

type server struct {
	dataRoot       string
	wireshark      string
	allowedOrigins map[string]struct{}
	launch         launcher
	now            func() time.Time
	mu             sync.Mutex
	launches       []time.Time
}

func newServer(dataRoot, wireshark string) (*server, error) {
	root, err := filepath.Abs(dataRoot)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	if wireshark == "" {
		wireshark, err = discoverWiresharkFor(runtime.GOOS, os.Getenv, exec.LookPath, "")
		if err != nil {
			wireshark = ""
		}
	} else {
		wireshark, err = discoverWiresharkFor(runtime.GOOS, os.Getenv, exec.LookPath, wireshark)
		if err != nil {
			return nil, err
		}
	}
	return &server{
		dataRoot:  root,
		wireshark: wireshark,
		allowedOrigins: map[string]struct{}{
			"http://127.0.0.1:8765": {},
			"http://localhost:8765": {},
			"http://[::1]:8765":     {},
		},
		launch: func(executable string, args ...string) error {
			command := exec.Command(executable, args...)
			command.Stdin = nil
			command.Stdout = nil
			command.Stderr = nil
			return command.Start()
		},
		now: time.Now,
	}, nil
}

func validID(value string) bool {
	if len(value) != 32 {
		return false
	}
	for _, char := range value {
		if !((char >= '0' && char <= '9') || (char >= 'a' && char <= 'f')) {
			return false
		}
	}
	return true
}

func validFilter(value string) bool {
	if len(value) > maxFilterBytes {
		return false
	}
	for _, char := range value {
		if char < 32 || char == 127 {
			return false
		}
	}
	return true
}

func safeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func (s *server) allowOrigin(w http.ResponseWriter, r *http.Request, require bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		if require {
			safeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "origin_required"}})
			return false
		}
		return true
	}
	if _, ok := s.allowedOrigins[origin]; !ok {
		safeJSON(w, http.StatusForbidden, map[string]any{"error": map[string]string{"code": "origin_rejected"}})
		return false
	}
	w.Header().Set("Access-Control-Allow-Origin", origin)
	w.Header().Set("Vary", "Origin")
	return true
}

func (s *server) rateLimit() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	cutoff := s.now().Add(-10 * time.Second)
	kept := s.launches[:0]
	for _, item := range s.launches {
		if item.After(cutoff) {
			kept = append(kept, item)
		}
	}
	s.launches = kept
	if len(s.launches) >= 5 {
		return false
	}
	s.launches = append(s.launches, s.now())
	return true
}

func (s *server) health(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		safeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]string{"code": "method_not_allowed"}})
		return
	}
	if !s.allowOrigin(w, r, false) {
		return
	}
	safeJSON(w, http.StatusOK, map[string]any{"status": "ok", "wireshark_available": s.wireshark != ""})
}

func (s *server) options(w http.ResponseWriter, r *http.Request) {
	if !s.allowOrigin(w, r, true) {
		return
	}
	w.Header().Set("Access-Control-Allow-Methods", "POST, OPTIONS")
	w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
	w.Header().Set("Access-Control-Max-Age", "60")
	w.WriteHeader(http.StatusNoContent)
}

func (s *server) open(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodOptions {
		s.options(w, r)
		return
	}
	if r.Method != http.MethodPost {
		safeJSON(w, http.StatusMethodNotAllowed, map[string]any{"error": map[string]string{"code": "method_not_allowed"}})
		return
	}
	if !s.allowOrigin(w, r, true) {
		return
	}
	if r.Header.Get("Content-Type") != "application/json" {
		safeJSON(w, http.StatusUnsupportedMediaType, map[string]any{"error": map[string]string{"code": "json_required"}})
		return
	}
	if !s.rateLimit() {
		safeJSON(w, http.StatusTooManyRequests, map[string]any{"error": map[string]string{"code": "launch_rate_limit"}})
		return
	}
	body := http.MaxBytesReader(w, r.Body, maxRequestBytes)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var request openRequest
	if err := decoder.Decode(&request); err != nil {
		safeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "invalid_request"}})
		return
	}
	if err := decoder.Decode(&struct{}{}); err != io.EOF {
		safeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "invalid_request"}})
		return
	}
	if !validID(request.RequestID) || len(request.Token) < 32 || len(request.Token) > 128 {
		safeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "invalid_grant"}})
		return
	}
	m, path, err := s.loadManifest(request.RequestID)
	if err != nil {
		safeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "invalid_grant"}})
		return
	}
	actual := sha256.Sum256([]byte(request.Token))
	expected, err := hex.DecodeString(m.TokenSHA256)
	if err != nil || len(expected) != sha256.Size || subtle.ConstantTimeCompare(actual[:], expected) != 1 {
		safeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "invalid_grant"}})
		return
	}
	if m.ExpiresUnix < s.now().Unix() {
		safeJSON(w, http.StatusUnauthorized, map[string]any{"error": map[string]string{"code": "grant_expired"}})
		return
	}
	capture, err := s.resolveArtifact(m)
	if err != nil {
		safeJSON(w, http.StatusUnprocessableEntity, map[string]any{"error": map[string]string{"code": "artifact_rejected"}})
		return
	}
	consumed := path + ".consumed"
	if err := os.Rename(path, consumed); err != nil {
		safeJSON(w, http.StatusConflict, map[string]any{"error": map[string]string{"code": "grant_consumed"}})
		return
	}
	defer os.Remove(consumed)
	if s.wireshark == "" {
		safeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "wireshark_unavailable"}})
		return
	}
	args := []string{"-r", capture}
	if m.DisplayFilter != "" {
		args = append(args, "-Y", m.DisplayFilter)
	}
	if err := s.launch(s.wireshark, args...); err != nil {
		safeJSON(w, http.StatusServiceUnavailable, map[string]any{"error": map[string]string{"code": "wireshark_launch_failed"}})
		return
	}
	safeJSON(w, http.StatusOK, map[string]any{"opened": true})
}

func (s *server) loadManifest(requestID string) (manifest, string, error) {
	var value manifest
	path := filepath.Join(s.dataRoot, "bridge", "requests", requestID+".json")
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > maxRequestBytes {
		return value, "", errors.New("manifest unavailable")
	}
	file, err := os.Open(path)
	if err != nil {
		return value, "", err
	}
	defer file.Close()
	decoder := json.NewDecoder(io.LimitReader(file, maxRequestBytes))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&value); err != nil {
		return value, "", err
	}
	if value.SchemaVersion != 1 || value.RequestID != requestID || !validID(value.CaseID) || !validID(value.ArtifactID) {
		return value, "", errors.New("invalid manifest")
	}
	if value.ArtifactKind != "original" && value.ArtifactKind != "evidence_capture" {
		return value, "", errors.New("invalid artifact kind")
	}
	if !validFilter(value.DisplayFilter) {
		return value, "", errors.New("invalid display filter")
	}
	return value, path, nil
}

func (s *server) resolveArtifact(value manifest) (string, error) {
	if filepath.IsAbs(value.RelativePath) || strings.ContainsRune(value.RelativePath, '\x00') {
		return "", errors.New("absolute path")
	}
	clean := filepath.Clean(filepath.FromSlash(value.RelativePath))
	if clean == "." || clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return "", errors.New("path traversal")
	}
	candidate, err := filepath.Abs(filepath.Join(s.dataRoot, clean))
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(candidate)
	if err != nil {
		return "", err
	}
	relative, err := filepath.Rel(s.dataRoot, resolved)
	if err != nil || relative == ".." || strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
		return "", errors.New("path escape")
	}
	info, err := os.Stat(resolved)
	if err != nil || !info.Mode().IsRegular() {
		return "", errors.New("artifact unavailable")
	}
	file, err := os.Open(resolved)
	if err != nil {
		return "", err
	}
	defer file.Close()
	digest := sha256.New()
	if _, err := io.Copy(digest, io.LimitReader(file, 128*1024*1024+1)); err != nil {
		return "", err
	}
	if info.Size() > 128*1024*1024 || hex.EncodeToString(digest.Sum(nil)) != value.ArtifactSHA256 {
		return "", errors.New("artifact integrity")
	}
	return resolved, nil
}

func wiresharkCandidates(goos string, getenv func(string) string, lookPath func(string) (string, error), configured string) []string {
	if configured != "" {
		return []string{configured}
	}
	candidates := []string{}
	switch goos {
	case "darwin":
		candidates = append(candidates, "/Applications/Wireshark.app/Contents/MacOS/Wireshark")
	case "windows":
		if value := getenv("ProgramFiles"); value != "" {
			candidates = append(candidates, filepath.Join(value, "Wireshark", "Wireshark.exe"))
		}
		if value := getenv("ProgramFiles(x86)"); value != "" {
			candidates = append(candidates, filepath.Join(value, "Wireshark", "Wireshark.exe"))
		}
	default:
		if path, err := lookPath("wireshark"); err == nil {
			candidates = append(candidates, path)
		}
		candidates = append(candidates, "/usr/bin/wireshark", "/usr/local/bin/wireshark")
	}
	return candidates
}

func discoverWiresharkFor(goos string, getenv func(string) string, lookPath func(string) (string, error), configured string) (string, error) {
	for _, candidate := range wiresharkCandidates(goos, getenv, lookPath, configured) {
		absolute, err := filepath.Abs(candidate)
		if err != nil {
			continue
		}
		resolved, err := filepath.EvalSymlinks(absolute)
		if err != nil {
			continue
		}
		info, err := os.Stat(resolved)
		if err == nil && info.Mode().IsRegular() {
			return resolved, nil
		}
	}
	return "", fmt.Errorf("wireshark unavailable")
}
