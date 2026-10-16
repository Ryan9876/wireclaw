package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
)

const (
	modelIdentity            = "wireclaw-qwen3-4b-instruct-2507-q4_k_m"
	modelRevision            = "cdbee75f17c01a7cc42f958dc650907174af0554"
	modelArtifact            = "models/qwen3-4b-instruct-2507-q4_k_m.gguf"
	runtimeRevision          = "8345f333951c661d166b00e6f9362e553768f292"
	runtimeTagRevision       = "d81235049384534c167caea52b85a694f6103d14"
	maxModelBytes      int64 = 3758096384
	maxRuntimeBytes    int64 = 512 << 20
	maxManifestBytes   int64 = 1 << 20
	pinnedPolicy             = `{"platform":"macos","architecture":"arm64","listen_host":"127.0.0.1","context_size":16384,"max_tokens":2048,"parallel":1,"prompt_cache_ram_mib":0,"port":8767,"model_alias":"wireclaw-qwen3-4b-instruct-2507-q4_k_m","authentication_required":true,"agent_tools":false,"web_ui":false,"network_downloads":false,"batch_size":128,"micro_batch_size":32}`
)

var errBundleVerification = errors.New("bundle verification failed")
var libraryName = regexp.MustCompile(`^lib[A-Za-z0-9_-]+(?:\.[0-9]+)*\.dylib$`)

// VerifiedBundle is constructed only after the signed bundle and all pinned
// resources pass verification. Launch accepts this value, never caller paths.
// Fields remain private; the zero value must never authorize launch.
type VerifiedBundle struct {
	root       string
	helperPath string
	modelPath  string
	modelID    string
}

type fileRecord struct {
	Path   string `json:"path"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size_bytes"`
}
type modelManifest struct {
	Schema       int    `json:"schema_version"`
	Bundle       string `json:"bundle_identifier"`
	ID           string `json:"model_id"`
	Repository   string `json:"repository"`
	Revision     string `json:"revision"`
	License      string `json:"license"`
	Quantization string `json:"quantization"`
	Architecture string `json:"architecture"`
	Validation   struct {
		Field  string `json:"metadata_field"`
		Reader string `json:"reader"`
	} `json:"architecture_validation"`
	Artifact    fileRecord   `json:"artifact"`
	Sources     []fileRecord `json:"source_files"`
	LicensePath string       `json:"license_path"`
}
type runtimeManifest struct {
	Schema       int    `json:"schema_version"`
	Bundle       string `json:"bundle_identifier"`
	Repository   string `json:"repository"`
	Revision     string `json:"revision"`
	Tag          string `json:"tag"`
	TagCommit    string `json:"tag_commit"`
	Platform     string `json:"platform"`
	Architecture string `json:"architecture"`
	Build        struct {
		Metal  bool   `json:"metal"`
		Server bool   `json:"server"`
		Cmake  string `json:"cmake_version"`
	} `json:"build_settings"`
	Entrypoint string          `json:"entrypoint"`
	Files      []fileRecord    `json:"files"`
	Licenses   []string        `json:"license_paths"`
	Policy     json.RawMessage `json:"policy"`
}

func verifyBundle() (VerifiedBundle, error) {
	self, err := os.Executable()
	if err != nil {
		return VerifiedBundle{}, errBundleVerification
	}
	root := filepath.Dir(filepath.Dir(filepath.Dir(self)))
	return verifyBundleAt(root, self, verifyCodeSignature)
}

// verifyBundleAt is the internal test seam. Production derives the app from
// its own executable and always uses Security.framework, with no CLI override.
func verifyBundleAt(root, self string, signature func(string, string) error) (VerifiedBundle, error) {
	bad := func() (VerifiedBundle, error) { return VerifiedBundle{}, errBundleVerification }
	if !filepath.IsAbs(root) || filepath.Clean(root) != root || filepath.Base(root) != "WireclawAI.app" || self != filepath.Join(root, "Contents/MacOS/WireclawAI") {
		return bad()
	}
	// Reject path redirection instead of resolving it to an alternate bundle.
	for p := root; p != filepath.Dir(p); p = filepath.Dir(p) {
		info, err := os.Lstat(p)
		if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return bad()
		}
	}
	entries := 0
	if err := filepath.WalkDir(root, func(_ string, d fs.DirEntry, err error) error {
		entries++
		if err != nil || entries > 512 || d.Type()&os.ModeSymlink != 0 || (!d.IsDir() && !d.Type().IsRegular()) {
			return errBundleVerification
		}
		return nil
	}); err != nil {
		return bad()
	}
	if signature(root, "app") != nil {
		return bad()
	}
	contents := filepath.Join(root, "Contents")
	ai := filepath.Join(contents, "Resources/ai")
	var model modelManifest
	var runtime runtimeManifest
	if readManifest(filepath.Join(ai, "model-manifest.json"), &model) != nil || readManifest(filepath.Join(ai, "runtime-manifest.json"), &runtime) != nil {
		return bad()
	}
	if model.Schema != 1 ||
		model.Bundle != bundleID ||
		model.ID != modelIdentity ||
		model.Repository != "Qwen/Qwen3-4B-Instruct-2507" ||
		model.Revision != modelRevision ||
		model.License != "Apache-2.0" ||
		model.Quantization != "Q4_K_M" ||
		model.Architecture != "qwen3" ||
		model.Validation.Field != "general.architecture" ||
		model.Validation.Reader != "gguf-py from pinned llama.cpp source" ||
		model.Artifact.Path != modelArtifact ||
		model.LicensePath != "licenses/Qwen-Apache-2.0.txt" ||
		len(model.Sources) == 0 {
		return bad()
	}
	for _, source := range model.Sources {
		if !safeRelative(source.Path) || !validDigest(source.SHA256) || source.Size < 0 {
			return bad()
		}
	}
	if runtime.Schema != 1 ||
		runtime.Bundle != bundleID ||
		runtime.Repository != "ggml-org/llama.cpp" ||
		runtime.Revision != runtimeRevision ||
		runtime.Tag != "v0.6.0" ||
		runtime.TagCommit != runtimeTagRevision ||
		runtime.Platform != "macos" ||
		runtime.Architecture != "arm64" ||
		!runtime.Build.Metal ||
		!runtime.Build.Server ||
		runtime.Build.Cmake == "" ||
		runtime.Entrypoint != "macos-arm64/llama-server" ||
		len(runtime.Files) < 2 ||
		len(runtime.Files) > 128 ||
		!reflect.DeepEqual(runtime.Licenses, []string{"licenses/llama.cpp-MIT.txt"}) ||
		!policyMatches(runtime.Policy) {
		return bad()
	}
	allowed := map[string]bool{
		"Info.plist":                              true,
		"MacOS/WireclawAI":                        true,
		"_CodeSignature/CodeResources":            true,
		"Resources/ai/model-manifest.json":        true,
		"Resources/ai/runtime-manifest.json":      true,
		"Resources/ai/model.gguf":                 true,
		"Resources/ai/" + model.LicensePath:       true,
		"Resources/ai/licenses/llama.cpp-MIT.txt": true,
	}
	codeFiles := map[string]bool{"MacOS/WireclawAI": true}
	seen := map[string]bool{}
	for _, record := range runtime.Files {
		relative, role := runtimeLocation(record.Path)
		if relative == "" || seen[record.Path] {
			return bad()
		}
		seen[record.Path] = true
		allowed[relative] = true
		codeFiles[relative] = true
		path := filepath.Join(contents, relative)
		if signature(path, role) != nil || verifyRecord(path, record, maxRuntimeBytes) != nil {
			return bad()
		}
	}
	if !seen["macos-arm64/llama-server"] || !seen["macos-arm64/libggml-metal.dylib"] {
		return bad()
	}
	modelPath := filepath.Join(ai, "model.gguf")
	if verifyRecord(modelPath, model.Artifact, maxModelBytes) != nil {
		return bad()
	}
	for _, license := range []string{model.LicensePath, runtime.Licenses[0]} {
		info, err := os.Stat(filepath.Join(ai, license))
		if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManifestBytes {
			return bad()
		}
	}
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		relative, err := filepath.Rel(contents, path)
		if err != nil || !allowed[relative] {
			return errBundleVerification
		}
		info, err := d.Info()
		if err != nil || !info.Mode().IsRegular() || (!codeFiles[relative] && info.Mode().Perm()&0111 != 0) {
			return errBundleVerification
		}
		return nil
	}); err != nil {
		return bad()
	}
	helper := filepath.Join(contents, "MacOS/llama-server")
	for _, path := range []string{self, helper} {
		info, err := os.Stat(path)
		if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0111 == 0 {
			return bad()
		}
	}
	return VerifiedBundle{root: root, helperPath: helper, modelPath: modelPath, modelID: modelIdentity}, nil
}

func runtimeLocation(path string) (string, string) {
	if path == "macos-arm64/llama-server" {
		return "MacOS/llama-server", "helper"
	}
	name := strings.TrimPrefix(path, "macos-arm64/")
	if path == "macos-arm64/"+name && libraryName.MatchString(name) {
		return "Frameworks/" + name, "library"
	}
	return "", ""
}
func safeRelative(path string) bool {
	return path != "" && !filepath.IsAbs(path) && filepath.Clean(path) == path && path != "." && path != ".." && !strings.HasPrefix(path, "../") && !strings.ContainsAny(path, "\\\x00")
}
func validDigest(value string) bool {
	data, err := hex.DecodeString(value)
	return err == nil && len(data) == sha256.Size && strings.ToLower(value) == value
}
func verifyRecord(path string, record fileRecord, limit int64) error {
	if record.Size <= 0 || record.Size > limit || !validDigest(record.SHA256) {
		return errBundleVerification
	}
	file, err := os.Open(path)
	if err != nil {
		return errBundleVerification
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() != record.Size {
		return errBundleVerification
	}
	digest := sha256.New()
	n, err := io.Copy(digest, io.LimitReader(file, record.Size+1))
	if err != nil || n != record.Size || hex.EncodeToString(digest.Sum(nil)) != record.SHA256 {
		return errBundleVerification
	}
	return nil
}
func readManifest(path string, value any) error {
	file, err := os.Open(path)
	if err != nil {
		return errBundleVerification
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maxManifestBytes {
		return errBundleVerification
	}
	data, err := io.ReadAll(io.LimitReader(file, maxManifestBytes+1))
	if err != nil || int64(len(data)) > maxManifestBytes || json.Unmarshal(data, value) != nil {
		return errBundleVerification
	}
	return nil
}
func policyMatches(data []byte) bool {
	decode := func(b []byte) any {
		var v any
		d := json.NewDecoder(bytes.NewReader(b))
		d.UseNumber()
		if d.Decode(&v) != nil {
			return nil
		}
		return v
	}
	return reflect.DeepEqual(decode(data), decode([]byte(pinnedPolicy)))
}
