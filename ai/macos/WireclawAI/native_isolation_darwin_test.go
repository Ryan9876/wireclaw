//go:build darwin && cgo

package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// TestNativeTask9Isolation exercises a disposable ad-hoc signed bundle. Run it
// only on macOS arm64 and outside the enclosing command sandbox.
func TestNativeTask9Isolation(t *testing.T) {
	if os.Getenv("WIRECLAW_NATIVE_TASK9") != "1" {
		t.Skip("opt-in native Task 9 sandbox probe")
	}
	if runtime.GOARCH != "arm64" {
		t.Fatal("native Task 9 qualification requires Apple Silicon")
	}
	stateDir, err := productionStateDir()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"api-key", "process.json", "runtime.log", "task9-probe.json", "task9-private-write"} {
		if _, err := os.Lstat(filepath.Join(stateDir, name)); err == nil {
			t.Skip("existing AI private state must not be disturbed")
		} else if !os.IsNotExist(err) {
			t.Fatalf("cannot preflight private output %s: %v", name, err)
		}
	}
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	support := filepath.Join(home, "Library", "Application Support", "Wireclaw")
	if err := os.MkdirAll(support, 0700); err != nil {
		t.Fatal(err)
	}
	testSupport, err := os.MkdirTemp(support, "task9-native-")
	if err != nil {
		t.Fatal(err)
	}
	helperStarted, cleanupComplete := false, false
	defer func() {
		if !helperStarted || cleanupComplete {
			_ = os.RemoveAll(testSupport)
		}
	}()
	for _, d := range []string{"cases/example", "state", "bridge-state", "run"} {
		if err := os.MkdirAll(filepath.Join(testSupport, d), 0700); err != nil {
			t.Fatal(err)
		}
	}
	dataPath := filepath.Join(testSupport, "cases/example/case.sqlite")
	statePath := filepath.Join(testSupport, "state/private.json")
	bridgePath := filepath.Join(testSupport, "bridge-state/token")
	receipt := filepath.Join(testSupport, "run/ai-host-receipt.json")
	for path, data := range map[string]string{dataPath: "case-fixture", statePath: "host-state-fixture", bridgePath: "bridge-state-fixture", receipt: "host-receipt-fixture\n"} {
		if err := os.WriteFile(path, []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}

	dockerPaths := []string{"/var/run/docker.sock", filepath.Join(home, ".docker/run/docker.sock")}
	dockerPresent := make([]bool, len(dockerPaths))
	dockerNotRun := make([]string, len(dockerPaths))
	for i, path := range dockerPaths {
		_, statErr := os.Stat(path)
		if statErr != nil && !os.IsNotExist(statErr) {
			t.Fatalf("cannot classify Docker Desktop socket path %s: %v", path, statErr)
		}
		if os.IsNotExist(statErr) {
			dockerNotRun[i] = "absent"
		} else {
			// Confirm the path is a live socket without sending any protocol data.
			// Stale socket files are NOT_RUN, not evidence of sandbox denial.
			conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
			if dialErr == nil {
				dockerPresent[i] = true
				_ = conn.Close()
			} else {
				dockerNotRun[i] = "endpoint unavailable"
			}
		}
	}

	root, self := fixtureBundle(t)
	info, err := os.ReadFile("../Info.plist")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "Contents/Info.plist"), info, 0600); err != nil {
		t.Fatal(err)
	}
	run := func(argv ...string) []byte {
		t.Helper()
		cmd := exec.Command(argv[0], argv[1:]...)
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("%s failed: %v", argv[0], err)
		}
		return out
	}
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(self); err != nil {
		t.Fatal(err)
	}
	run(goTool, "build", "-o", self, ".")
	helper := filepath.Join(root, "Contents/MacOS/llama-server")
	model := filepath.Join(root, "Contents/Resources/ai/model.gguf")
	if err := os.Remove(helper); err != nil {
		t.Fatal(err)
	}
	probeSource := filepath.Join(filepath.Dir(root), "sandbox-probe.c")
	probe := fmt.Sprintf(nativeIsolationProbe, cString(filepath.Join(stateDir, "api-key")), cString(model), cString(helper), cString(dockerPaths[0]), cString(dockerPaths[1]), cString(dataPath), cString(statePath), cString(bridgePath), cString(receipt), cString(receipt))
	if err := os.WriteFile(probeSource, []byte(probe), 0600); err != nil {
		t.Fatal(err)
	}
	run("/usr/bin/clang", probeSource, "-o", helper)
	library := filepath.Join(root, "Contents/Frameworks/libggml-metal.dylib")
	if err := os.Remove(library); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(probeSource, []byte("int wireclaw_fixture(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	run("/usr/bin/clang", "-dynamiclib", probeSource, "-o", library)
	run("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "llama-server", "--entitlements", "../helper.entitlements.plist", helper)
	run("/usr/bin/codesign", "--force", "--sign", "-", "--identifier", "libggml-metal.dylib", library)
	mutateManifest(t, root, "runtime", func(v map[string]any) {
		for _, item := range v["files"].([]any) {
			r := item.(map[string]any)
			rel, _ := runtimeLocation(r["path"].(string))
			b, e := os.ReadFile(filepath.Join(root, "Contents", rel))
			if e != nil {
				t.Fatal(e)
			}
			sum := sha256.Sum256(b)
			r["sha256"], r["size_bytes"] = hex.EncodeToString(sum[:]), len(b)
		}
	})
	run("/usr/bin/codesign", "--force", "--sign", "-", "--entitlements", "../parent.entitlements.plist", root)
	run("/usr/bin/codesign", "--verify", "--deep", "--strict", "--verbose=4", root)
	assertSignedEntitlements(t, helper, map[string]any{"com.apple.security.app-sandbox": true, "com.apple.security.inherit": true})
	assertSignedEntitlements(t, root, map[string]any{"com.apple.security.app-sandbox": true, "com.apple.security.network.server": true})
	if _, err := verifyBundleAt(root, self, permitSignature); err != nil {
		t.Fatalf("fixture bundle: %v", err)
	}
	for _, target := range []struct{ path, role string }{{helper, "helper"}, {library, "library"}} {
		if err := verifyCodeSignature(target.path, target.role); err != nil {
			t.Fatalf("%s signature: %v", target.role, err)
		}
	}

	key := strings.Repeat("b", 64)
	keyReader, keyWriter, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := keyWriter.Write([]byte(key + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = keyWriter.Close()
	start := exec.Command(self, "start")
	start.ExtraFiles = []*os.File{keyReader}
	startOutput, startErr := start.CombinedOutput()
	_ = keyReader.Close()
	if startErr != nil {
		t.Fatalf("signed start: %v", startErr)
	}
	helperStarted = true
	hostTool := filepath.Join("..", "..", "..", "launch", "macos", "ai_lifecycle.py")
	defer func() {
		if cleanupComplete {
			return
		}
		ok := cleanupNativeIsolationFixture(nativeIsolationCleanupOps{
			status: func() ([]byte, error) { return exec.Command(self, "status").Output() },
			recover: func(status []byte) error {
				cmd := exec.Command("/usr/bin/python3", hostTool, "recover", receipt, helper)
				cmd.Stdin = bytes.NewReader(status)
				if _, err := cmd.CombinedOutput(); err != nil {
					return errors.New("trusted recovery failed")
				}
				return nil
			},
			hostStop: func() error {
				if _, err := exec.Command("/usr/bin/python3", hostTool, "stop", receipt, helper).CombinedOutput(); err != nil {
					return errors.New("verified host stop failed")
				}
				return nil
			},
			wrapperStop: func() error {
				if _, err := exec.Command(self, "stop").CombinedOutput(); err != nil {
					return errors.New("wrapper cleanup failed")
				}
				return nil
			},
			removeReceipt: func() error {
				if _, err := exec.Command("/usr/bin/python3", hostTool, "remove", receipt, helper).CombinedOutput(); err != nil {
					return errors.New("host receipt removal failed")
				}
				return nil
			},
			privateStateRemoved: func() bool {
				for _, name := range []string{"api-key", "process.json"} {
					if _, err := os.Lstat(filepath.Join(stateDir, name)); !os.IsNotExist(err) {
						return false
					}
				}
				for _, name := range []string{"runtime.log", "task9-probe.json", "task9-private-write"} {
					path := filepath.Join(stateDir, name)
					if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
						return false
					}
				}
				return true
			},
			removeFixture: func() error { return os.RemoveAll(testSupport) },
			preserve: func(reason string) {
				t.Errorf("native helper cleanup incomplete (%s); preserving receipt and fixture at %s", reason, testSupport)
			},
		})
		if ok {
			cleanupComplete = true
		}
	}()
	if len(startOutput) > 1024 || bytes.Contains(startOutput, []byte(key)) {
		t.Fatalf("unbounded or secret-bearing start output")
	}
	var started map[string]any
	if err := json.Unmarshal(startOutput, &started); err != nil || started["state"] != "running" {
		t.Fatalf("start receipt malformed or unavailable")
	}
	pid := int(started["pid"].(float64))
	probeResult := filepath.Join(stateDir, "task9-probe.json")
	var result []byte
	for i := 0; i < 50; i++ {
		result, _ = os.ReadFile(probeResult)
		if len(result) > 0 {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	var evidence map[string]json.RawMessage
	if err := json.Unmarshal(result, &evidence); err != nil {
		t.Fatalf("native probe evidence unavailable: %v", err)
	}
	for i, name := range []string{"docker_var_run_errno", "docker_desktop_errno"} {
		var errno int
		if err := json.Unmarshal(evidence[name], &errno); err != nil {
			t.Fatalf("Docker socket result unavailable: %s", name)
		}
		if dockerPresent[i] {
			if syscall.Errno(errno) != syscall.EPERM && syscall.Errno(errno) != syscall.EACCES {
				t.Errorf("discovered Docker socket was not sandbox-denied: %s errno=%d", name, errno)
			} else {
				t.Logf("%s: DENIED errno=%d", dockerPaths[i], errno)
			}
		} else if errno != 0 {
			t.Logf("%s: NOT_RUN (%s; helper errno=%d)", dockerPaths[i], dockerNotRun[i], errno)
		} else {
			t.Errorf("%s: helper connected although host preflight did not find a live socket", dockerPaths[i])
		}
	}
	for _, name := range []string{"wireclaw_data_errno", "wireclaw_state_errno", "bridge_state_errno", "host_receipt_read_errno", "host_receipt_write_errno", "core_outbound_errno", "bridge_outbound_errno", "arbitrary_outbound_errno"} {
		var errno int
		if err := json.Unmarshal(evidence[name], &errno); err != nil || (syscall.Errno(errno) != syscall.EPERM && syscall.Errno(errno) != syscall.EACCES) {
			t.Errorf("sandbox denial is inconclusive for %s: errno=%d", name, errno)
		} else {
			t.Logf("%s: DENIED errno=%d", name, errno)
		}
	}
	for _, name := range []string{"model_read_allowed", "runtime_read_allowed", "private_key_read_allowed", "private_write_allowed", "loopback_bind_allowed"} {
		var allowed bool
		if err := json.Unmarshal(evidence[name], &allowed); err != nil || !allowed {
			t.Errorf("native sandbox positive boundary failed: %s", name)
		}
	}
	if bytes.Contains(result, []byte(key)) || len(result) > 1024 {
		t.Fatal("native probe evidence leaks key or exceeds bound")
	}
	if runtimeLog, err := os.ReadFile(filepath.Join(stateDir, "runtime.log")); err != nil || bytes.Contains(runtimeLog, []byte(key)) {
		t.Fatal("sandbox runtime log is missing or contains the launch key")
	}
	if privateState, err := os.ReadFile(filepath.Join(stateDir, "process.json")); err != nil || bytes.Contains(privateState, []byte(key)) {
		t.Fatal("sandbox lifecycle state is missing or contains the launch key")
	}
	fixtureBytes := map[string]string{dataPath: "case-fixture", statePath: "host-state-fixture", bridgePath: "bridge-state-fixture", receipt: "host-receipt-fixture\n"}
	for path, expected := range fixtureBytes {
		b, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("host fixture changed or disappeared: %s", filepath.Base(path))
		}
		if string(b) != expected {
			t.Fatalf("host fixture bytes changed: %s", filepath.Base(path))
		}
		if strings.Contains(string(b), key) {
			t.Fatal("host fixture contains launch key")
		}
	}
	privateTemp := filepath.Join(stateDir, "task9-private-write")
	privateTempInfo, err := os.Stat(privateTemp)
	privateTempBytes, readErr := os.ReadFile(privateTemp)
	if err != nil || readErr != nil || privateTempInfo.Mode().Perm() != 0600 || privateTempInfo.Size() != 2 || string(privateTempBytes) != "ok" {
		t.Fatal("bounded write to sandbox-private TMPDIR was not verified")
	}
	if b, _ := os.ReadFile(receipt); string(b) != "host-receipt-fixture\n" {
		t.Fatal("sandbox modified host lifecycle receipt")
	}

	// A real inbound request must reach the helper's fixed numeric loopback listener.
	conn, err := net.DialTimeout("tcp4", "127.0.0.1:8767", time.Second)
	if err != nil {
		t.Fatalf("inbound Core request could not reach expected listener: %v", err)
	}
	_, _ = conn.Write([]byte("GET /v1/models HTTP/1.0\r\n\r\n"))
	response := make([]byte, 128)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	n, _ := conn.Read(response)
	_ = conn.Close()
	if !bytes.Contains(response[:n], []byte("200 OK")) {
		t.Fatal("inbound Core request did not receive bounded fixture response")
	}
	listeners := run("/usr/sbin/lsof", "-nP", "-a", "-p", fmt.Sprint(pid), "-iTCP", "-sTCP:LISTEN")
	listenerText := string(listeners)
	listenerRows := strings.Split(strings.TrimSpace(listenerText), "\n")
	if len(listenerRows) != 2 || !strings.Contains(listenerText, "127.0.0.1:8767") || strings.Contains(listenerText, "*:8767") || strings.Contains(listenerText, "[::]:8767") {
		t.Fatal("listener is not restricted to numeric IPv4 loopback")
	}
	if !bytes.Contains(startOutput, []byte("\"executable\"")) {
		t.Fatal("start did not return bounded identity receipt")
	}

	// Corroborate EPERM/EACCES observations with this helper's own sandbox deny log.
	// Unified log access is not required for the result: this account may not
	// have local log-store rights. The signed entitlement dictionary and each
	// operation's observed EPERM/EACCES provide the classification. No probe
	// targets vmnetd or sends any protocol bytes.

	status := exec.Command(self, "status")
	statusOutput, statusErr := status.CombinedOutput()
	if statusErr != nil || len(statusOutput) > 1024 || bytes.Contains(statusOutput, []byte(key)) {
		t.Fatal("fresh status is not bounded and secret-free")
	}
	var tampered map[string]any
	if err := json.Unmarshal(statusOutput, &tampered); err != nil {
		t.Fatal("status identity receipt is malformed")
	}
	tampered["pid"] = os.Getpid()
	tamperedStatus, _ := json.Marshal(tampered)
	untrustedReceipt := receipt + ".recovery"
	recover := exec.Command("/usr/bin/python3", hostTool, "recover", untrustedReceipt, helper)
	recover.Stdin = bytes.NewReader(tamperedStatus)
	if _, err := recover.CombinedOutput(); err == nil {
		t.Fatal("runtime-controlled status selected an unrelated host signal target")
	}
	if _, err := os.Lstat(untrustedReceipt); !os.IsNotExist(err) {
		t.Fatal("unverified recovery created an authoritative receipt")
	}
	if b, _ := os.ReadFile(receipt); string(b) != "host-receipt-fixture\n" {
		t.Fatal("unverified recovery modified authoritative host receipt")
	}
	if err := os.Remove(receipt); err != nil {
		t.Fatal("could not replace disposable fixture receipt")
	}
	create := exec.Command("/usr/bin/python3", hostTool, "create", receipt, helper)
	create.Stdin = bytes.NewReader(statusOutput)
	if _, err := create.CombinedOutput(); err != nil {
		t.Fatalf("trusted host receipt create: %v", err)
	}
	receiptInfo, err := os.Stat(receipt)
	if err != nil || receiptInfo.Mode().Perm() != 0600 {
		t.Fatal("trusted host receipt is not mode 0600")
	}
	if b, _ := os.ReadFile(receipt); bytes.Contains(b, []byte(key)) {
		t.Fatal("host receipt contains launch key")
	}
	stop := exec.Command("/usr/bin/python3", hostTool, "stop", receipt, helper)
	if _, err := stop.CombinedOutput(); err != nil {
		t.Fatalf("independently verified helper stop failed: %v", err)
	}
	cleanup := exec.Command(self, "stop")
	cleanupOutput, err := cleanup.CombinedOutput()
	if err != nil || bytes.Contains(cleanupOutput, []byte(key)) {
		t.Fatal("wrapper cleanup failed or leaked key")
	}
	remove := exec.Command("/usr/bin/python3", hostTool, "remove", receipt, helper)
	if _, err := remove.CombinedOutput(); err != nil {
		t.Fatalf("host receipt removal failed: %v", err)
	}
	for _, path := range []string{filepath.Join(stateDir, "api-key"), filepath.Join(stateDir, "process.json")} {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Fatalf("private lifecycle material remains: %s", filepath.Base(path))
		}
	}
	for _, name := range []string{"runtime.log", "task9-probe.json", "task9-private-write"} {
		if err := os.Remove(filepath.Join(stateDir, name)); err != nil && !os.IsNotExist(err) {
			t.Fatalf("private test artifact cleanup failed: %s", filepath.Base(name))
		}
	}
	if _, err := processIdentityForPID(pid); !errors.Is(err, errProcessMissing) {
		t.Fatal("trusted host receipt removal did not confirm the exact helper PID is absent")
	}
	cleanupComplete = true
}

func cString(value string) string { return fmt.Sprintf("%q", value) }

type nativeIsolationCleanupOps struct {
	status              func() ([]byte, error)
	recover             func([]byte) error
	hostStop            func() error
	wrapperStop         func() error
	removeReceipt       func() error
	privateStateRemoved func() bool
	removeFixture       func() error
	preserve            func(reason string)
}

// cleanupNativeIsolationFixture deletes test state only after recovery,
// identity-verified host stop, wrapper cleanup, and host receipt removal all
// succeed. Receipt removal independently confirms the managed PID is absent.
func cleanupNativeIsolationFixture(ops nativeIsolationCleanupOps) bool {
	preserve := func(reason string) bool {
		ops.preserve(reason)
		return false
	}
	status, err := ops.status()
	if err != nil {
		return preserve("status unavailable")
	}
	if err := ops.recover(status); err != nil {
		return preserve("trusted recovery failed")
	}
	if err := ops.hostStop(); err != nil {
		return preserve("verified host stop failed")
	}
	if err := ops.wrapperStop(); err != nil {
		return preserve("wrapper cleanup failed")
	}
	if err := ops.removeReceipt(); err != nil {
		return preserve("host receipt removal did not confirm exit")
	}
	if !ops.privateStateRemoved() {
		return preserve("private lifecycle cleanup incomplete")
	}
	if err := ops.removeFixture(); err != nil {
		return preserve("fixture cleanup failed")
	}
	return true
}

func assertSignedEntitlements(t *testing.T, path string, expected map[string]any) {
	t.Helper()
	cmd := exec.Command("/usr/bin/codesign", "-d", "--entitlements", ":-", path)
	data, err := cmd.Output()
	if err != nil {
		t.Fatalf("signed entitlement inspection failed")
	}
	plutil := exec.Command("/usr/bin/plutil", "-convert", "json", "-o", "-", "-")
	plutil.Stdin = bytes.NewReader(data)
	jsonData, err := plutil.Output()
	if err != nil {
		t.Fatalf("signed entitlement plist is invalid")
	}
	var actual map[string]any
	if err := json.Unmarshal(jsonData, &actual); err != nil {
		t.Fatalf("signed entitlements are not JSON-decodable")
	}
	if len(actual) != len(expected) {
		t.Fatalf("signed entitlements are broader or incomplete")
	}
	for key, value := range expected {
		if actual[key] != value {
			t.Fatalf("signed entitlement mismatch: %s", key)
		}
	}
	if _, ok := actual["com.apple.security.network.client"]; ok {
		t.Fatal("signed code has forbidden network.client")
	}
}

const nativeIsolationProbe = `#include <errno.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
static int denied_read(const char *p){errno=0;int f=open(p,O_RDONLY);if(f>=0){close(f);return 0;}return errno;}
static int denied_write(const char *p){errno=0;int f=open(p,O_WRONLY|O_TRUNC);if(f>=0){close(f);return 0;}return errno;}
static int denied_unix(const char *p){int s=socket(AF_UNIX,SOCK_STREAM,0);if(s<0)return errno;struct sockaddr_un a={0};a.sun_family=AF_UNIX;snprintf(a.sun_path,sizeof(a.sun_path),"%%s",p);int r=connect(s,(struct sockaddr*)&a,sizeof(a));int e=errno;close(s);return r<0?e:0;}
static int denied_tcp(const char *ip,int port){int s=socket(AF_INET,SOCK_STREAM,0);if(s<0)return errno;struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(port);inet_pton(AF_INET,ip,&a.sin_addr);int r=connect(s,(struct sockaddr*)&a,sizeof(a));int e=errno;close(s);return r<0?e:0;}
static int readable(const char *p){int f=open(p,O_RDONLY);if(f<0)return 0;char b[8];int n=read(f,b,sizeof(b));close(f);return n>0;}
static int writable_private_tmp(void){char p[4096];snprintf(p,sizeof(p),"%%s/task9-private-write",getenv("TMPDIR"));int f=open(p,O_CREAT|O_TRUNC|O_WRONLY,0600);if(f<0)return 0;int ok=write(f,"ok",2)==2;close(f);return ok;}
int main(void){
 int s=socket(AF_INET,SOCK_STREAM,0);if(s<0)return 10;int one=1;setsockopt(s,SOL_SOCKET,SO_REUSEADDR,&one,sizeof(one));struct sockaddr_in a={0};a.sin_family=AF_INET;a.sin_port=htons(8767);inet_pton(AF_INET,"127.0.0.1",&a.sin_addr);if(bind(s,(struct sockaddr*)&a,sizeof(a))||listen(s,2))return 11;
	int key=readable(%s);int model=readable(%s);int runtime=readable(%s);
	 int values[]={denied_unix(%s),denied_unix(%s),denied_read(%s),denied_read(%s),denied_read(%s),denied_read(%s),denied_write(%s),denied_tcp("127.0.0.1",8767),denied_tcp("127.0.0.1",8766),denied_tcp("192.0.2.1",9),key,model,runtime,writable_private_tmp(),1};
	 const char *names[]={"docker_var_run_errno","docker_desktop_errno","wireclaw_data_errno","wireclaw_state_errno","bridge_state_errno","host_receipt_read_errno","host_receipt_write_errno","core_outbound_errno","bridge_outbound_errno","arbitrary_outbound_errno","private_key_read_allowed","model_read_allowed","runtime_read_allowed","private_write_allowed","loopback_bind_allowed"};
	 char out[1024];size_t n=0;n+=(size_t)snprintf(out+n,sizeof(out)-n,"{");for(int i=0;i<15;i++){if(i<10)n+=(size_t)snprintf(out+n,sizeof(out)-n,"%%s\"%%s\":%%d",i?",":"",names[i],values[i]);else n+=(size_t)snprintf(out+n,sizeof(out)-n,"%%s\"%%s\":%%s",i?",":"",names[i],values[i]?"true":"false");}snprintf(out+n,sizeof(out)-n,"}\n");
 char path[4096];snprintf(path,sizeof(path),"%%s/task9-probe.json",getenv("HOME"));int f=open(path,O_CREAT|O_TRUNC|O_WRONLY,0600);if(f<0)return 12;write(f,out,strlen(out));close(f);
 int c=accept(s,NULL,NULL);if(c>=0){char request[256];(void)read(c,request,sizeof(request));const char response[]="HTTP/1.0 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";(void)write(c,response,sizeof(response)-1);close(c);}for(;;)pause();
}`
