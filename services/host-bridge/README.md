# Native Host Bridge

Gate 6 implements the native Go bridge used only to launch Wireshark with an approved Wireclaw capture artifact and backend-approved display filter.

## Trust boundary

The browser never supplies a filesystem path, executable, Wireshark argument list, or display filter to the bridge. The local API first validates the case/finding/artifact and writes a short-lived manifest under the shared data root. The browser receives only a random request ID and one-time token. The manifest stores only the SHA-256 of that token.

The bridge:

1. binds to loopback only;
2. accepts only the Wireclaw UI origins;
3. validates a bounded JSON request;
4. authenticates the one-time token in constant time;
5. resolves the API-created manifest beneath the configured data root;
6. rejects traversal and symlink escapes;
7. verifies the capture SHA-256 and approved artifact kind;
8. consumes the grant so it cannot be replayed;
9. launches the configured/discovered Wireshark executable with direct argv and no shell.

It has no generic command endpoint and cannot accept arbitrary executable names or CLI arguments.

## Run from source

```bash
cd services/host-bridge
go test ./...
go vet ./...
go build -o wireclaw-host-bridge .
./wireclaw-host-bridge --data-root ../../data
```

Optional administrator configuration:

```text
--listen 127.0.0.1:8766
--wireshark /approved/path/to/Wireshark
WIRECLAW_WIRESHARK_PATH=/approved/path/to/Wireshark
```

The listen address must be loopback. Caller requests cannot change the Wireshark path.

Platform discovery is isolated behind `discoverWireshark`: macOS checks the native application executable, Windows checks the standard Program Files locations, and Linux supports an administrator PATH plus standard locations. The resolved executable is canonicalized before use.

If the bridge or Wireshark is unavailable, the web report remains usable, both native-open actions stay visible but disabled, display-filter copy and packet evidence remain available, and the API can still create a focused evidence capture.
