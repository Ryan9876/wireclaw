# Local web workflow

React/TypeScript presents the existing local API's capture, symptom, progress,
report, evidence and deletion workflow. It never invokes analyzers or providers.
The compiled UI is served on the API's loopback origin; no separate frontend
server, proxy, remote API URL or browser storage of packet data is required.

## Run from a checkout

Install Python 3.12+, Node 24+, and the packet tools described in
[the analyzer instructions](../../services/analyzer/README.md). From the repository root:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[test]'
npm ci --prefix apps/web
npm run build --prefix apps/web
python -m wireclaw_api.cli --data-root data
```

Open `http://127.0.0.1:8765/`. On Windows, activate with
`.venv\Scripts\Activate.ps1`; the remaining commands are the same. Native Windows
and macOS browser execution has not been verified for this gate.

Select/drop one capture, describe the symptom, and select **Investigate capture**.
Case creation is implicit. Bookmark the case URL to recover persisted state after
reload. Recovered idle/failed cases require an explicit continue/retry action.
Deletion identifies the case and its stored files before confirmation, and reports
pending cleanup accurately. The source file outside Wireclaw is unchanged.

Both Wireshark actions are visible on applicable findings and disabled with an
explanation until Gate 6. No bridge or extraction endpoint is simulated.

For local edits, run `npm run build:watch --prefix apps/web` beside the API process.
The API serves the updated production assets. Production serving requires the build;
missing assets do not fall back to exposing repository files.

## Verify

```bash
npm run lint --prefix apps/web
npm run format:check --prefix apps/web
npm run build --prefix apps/web
npm test --prefix apps/web
python scripts/prepare_web_fixtures.py
cd apps/web
npx playwright install chromium
npm run test:e2e
```

Activate the Python environment and keep real TShark/capinfos on PATH when running
browser tests. The fixture command generates ignored PCAPs and refreshes committed
normalized API fixtures using real tools. Browser tests start the real API with a
separate ignored data root; they use the compiled production bundle, not mocks.
`WIRECLAW_BROWSER_PATH` can select an existing compatible Chromium executable.

`npm run contracts` regenerates TypeScript contracts and CSP-compatible standalone
validators from `contracts/`; do not hand-edit generated files. The application
rejects incompatible responses, foreign case IDs and evidence IDs rather than
rendering unvalidated diagnostic data. Reports publish only between matching
COMPLETE case snapshots and disappear on revision, run or connectivity changes.

See [Gate 5 verification](../../docs/gate5-verification.md) for evidence and limits.
