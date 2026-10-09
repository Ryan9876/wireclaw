import { useState } from 'react';
import { ApiError, errorMessage, isRunning, revision } from './api';
import { Dialog } from './Dialog';
import { EvidenceDrawer } from './EvidenceDrawer';
import { Intake } from './Intake';
import { Progress } from './Progress';
import { ReportView } from './ReportView';
import { useCase } from './useCase';

export function App() {
  const investigation = useCase();
  const { id, record, report, busy, error, notice } = investigation;
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [evidenceView, setEvidenceView] = useState<{ report: typeof report; ids: string[] } | null>(
    null,
  );
  const [recoveryId, setRecoveryId] = useState('');
  const locked =
    busy ||
    (!!record &&
      (isRunning(record) ||
        ['INGESTING', 'VALIDATING_CAPTURE', 'ASSEMBLING_REPORT'].includes(record.state)));

  return (
    <>
      <a
        className="skip-link"
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          document.getElementById('main')?.focus();
        }}
      >
        Skip to investigation
      </a>
      <header className="app-header">
        <div className="brand">
          <span className="brand-mark" aria-hidden="true">
            W
          </span>
          <div>
            <strong>Wireclaw</strong>
            <span>Packet investigation</span>
          </div>
        </div>
        <div className="local-status">
          <span aria-hidden="true">◉</span> Local capture analysis{' '}
          <span className="separator">/</span> Rules-only
        </div>
      </header>
      <main id="main" tabIndex={-1}>
        <div className="page-heading">
          <div>
            <span className="eyebrow">Evidence before diagnosis</span>
            <h1>{id ? 'Capture investigation' : 'Investigate a network symptom'}</h1>
            <p className="muted">
              Deterministic packet facts. Traceable conclusions. Visible uncertainty.
            </p>
          </div>
          {id && (
            <button className="quiet" disabled={locked} onClick={investigation.newCase}>
              New case
            </button>
          )}
        </div>
        {notice && (
          <div className="notice" role="status">
            {notice}
          </div>
        )}
        {error && (
          <div className="error" role="alert">
            <p>{error}</p>
            {id && (
              <button disabled={busy} onClick={() => void investigation.refresh()}>
                Refresh status
              </button>
            )}
          </div>
        )}
        {!id && (
          <>
            <Intake busy={busy} onStart={investigation.start} />
            <details className="recovery panel">
              <summary>Recover an existing local case</summary>
              <p className="muted">
                Bookmark a case to return after reload. Or enter its logical case ID; no file path
                or URL is accepted.
              </p>
              <form
                onSubmit={(event) => {
                  event.preventDefault();
                  investigation.recover(recoveryId.trim());
                }}
              >
                <label htmlFor="recover-id">Case ID</label>
                <input
                  id="recover-id"
                  value={recoveryId}
                  onChange={(event) => setRecoveryId(event.target.value)}
                  maxLength={32}
                  placeholder="32-character case ID"
                />
                <button type="submit" disabled={busy}>
                  Recover case
                </button>
              </form>
            </details>
          </>
        )}
        {id && !record && !error && (
          <div className="panel">
            <p role="status">Recovering local case state…</p>
          </div>
        )}
        {record && (
          <>
            <section className="panel case-context" aria-labelledby="context-heading">
              <div className="section-heading">
                <h2 id="context-heading">Case context</h2>
                <button
                  className="danger quiet"
                  disabled={locked}
                  onClick={() => setDeleteId(record.id)}
                >
                  Delete case
                </button>
              </div>
              <p className="case-id">
                Case <code>{record.id}</code>
              </p>
              <p className="symptom">{record.symptom}</p>
              {record.capture_sha && (
                <details>
                  <summary>Immutable original capture</summary>
                  <p>
                    SHA-256 <code>{record.capture_sha}</code>
                  </p>
                  <p>The stored original is read-only. Your source file is unchanged.</p>
                </details>
              )}
            </section>
            {record.state !== 'COMPLETE' && <Progress record={record} />}
            {record.state === 'FAILED' && (
              <section className="panel failure" aria-labelledby="failure-heading">
                <h2 id="failure-heading">Investigation failed</h2>
                <p>{errorMessage(new ApiError(record.last_error ?? 'operation_failed'))}</p>
                <p className="error-code">
                  Backend error: <code>{record.last_error ?? 'unknown'}</code>
                </p>
                <p>
                  Prior evidence and any registered immutable capture remain available. This is an
                  execution failure, not an insufficient-evidence conclusion.
                </p>
              </section>
            )}
            {!record.original_id && !locked && ['NEW', 'FAILED'].includes(record.state) && (
              <Intake
                fixedSymptom={record.symptom}
                busy={locked}
                onStart={(file) => investigation.resumeUpload(file)}
              />
            )}
            {record.original_id &&
              !locked &&
              ['BASELINE_ANALYSIS', 'INVESTIGATING', 'FAILED'].includes(record.state) && (
                <div className="panel resume">
                  <p>
                    {record.state === 'FAILED'
                      ? 'Retry using the preserved original capture.'
                      : 'Capture intake is complete. Continue when ready; recovery never starts an investigation automatically.'}
                  </p>
                  <button className="primary" onClick={() => void investigation.investigate()}>
                    {record.state === 'FAILED' ? 'Retry investigation' : 'Continue investigation'}
                  </button>
                </div>
              )}
            {!busy && report && (
              <ReportView
                key={revision(record)}
                report={report}
                onEvidence={(ids) => {
                  if (ids.length) setEvidenceView({ report, ids });
                }}
              />
            )}
            {record.state === 'COMPLETE' && (
              <details className="panel">
                <summary>Investigation complete · inspect recorded lifecycle</summary>
                <Progress record={record} />
              </details>
            )}
            {record.state === 'COMPLETE' && !report && !error && (
              <p className="panel" role="status">
                Retrieving and verifying the current report…
              </p>
            )}
          </>
        )}
        {deleteId === id && record && (
          <Dialog
            title="Delete this case?"
            titleId="delete-title"
            closeDisabled={busy}
            onClose={() => {
              if (!busy) setDeleteId(null);
            }}
          >
            <p>
              Delete case <code>{record.id}</code>?
            </p>
            <blockquote>{record.symptom}</blockquote>
            <p>
              This removes the locally stored original capture, normalized evidence, and report.
              Your source file outside Wireclaw is unchanged. Deletion cannot be undone.
            </p>
            {error && (
              <p className="error" role="alert">
                {error}
              </p>
            )}
            <div className="button-row">
              <button
                autoFocus
                data-initial-focus
                disabled={busy}
                onClick={() => setDeleteId(null)}
              >
                Keep case
              </button>
              <button
                className="danger solid"
                disabled={busy}
                onClick={() => void investigation.remove()}
              >
                {busy ? 'Deleting…' : 'Delete case and stored files'}
              </button>
            </div>
          </Dialog>
        )}
        {evidenceView?.report === report && evidenceView && id && report && (
          <EvidenceDrawer
            caseId={id}
            ids={evidenceView.ids}
            onClose={() => setEvidenceView(null)}
          />
        )}
      </main>
      <footer className="app-footer">
        Local-first · No model provider · Evidence remains authoritative
      </footer>
    </>
  );
}
