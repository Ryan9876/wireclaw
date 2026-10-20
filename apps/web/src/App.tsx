import { useEffect, useState } from 'react';
import {
  aiStatusLabel,
  ApiError,
  api,
  errorMessage,
  isRunning,
  revision,
  type AIStatus,
} from './api';
import { Conversation } from './Conversation';
import { Dialog } from './Dialog';
import { EvidenceDrawer } from './EvidenceDrawer';
import { fileSize, Intake } from './Intake';
import { Progress } from './Progress';
import { ReportView } from './ReportView';
import { useCase } from './useCase';

export function App() {
  const investigation = useCase();
  const { id, record, report, busy, error, notice } = investigation;
  const [pendingFiles, setPendingFiles] = useState<File[]>();
  const [deleteId, setDeleteId] = useState<string | null>(null);
  const [evidenceView, setEvidenceView] = useState<{ report: typeof report; ids: string[] } | null>(
    null,
  );
  const [recoveryId, setRecoveryId] = useState('');
  const [runtimeAIStatus, setRuntimeAIStatus] = useState<AIStatus>();
  useEffect(() => {
    const controller = new AbortController();
    api.aiStatus(controller.signal).then(
      (status) => {
        if (!controller.signal.aborted) setRuntimeAIStatus(status);
      },
      () => {
        if (!controller.signal.aborted) setRuntimeAIStatus(undefined);
      },
    );
    return () => controller.abort();
  }, []);
  const original = record?.artifacts.find((artifact) => artifact.id === record.original_id);
  const currentAIStatus = record?.ai_status ?? runtimeAIStatus;
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
        <img className="brand" src="/brand/wireclaw-logo.jpeg" alt="Wireclaw" />
        <div className="local-status">
          <span aria-hidden="true">◉</span> Local capture analysis{' '}
          <span className="separator">/</span> {aiStatusLabel(currentAIStatus)}
        </div>
      </header>
      <main id="main" tabIndex={-1}>
        <h1 className="sr-only">Capture investigation</h1>
        {id && (
          <div className="case-toolbar">
            <button
              className="quiet"
              disabled={locked}
              onClick={() => {
                setPendingFiles(undefined);
                investigation.newCase();
              }}
            >
              New case
            </button>
          </div>
        )}
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
            <Intake busy={busy} initialFiles={pendingFiles} onStart={investigation.start} />
            <details className="recovery">
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
            {record.original_id && (
              <div className="selected-file">
                <span aria-hidden="true">▤</span>
                <div>
                  <strong>
                    {record.name || record.display_name || record.capture_name || 'Stored capture'}
                  </strong>
                  {original && <span>{fileSize(original.bytes)}</span>}
                </div>
              </div>
            )}
            <p className="symptom user-question">{record.symptom}</p>
            <details className="case-context">
              <summary>Case details</summary>
              <p className="case-id">
                Case <code>{record.id}</code>
              </p>
              {record.capture_sha && (
                <p>
                  Immutable original · SHA-256 <code>{record.capture_sha}</code>
                </p>
              )}
              <p>Your source file is unchanged.</p>
              <details>
                <summary>Recorded lifecycle history</summary>
                <ol>
                  {record.history.map((entry) => (
                    <li key={entry.seq}>
                      <code>{entry.state}</code> · <time dateTime={entry.at}>{entry.at}</time>
                    </li>
                  ))}
                </ol>
              </details>
              <button
                className="danger quiet"
                disabled={locked}
                onClick={() => setDeleteId(record.id)}
              >
                Delete case
              </button>
            </details>
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
            {!busy && report && record.original_id && (
              <ReportView
                key={revision(record)}
                report={report}
                originalId={record.original_id}
                onEvidence={(ids) => {
                  if (ids.length) setEvidenceView({ report, ids });
                }}
              />
            )}
            {!busy && report && record.original_id && (
              <Conversation
                key={`${id}-${revision(record)}`}
                caseId={record.id}
                enabled={!!currentAIStatus && currentAIStatus.effective_provider_mode !== 'none'}
                onAttach={(files) => {
                  setPendingFiles(files);
                  investigation.newCase();
                }}
                onEvidence={(ids) => {
                  if (ids.length) setEvidenceView({ report, ids });
                }}
              />
            )}
            {!report && (locked || !!record.original_id) && (
              <div className="composer-wrap">
                <div className="composer">
                  <button className="attach quiet" disabled aria-label="Attach capture">
                    ＋
                  </button>
                  <textarea
                    rows={1}
                    disabled
                    aria-label="Question about this report"
                    placeholder="Waiting for the investigation report…"
                  />
                  <button className="send primary" disabled aria-label="Send">
                    ↑
                  </button>
                </div>
                <p className="composer-hint">
                  {locked
                    ? 'Investigation in progress. Capture evidence remains authoritative.'
                    : 'A completed report is required for follow-up.'}
                </p>
              </div>
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
              This removes the locally stored original capture, normalized evidence, report, and any
              derived evidence captures. Your source file outside Wireclaw is unchanged. Deletion
              cannot be undone.
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
    </>
  );
}
