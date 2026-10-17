import { useEffect, useState } from 'react';
import {
  api,
  aiStatusLabel,
  ApiError,
  errorMessage,
  type Evidence,
  type AIStatus,
  type NativeBridgeState,
  type Report,
} from './api';

export const human = (value: string) => value.replaceAll('_', ' ').replaceAll('.', ' ');
const domains: Record<string, string> = {
  client: 'Client',
  local_network: 'Local network',
  network_path: 'Network path',
  server_application: 'Server / application',
  dns: 'Name resolution',
  capture_observability: 'Capture / observability',
  unknown: 'Unknown',
};
const domainText = (items?: string[]) =>
  items?.length ? items.map((d) => domains[d] ?? human(d)).join(' · ') : 'Unknown';
export function TextList({ title, values }: { title: string; values?: string[] }) {
  if (!values?.length) return null;
  return (
    <section className="text-list">
      <h3>{title}</h3>
      <ul>
        {values.map((value, i) => (
          <li key={i}>{value}</li>
        ))}
      </ul>
    </section>
  );
}

function EvidenceLinks({
  ids,
  onEvidence,
}: {
  ids: string[];
  onEvidence: (ids: string[]) => void;
}) {
  return (
    <div className="evidence-links">
      <span>Evidence</span>
      {ids.length ? (
        ids.map((id) => (
          <button key={id} className="evidence-id" onClick={() => onEvidence([id])}>
            {id}
          </button>
        ))
      ) : (
        <span className="muted">No discriminating evidence cited</span>
      )}
    </div>
  );
}

function SupportingEvidence({ caseId, ids }: { caseId: string; ids: string[] }) {
  const [items, setItems] = useState<Evidence[]>([]);
  const [error, setError] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    Promise.all(ids.map((id) => api.evidence(caseId, id, controller.signal)))
      .then((records) => {
        if (!controller.signal.aborted) setItems(records);
      })
      .catch((failure) => {
        if (!controller.signal.aborted) setError(errorMessage(failure));
      });
    return () => controller.abort();
  }, [caseId, ids]);
  return (
    <div className="supporting-evidence">
      <h4>Deterministic support</h4>
      {items.length ? (
        <ul>
          {items.map((item) => (
            <li key={item.id}>
              <span className="tag">{human(item.epistemic_class)}</span> {item.summary}
            </li>
          ))}
        </ul>
      ) : (
        <p className="muted">{error || 'Loading cited deterministic evidence…'}</p>
      )}
    </div>
  );
}

function Finding({
  finding,
  caseId,
  originalId,
  bridgeAvailable,
  onBridgeState,
  onEvidence,
}: {
  finding: Report['findings'][number];
  caseId: string;
  originalId: string;
  bridgeAvailable: NativeBridgeState;
  onBridgeState: (state: NativeBridgeState) => void;
  onEvidence: (ids: string[]) => void;
}) {
  const [copyStatus, setCopyStatus] = useState('');
  const [actionStatus, setActionStatus] = useState('');
  const [busy, setBusy] = useState(false);
  const [evidenceArtifact, setEvidenceArtifact] = useState<string | null>(null);
  async function copy() {
    try {
      await navigator.clipboard.writeText(finding.wireshark.display_filter ?? '');
      setCopyStatus('Display filter copied.');
    } catch {
      setCopyStatus('Clipboard unavailable. Select and copy the visible filter manually.');
    }
  }
  async function openArtifact(artifactId: string, label: string) {
    const grant = await api.bridgeGrant(caseId, artifactId, finding.id);
    await api.openBridge(grant);
    setActionStatus(`${label} opened in native Wireshark.`);
  }
  async function fullCapture() {
    setBusy(true);
    setActionStatus('');
    try {
      await openArtifact(originalId, 'Full capture');
    } catch (error) {
      setActionStatus(errorMessage(error));
      if (error instanceof ApiError && error.code === 'bridge_unavailable')
        onBridgeState('bridge_unavailable');
      if (error instanceof ApiError && error.code === 'wireshark_unavailable')
        onBridgeState('wireshark_unavailable');
    } finally {
      setBusy(false);
    }
  }
  async function createEvidence(openAfter: boolean) {
    setBusy(true);
    setActionStatus('');
    try {
      let artifactId = evidenceArtifact;
      if (!artifactId) {
        const capture = await api.evidenceCapture(caseId, finding.id);
        artifactId = capture.artifact_id;
        setEvidenceArtifact(artifactId);
      }
      if (openAfter) {
        await openArtifact(artifactId, 'Focused evidence capture');
      } else {
        setActionStatus(`Focused evidence capture created locally as artifact ${artifactId}.`);
      }
    } catch (error) {
      setActionStatus(errorMessage(error));
      if (error instanceof ApiError && error.code === 'bridge_unavailable')
        onBridgeState('bridge_unavailable');
      if (error instanceof ApiError && error.code === 'wireshark_unavailable')
        onBridgeState('wireshark_unavailable');
    } finally {
      setBusy(false);
    }
  }
  const unavailable = bridgeAvailable !== 'ready';
  return (
    <article className="finding" aria-labelledby={`${finding.id}-title`}>
      <div className="finding-top">
        <span className="eyebrow">
          {finding.id} / {human(finding.category)}
        </span>
        <span className="tag">{human(finding.confidence)} confidence · Inferred</span>
      </div>
      <h3 id={`${finding.id}-title`}>{finding.title}</h3>
      <p>{finding.statement}</p>
      <p className="domain">
        <strong>Fault domain:</strong> {domainText(finding.fault_domains)}
      </p>
      {finding.affected_scope && Object.keys(finding.affected_scope).length > 0 && (
        <p className="scope">
          <strong>Affected scope:</strong>{' '}
          {Object.entries(finding.affected_scope)
            .map(([k, v]) => `${human(k)} ${String(v)}`)
            .join(' · ')}
        </p>
      )}
      <EvidenceLinks ids={finding.evidence_ids} onEvidence={onEvidence} />
      <SupportingEvidence caseId={caseId} ids={finding.evidence_ids} />
      <TextList title="Limitations" values={finding.limitations} />
      <TextList title="Alternate explanations" values={finding.alternate_explanations} />
      <TextList title="Next validation" values={finding.recommended_validation} />
      {finding.wireshark.applicable && (
        <div className="validation-actions">
          <div className="button-row">
            <button
              disabled={busy || unavailable}
              aria-describedby={`${finding.id}-bridge`}
              onClick={() => void fullCapture()}
            >
              Open Full Capture in Wireshark
            </button>
            <button
              disabled={busy || unavailable}
              aria-describedby={`${finding.id}-bridge`}
              onClick={() => void createEvidence(true)}
            >
              Open Evidence Capture in Wireshark
            </button>
          </div>
          <p id={`${finding.id}-bridge`} className="muted">
            {bridgeAvailable === 'checking'
              ? 'Checking the local native Wireshark bridge…'
              : bridgeAvailable === 'ready'
                ? 'Native bridge available. Launch grants are one-time and short-lived.'
                : bridgeAvailable === 'wireshark_unavailable'
                  ? 'The native bridge is running, but approved Wireshark was not found. Packet evidence remains usable and focused capture generation remains available.'
                  : bridgeAvailable === 'api_unavailable'
                    ? 'The local API is unavailable. Packet evidence and copied filters remain available in this report.'
                    : 'Native Wireshark bridge unavailable. Packet evidence remains usable and focused capture generation remains available.'}
          </p>
          {bridgeAvailable !== 'ready' &&
            bridgeAvailable !== 'checking' &&
            bridgeAvailable !== 'api_unavailable' && (
              <button className="quiet" disabled={busy} onClick={() => void createEvidence(false)}>
                Create evidence capture without opening Wireshark
              </button>
            )}
          {finding.wireshark.display_filter && (
            <>
              <p className="eyebrow">Wireshark display filter</p>
              <pre>{finding.wireshark.display_filter}</pre>
              <button className="quiet" onClick={copy}>
                Copy Wireshark Display Filter
              </button>
              <span className="copy-status" role="status">
                {copyStatus}
              </span>
            </>
          )}
          <button className="quiet" onClick={() => onEvidence(finding.evidence_ids)}>
            Show Packet Evidence
          </button>
          <p className="copy-status" role="status">
            {actionStatus}
          </p>
        </div>
      )}
    </article>
  );
}

export function ReportView({
  report,
  originalId,
  onEvidence,
}: {
  report: Report;
  originalId: string;
  onEvidence: (ids: string[]) => void;
}) {
  const { conclusion, capture_quality: quality, time_attribution: time } = report;
  const reasoningStatus = report.reasoning;
  const embeddedFailed =
    reasoningStatus?.provider_mode === 'embedded_local' &&
    reasoningStatus.mode === 'model_fallback';
  const statusForReport: AIStatus = {
    effective_provider_mode:
      embeddedFailed || reasoningStatus?.embedded_availability === 'unavailable'
        ? 'none'
        : (reasoningStatus?.provider_mode ?? 'none'),
    embedded_availability: embeddedFailed
      ? 'unavailable'
      : (reasoningStatus?.embedded_availability ?? 'not_applicable'),
    model:
      embeddedFailed || reasoningStatus?.embedded_availability === 'unavailable'
        ? reasoningStatus.model
        : null,
    failure_code: embeddedFailed
      ? (reasoningStatus.failure_code ?? 'provider_unavailable')
      : (reasoningStatus?.embedded_failure_code ?? null),
  };
  const [bridgeAvailable, setBridgeAvailable] = useState<NativeBridgeState>('checking');
  useEffect(() => {
    const controller = new AbortController();
    api
      .bridgeHealth(controller.signal)
      .then((available) => {
        if (!controller.signal.aborted) setBridgeAvailable(available);
      })
      .catch(() => {
        if (!controller.signal.aborted) setBridgeAvailable('bridge_unavailable');
      });
    return () => controller.abort();
  }, [report.case_id]);
  return (
    <div className="report">
      <section className="summary panel" aria-labelledby="conclusion-heading">
        <div className="section-heading">
          <span className="eyebrow">Investigation result · {report.status}</span>
          <span className="tag">{aiStatusLabel(statusForReport)}</span>
        </div>
        <h2 id="conclusion-heading">
          {conclusion.type === 'insufficient_evidence'
            ? 'Insufficient evidence'
            : 'Supported finding'}
        </h2>
        <p className="conclusion">{conclusion.statement}</p>
        <dl className="result-facts">
          <div>
            <dt>Confidence</dt>
            <dd>{human(conclusion.confidence)}</dd>
          </div>
          <div>
            <dt>Fault domain</dt>
            <dd>{domainText(conclusion.fault_domains)}</dd>
          </div>
          <div>
            <dt>Capture quality</dt>
            <dd>{human(quality.state)}</dd>
          </div>
        </dl>
        <p className="muted">
          Conclusions are inferred from deterministic evidence. Confidence describes support for the
          conclusion; it does not prove a root cause.
        </p>
        <EvidenceLinks ids={conclusion.evidence_ids} onEvidence={onEvidence} />
      </section>
      <section className="panel quality" aria-labelledby="quality-heading">
        <h2 id="quality-heading">Capture quality: {human(quality.state)}</h2>
        {quality.limitations.length ? (
          <ul>
            {quality.limitations.map((item, index) => (
              <li key={index}>{item}</li>
            ))}
          </ul>
        ) : (
          <p>No material capture-quality limitation recorded by the analyzer.</p>
        )}
        <EvidenceLinks ids={quality.evidence_ids} onEvidence={onEvidence} />
      </section>
      <section className="panel" aria-labelledby="time-heading">
        <div className="section-heading">
          <h2 id="time-heading">Time attribution</h2>
          {time && (
            <span className="tag">
              Stage subtotal:{' '}
              {time.total_ms.toLocaleString(undefined, { maximumFractionDigits: 3 })} ms
            </span>
          )}
        </div>
        <p className="muted">
          Available stage intervals only. This subtotal is not complete end-to-end transaction time;
          missing stages remain unknown.
        </p>
        {time?.segments.length ? (
          <div className="table-wrap">
            <table>
              <caption className="sr-only">
                Available stage intervals and measurement classes
              </caption>
              <thead>
                <tr>
                  <th scope="col">Stage</th>
                  <th scope="col">Interval</th>
                  <th scope="col">Measurement</th>
                  <th scope="col">Evidence</th>
                </tr>
              </thead>
              <tbody>
                {time.segments.map((segment, index) => (
                  <tr key={index}>
                    <th scope="row">{human(segment.name)}</th>
                    <td>
                      {segment.duration_ms.toLocaleString(undefined, { maximumFractionDigits: 3 })}{' '}
                      ms
                    </td>
                    <td>
                      {human(segment.measurement_class)}
                      {segment.measurement_class === 'inferred' ? ' (estimated)' : ' (measured)'}
                    </td>
                    <td>
                      <button className="quiet" onClick={() => onEvidence(segment.evidence_ids)}>
                        Inspect stage evidence
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <p>No deterministic stage intervals available.</p>
        )}
        <TextList title="Attribution limitations" values={time?.limitations} />
        <p>
          <strong>Unknown / unobserved:</strong> complete user-visible transaction time and any
          stage not listed above.
        </p>
      </section>
      <section aria-labelledby="findings-heading">
        <div className="section-heading">
          <h2 id="findings-heading">
            Findings <span className="count">{report.findings.length}</span>
          </h2>
          <span className="muted">Backend priority order</span>
        </div>
        {report.findings.length ? (
          report.findings.map((finding) => (
            <Finding
              key={finding.id}
              finding={finding}
              caseId={report.case_id}
              originalId={originalId}
              bridgeAvailable={bridgeAvailable}
              onBridgeState={setBridgeAvailable}
              onEvidence={onEvidence}
            />
          ))
        ) : (
          <div className="panel">
            <p>
              No supported diagnostic finding in this capture. Review the remaining hypotheses and
              next evidence below.
            </p>
          </div>
        )}
      </section>
      {report.remaining_hypotheses.length > 0 && (
        <section className="panel" aria-labelledby="hypotheses-heading">
          <h2 id="hypotheses-heading">Remaining hypotheses</h2>
          <p className="muted">Possibilities to discriminate, not established findings.</p>
          {report.remaining_hypotheses.map((hypothesis, index) => (
            <article className="hypothesis" key={index}>
              <h3>{hypothesis.statement}</h3>
              <p>Possible domain: {domainText(hypothesis.fault_domains)}</p>
              <EvidenceLinks ids={hypothesis.evidence_ids} onEvidence={onEvidence} />
              <TextList title="Evidence needed" values={hypothesis.next_evidence} />
            </article>
          ))}
        </section>
      )}
      <section className="panel" aria-labelledby="validation-heading">
        <h2 id="validation-heading">Next evidence & limitations</h2>
        <TextList title="Recommended next evidence" values={report.recommended_next_evidence} />
        <TextList title="Investigation limitations" values={report.limitations} />
      </section>
      <details className="panel">
        <summary>Analyzer versions & report provenance</summary>
        <dl className="facts">
          {Object.entries(report.analyzer_versions).map(([tool, version]) => (
            <div key={tool}>
              <dt>{tool}</dt>
              <dd>{version}</dd>
            </div>
          ))}
          <div>
            <dt>Case ID</dt>
            <dd>
              <code>{report.case_id}</code>
            </dd>
          </div>
          <div>
            <dt>Schema</dt>
            <dd>{report.schema_version}</dd>
          </div>
        </dl>
      </details>
    </div>
  );
}
