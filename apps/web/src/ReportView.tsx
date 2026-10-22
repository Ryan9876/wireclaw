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

function plainObservation(finding: Report['findings'][number]) {
  if (finding.category === 'tcp.rtt') {
    const match = finding.statement.match(/median ACK RTT of ([\d.]+) ms across (\d+) sample/);
    if (match)
      return `TCP acknowledgements took about ${Number(match[1])} ms to return at the median, measured across ${match[2]} samples.`;
  }
  if (finding.category === 'tcp.establishment_delay') {
    const setup = finding.statement.match(/establishment took ([\d.]+) ms/);
    const repeated = finding.statement.match(/repeated SYN evidence appears in (\d+) frame/);
    if (setup && repeated)
      return `TCP connection setup took about ${(Number(setup[1]) / 1000).toFixed(1)} seconds, with repeat connection attempts in ${repeated[1]} frames.`;
    if (setup)
      return `TCP connection setup took about ${(Number(setup[1]) / 1000).toFixed(1)} seconds.`;
  }
  return finding.statement;
}

function LayerIcon() {
  return (
    <svg width="24" height="24" viewBox="0 0 24 24" fill="none" aria-hidden="true">
      <path
        d="M4 6.5h16M4 12h16M4 17.5h16"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
      <circle cx="7" cy="6.5" r="1" fill="currentColor" />
      <circle cx="17" cy="12" r="1" fill="currentColor" />
      <circle cx="10" cy="17.5" r="1" fill="currentColor" />
    </svg>
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
          <button
            key={id}
            className="evidence-id"
            title={id}
            aria-label={`Inspect evidence ${id}`}
            onClick={() => onEvidence([id])}
          >
            {id.length > 60 ? `${id.slice(0, 3)}…${id.slice(-36)}` : id}
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
      <TextList title="Limitations" values={finding.limitations.slice(0, 1)} />
      <TextList title="Next validation" values={finding.recommended_validation} />
      <details className="technical-detail">
        <summary>Packet details and alternate explanations</summary>
        <TextList title="Additional limitations" values={finding.limitations.slice(1)} />
        <SupportingEvidence caseId={caseId} ids={finding.evidence_ids} />
        <TextList title="Alternate explanations" values={finding.alternate_explanations} />
      </details>
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

  const layerDefinitions = [
    {
      number: '7',
      name: 'Application',
      assessmentName: 'application-layer',
      categories: ['dns.timing', 'server.application_wait'],
    },
    {
      number: '4',
      name: 'Transport / TCP',
      assessmentName: 'transport-layer',
      categories: [
        'tcp.establishment_delay',
        'tcp.establishment_failure',
        'tcp.retransmission',
        'tcp.retransmission_rate',
        'tcp.rtt',
        'tcp.receive_window',
        'tcp.reordering',
        'tcp.reset',
      ],
    },
    {
      number: '3',
      name: 'Network / IP',
      assessmentName: 'network-layer',
      categories: ['ip.fragmentation', 'ip.mtu', 'ip.routing_error'],
    },
    {
      number: '2',
      name: 'Data Link / Ethernet',
      assessmentName: 'data-link layer',
      categories: ['ethernet.frame_error', 'ethernet.crc_error', 'arp.failure', 'wifi.retry'],
    },
  ];
  const layerFindings = layerDefinitions.map((layer) => ({
    ...layer,
    findings: report.findings.filter((finding) => layer.categories.includes(finding.category)),
  }));
  const reportEvidenceIds = new Set(conclusion.evidence_ids);
  const strongestFinding = report.findings.find((finding) =>
    finding.evidence_ids.some((id) => reportEvidenceIds.has(id)),
  );
  const conclusionText =
    strongestFinding && conclusion.statement === strongestFinding.statement
      ? plainObservation(strongestFinding)
      : conclusion.statement;
  const nextStep =
    report.recommended_next_evidence?.[0] ??
    report.findings.flatMap((finding) => finding.recommended_validation)[0] ??
    report.remaining_hypotheses.flatMap((hypothesis) => hypothesis.next_evidence)[0];
  const layerStatus = (findings: Report['findings'], isStrongest: boolean) =>
    !findings.length
      ? 'Not assessable from this capture'
      : isStrongest
        ? 'Strongest signal'
        : 'Possible contributor';

  return (
    <section className="report" role="region" aria-label="Analysis results">
      <article className="summary-message assistant-message" aria-labelledby="conclusion-heading">
        <p className="answer-label">Wireclaw · {aiStatusLabel(statusForReport)}</p>
        <h2 className="result-kind" id="conclusion-heading">
          Here's what I found
        </h2>
        <p className="conclusion" role="status">
          {conclusionText}
        </p>
        {quality.state !== 'good' && (
          <p className="quality-note">
            <strong>Capture quality was {human(quality.state)}.</strong> {quality.limitations[0]}
          </p>
        )}
        {strongestFinding && conclusionText !== plainObservation(strongestFinding) && (
          <p className="summary-support">
            The clearest supporting observation is: {plainObservation(strongestFinding)}
          </p>
        )}
        <p className="muted summary-caveat">
          The report describes what this capture supports. It does not prove a root cause beyond the
          evidence shown here.
        </p>
      </article>
      <div className="layer-sequence" aria-label="Network layer findings">
        {layerFindings.map((layer) => {
          const isStrongest =
            conclusion.type === 'supported_finding' &&
            !!strongestFinding &&
            layer.findings.some((finding) => finding.id === strongestFinding.id);
          const status = layerStatus(layer.findings, isStrongest);
          const evidenceIds = [
            ...new Set(layer.findings.flatMap((finding) => finding.evidence_ids)),
          ];
          return (
            <article
              key={layer.number}
              className={`layer-card ${isStrongest ? 'layer-card-strongest' : ''}`}
              data-testid="osi-layer-card"
              data-layer={layer.number}
              aria-labelledby={`layer-${layer.number}-title`}
            >
              <div className="layer-card-heading">
                <span className="layer-icon" aria-hidden="true">
                  <LayerIcon />
                </span>
                <div className="layer-title-group">
                  <h3 id={`layer-${layer.number}-title`}>{layer.name}</h3>
                  <span className="layer-number">OSI layer {layer.number}</span>
                </div>
                <span className={`layer-status ${isStrongest ? 'emphasized' : ''}`}>{status}</span>
              </div>
              {layer.findings.length ? (
                <>
                  <h4>What Wireclaw saw</h4>
                  {layer.findings.map((finding) => (
                    <div className="layer-observation" key={finding.id}>
                      <strong>{finding.title}</strong>
                      <p>{plainObservation(finding)}</p>
                    </div>
                  ))}
                  <h4>
                    {isStrongest ? 'Why this is the strongest signal' : 'Why this may contribute'}
                  </h4>
                  <p className="layer-explanation">
                    {isStrongest
                      ? 'This report finding is directly cited by the overall conclusion. It supports a concern at this layer, but the capture does not establish the exact fault source.'
                      : 'The report includes a finding at this layer, so it may contribute. The available evidence does not identify it as the main cause.'}
                  </p>
                  {layer.findings[0].alternate_explanations[0] && (
                    <p className="layer-caveat">{layer.findings[0].alternate_explanations[0]}</p>
                  )}
                  <p className="layer-support">
                    <strong>
                      {human(layer.findings[0].confidence)[0].toUpperCase()}
                      {human(layer.findings[0].confidence).slice(1)} support
                    </strong>
                    <span>Support for this finding, not certainty about root cause</span>
                  </p>
                  <button
                    className="view-evidence quiet"
                    onClick={() => onEvidence(evidenceIds)}
                    aria-label={`View evidence for ${layer.name}`}
                  >
                    View evidence <span aria-hidden="true">({evidenceIds.length})</span>
                  </button>
                  <details className="technical-detail layer-technical">
                    <summary>Technical evidence</summary>
                    {layer.findings.map((finding) => (
                      <Finding
                        key={finding.id}
                        finding={finding}
                        caseId={report.case_id}
                        originalId={originalId}
                        bridgeAvailable={bridgeAvailable}
                        onBridgeState={setBridgeAvailable}
                        onEvidence={onEvidence}
                      />
                    ))}
                  </details>
                </>
              ) : (
                <>
                  <h4>What Wireclaw saw</h4>
                  <p className="layer-explanation">
                    The report contains no {layer.assessmentName} finding. This capture does not
                    provide enough layer-specific evidence to assess it.
                  </p>
                  <h4>Why this cannot be ruled out</h4>
                  <p className="layer-caveat">
                    No finding here does not show that the layer is fault-free. More targeted or
                    additional capture evidence may be needed.
                  </p>
                  <p className="layer-support">No layer-specific support was available to rate.</p>
                </>
              )}
            </article>
          );
        })}
      </div>
      {nextStep && (
        <article className="next-step-message assistant-message">
          <p className="answer-label">Wireclaw · Next step</p>
          <h3>What to check next</h3>
          <p>{nextStep}</p>
        </article>
      )}
      <details className="technical-detail report-technical">
        <summary>Technical report details</summary>
        <section className="quality" aria-labelledby="quality-heading">
          <h3 id="quality-heading">Capture quality: {human(quality.state)}</h3>
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
        <section aria-labelledby="time-heading">
          <div className="section-heading">
            <h3 id="time-heading">Time attribution</h3>
            {time && (
              <span className="tag">
                Stage subtotal:{' '}
                {time.total_ms.toLocaleString(undefined, { maximumFractionDigits: 3 })} ms
              </span>
            )}
          </div>
          <p className="muted">
            Available stage intervals only. This subtotal is not complete end-to-end transaction
            time; missing stages remain unknown.
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
                        {segment.duration_ms.toLocaleString(undefined, {
                          maximumFractionDigits: 3,
                        })}{' '}
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
        {report.findings.some(
          (finding) => !layerFindings.some((layer) => layer.findings.includes(finding)),
        ) && (
          <section aria-labelledby="other-findings-heading">
            <h3 id="other-findings-heading">Other report findings</h3>
            {report.findings
              .filter((finding) => !layerFindings.some((layer) => layer.findings.includes(finding)))
              .map((finding) => (
                <Finding
                  key={finding.id}
                  finding={finding}
                  caseId={report.case_id}
                  originalId={originalId}
                  bridgeAvailable={bridgeAvailable}
                  onBridgeState={setBridgeAvailable}
                  onEvidence={onEvidence}
                />
              ))}
          </section>
        )}
        {report.remaining_hypotheses.length > 0 && (
          <section aria-labelledby="hypotheses-heading">
            <h3 id="hypotheses-heading">Remaining possibilities</h3>
            <p className="muted">Possibilities to discriminate, not established findings.</p>
            {report.remaining_hypotheses.map((hypothesis, index) => (
              <article className="hypothesis" key={index}>
                <h4>{hypothesis.statement}</h4>
                <p>Possible area: {domainText(hypothesis.fault_domains)}</p>
                <EvidenceLinks ids={hypothesis.evidence_ids} onEvidence={onEvidence} />
                <TextList title="Evidence needed" values={hypothesis.next_evidence} />
              </article>
            ))}
          </section>
        )}
        <TextList title="Additional investigation limitations" values={report.limitations} />
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
    </section>
  );
}
