import { useEffect, useState } from 'react';
import { api, errorMessage, type Evidence } from './api';
import { Dialog } from './Dialog';
import { human, TextList } from './ReportView';

const titles: Record<string, string> = {
  analyze_tcp_establishment: 'TCP connection setup',
  analyze_tcp_health: 'TCP connection health',
  analyze_tcp_resets: 'TCP resets',
  assess_capture_quality: 'Capture quality',
  get_capture_metadata: 'Capture details',
  analyze_dns: 'DNS activity',
};

function title(item: Evidence) {
  const label = titles[item.category] ?? human(item.category);
  return label.charAt(0).toUpperCase() + label.slice(1);
}

function recordLabel(item: Evidence) {
  if (item.category === 'analyze_tcp_establishment') {
    const state = item.value.state;
    if (state === 'established') return 'The TCP connection setup completed in this capture.';
    if (state === 'incomplete')
      return 'A connection request was observed; setup did not complete in this capture.';
    if (state === 'reset_during_establishment')
      return 'A reset was observed during connection setup.';
    if (state === 'midstream') return 'Connection setup was not observed in this capture.';
  }
  if (item.category === 'assess_capture_quality' && typeof item.value.state === 'string')
    return `Capture quality assessment: ${human(item.value.state)}.`;
  if (item.category === 'analyze_tcp_health')
    return 'This capture records TCP health indicators for the stream. They do not establish physical loss or its location.';
  if (item.summary.trim().toLowerCase() === human(item.category).toLowerCase())
    return `This record contains ${title(item).toLowerCase()} evidence from the capture.`;
  return item.summary;
}

const measurementLabels: Record<string, string> = {
  state: 'Status',
  establishment_seconds: 'Connection setup',
  syn_to_synack_seconds: 'SYN to SYN-ACK',
  timing_reliable: 'Timing reliable',
  data_packets: 'Data packets',
  packets: 'Packets in stream',
  retransmissions: 'Retransmissions',
  retransmission_union_count: 'Retransmission indicators',
  duplicate_ack_count: 'Duplicate ACK indicators',
  out_of_order_count: 'Out-of-order indicators',
  rate: 'Rate',
};

function endpoint(address: string, port: number) {
  return `${address.includes(':') ? `[${address}]` : address}:${port}`;
}

function connections(item: Evidence) {
  const scope = item.scope;
  const complete =
    typeof scope.src_ip === 'string' &&
    typeof scope.dst_ip === 'string' &&
    typeof scope.src_port === 'number' &&
    typeof scope.dst_port === 'number';
  if (!complete) return [];
  const firstSyn =
    item.category === 'analyze_tcp_establishment' &&
    typeof item.value.syn_frame === 'number' &&
    item.value.syn_frame === scope.start_frame;
  return [
    [firstSyn ? 'Client' : 'Source', endpoint(scope.src_ip!, scope.src_port!)],
    [firstSyn ? 'Server' : 'Destination', endpoint(scope.dst_ip!, scope.dst_port!)],
  ];
}

function packetSummary(item: Evidence) {
  const frames = [...new Set(item.frame_refs ?? [])].sort((a, b) => a - b);
  if (
    frames.length > 2 &&
    frames.every((frame, index) => index === 0 || frame === frames[index - 1] + 1)
  )
    return `${frames[0]}–${frames.at(-1)}`;
  if (frames.length) return frames.join(', ');
  if (typeof item.scope.start_frame === 'number' && typeof item.scope.end_frame === 'number')
    return `${item.scope.start_frame}–${item.scope.end_frame}`;
  return 'No packet references recorded';
}

function measurements(item: Evidence) {
  const value = item.value;
  const scalar = (entry: unknown): entry is string | number | boolean =>
    typeof entry === 'string' || typeof entry === 'number' || typeof entry === 'boolean';
  if (item.category === 'analyze_tcp_health') {
    const indicators =
      value.indicators && typeof value.indicators === 'object'
        ? (value.indicators as Record<string, unknown>)
        : {};
    const indicatorCount = (name: string) => {
      const indicator = indicators[name];
      if (!indicator || typeof indicator !== 'object') return undefined;
      const count = (indicator as Record<string, unknown>).count;
      return typeof count === 'number' ? count : undefined;
    };
    const fields: [string, unknown][] = [
      ['packets', value.packets],
      ['data_packets', value.data_packets],
      ['retransmission_union_count', value.retransmission_union_count],
      ['duplicate_ack_count', indicatorCount('duplicate_ack')],
      ['out_of_order_count', indicatorCount('out_of_order')],
    ];
    return fields.filter((field): field is [string, string | number | boolean] => scalar(field[1]));
  }
  const priority =
    item.category === 'analyze_tcp_establishment'
      ? ['state', 'establishment_seconds', 'syn_to_synack_seconds', 'timing_reliable']
      : item.category === 'assess_capture_quality'
        ? ['state']
        : ['state', 'retransmissions', 'data_packets', 'rate'];
  const selected = priority.filter(
    (key) => value[key] !== null && ['string', 'number', 'boolean'].includes(typeof value[key]),
  );
  if (selected.length) return selected.map((key) => [key, value[key]] as const);
  return Object.entries(value)
    .filter(
      ([key, entry]) =>
        !['calculation', 'capture_sha256', 'limitations'].includes(key) &&
        entry !== null &&
        ['string', 'number', 'boolean'].includes(typeof entry),
    )
    .slice(0, 6);
}

export function EvidenceDrawer({
  caseId,
  ids,
  onClose,
}: {
  caseId: string;
  ids: string[];
  onClose: () => void;
}) {
  const [selected, setSelected] = useState(ids[0] ?? '');
  const [item, setItem] = useState<Evidence | null>(null);
  const [error, setError] = useState('');
  const [retry, setRetry] = useState(0);
  const [copyStatus, setCopyStatus] = useState('');
  useEffect(() => {
    const controller = new AbortController();
    if (selected)
      api
        .evidence(caseId, selected, controller.signal)
        .then((data) => {
          if (!controller.signal.aborted) {
            setItem(data);
            setError('');
          }
        })
        .catch((failure) => {
          if (!controller.signal.aborted) setError(errorMessage(failure));
        });
    return () => controller.abort();
  }, [caseId, selected, retry]);

  async function copyFilter(filter: string) {
    try {
      await navigator.clipboard.writeText(filter);
      setCopyStatus('Display filter copied.');
    } catch {
      setCopyStatus('Clipboard unavailable. Select and copy the visible filter manually.');
    }
  }

  return (
    <Dialog
      title="Technical evidence"
      titleId="evidence-title"
      onClose={onClose}
      className="evidence-drawer"
    >
      {ids.length > 1 && (
        <div className="evidence-picker">
          <label htmlFor="evidence-select">Evidence record</label>
          <select
            id="evidence-select"
            value={selected}
            onChange={(event) => {
              setItem(null);
              setError('');
              setCopyStatus('');
              setSelected(event.target.value);
            }}
          >
            {ids.map((id, index) => (
              <option key={id} value={id}>
                Evidence {index + 1}
              </option>
            ))}
          </select>
        </div>
      )}
      {error && (
        <div className="error" role="alert">
          <p>{error}</p>
          <button
            onClick={() => {
              setError('');
              setRetry(retry + 1);
            }}
          >
            Retry evidence
          </button>
        </div>
      )}
      {!item && !error && <p role="status">Loading evidence…</p>}
      {item && (
        <article aria-labelledby="evidence-record-title">
          <header className="evidence-intro">
            <h3 id="evidence-record-title">{title(item)}</h3>
            <span className="tag">
              {item.epistemic_class === 'derived' ? 'Derived' : 'Observed'} evidence
            </span>
          </header>
          <section className="evidence-section">
            <h4>What this shows</h4>
            <p>{recordLabel(item)}</p>
            <dl className="facts evidence-facts">
              {item.scope.capture === true && (
                <div>
                  <dt>Scope</dt>
                  <dd>Capture-wide</dd>
                </div>
              )}
              {connections(item).map(([label, value]) => (
                <div key={label}>
                  <dt>{label}</dt>
                  <dd>{value}</dd>
                </div>
              ))}
              {typeof item.scope.tcp_stream === 'number' && (
                <div>
                  <dt>TCP stream</dt>
                  <dd>{item.scope.tcp_stream}</dd>
                </div>
              )}
              <div>
                <dt>Packets</dt>
                <dd>{packetSummary(item)}</dd>
              </div>
            </dl>
          </section>
          <section className="evidence-section">
            <h4>Measurements</h4>
            {measurements(item).length ? (
              <dl className="facts evidence-facts">
                {measurements(item).map(([key, value]) => (
                  <div key={key}>
                    <dt>{measurementLabels[key] ?? human(key)}</dt>
                    <dd>
                      {typeof value === 'boolean' ? String(value) : String(value)}
                      {key.endsWith('_seconds') ? ' s' : ''}
                    </dd>
                  </div>
                ))}
              </dl>
            ) : (
              <p className="muted">No summary measurements recorded.</p>
            )}
          </section>
          <section className="evidence-section">
            <h4>Inspect in Wireshark</h4>
            {item.display_filter ? (
              <>
                <p className="muted">Display filter</p>
                <pre className="evidence-filter">{item.display_filter}</pre>
                <button
                  className="quiet"
                  type="button"
                  onClick={() => void copyFilter(item.display_filter!)}
                >
                  Copy Wireshark Display Filter
                </button>
                <span className="copy-status" role="status">
                  {copyStatus}
                </span>
              </>
            ) : (
              <p className="muted">No display filter recorded for this evidence.</p>
            )}
          </section>
          <TextList title="Limitations" values={item.limitations} />
          <details className="evidence-raw">
            <summary>Raw record</summary>
            <pre>{JSON.stringify(item, null, 2)}</pre>
          </details>
        </article>
      )}
    </Dialog>
  );
}
