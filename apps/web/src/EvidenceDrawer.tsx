import { useEffect, useState } from 'react';
import { api, errorMessage, type Evidence } from './api';
import { Dialog } from './Dialog';
import { human, TextList } from './ReportView';

function Values({ value }: { value: unknown }) {
  if (value === null) return <span className="muted">Unknown / unobserved</span>;
  if (typeof value !== 'object')
    return <span>{typeof value === 'boolean' ? String(value) : String(value)}</span>;
  if (Array.isArray(value)) {
    if (!value.length) return <span className="muted">None recorded</span>;
    return (
      <ol className="normalized-array">
        {value.map((item, index) => (
          <li key={index}>
            <Values value={item} />
          </li>
        ))}
      </ol>
    );
  }
  const entries = Object.entries(value);
  if (!entries.length) return <span className="muted">None recorded</span>;
  return (
    <dl className="normalized-values">
      {entries.map(([key, item]) => (
        <div key={key}>
          <dt>{human(key)}</dt>
          <dd>
            <Values value={item} />
          </dd>
        </div>
      ))}
    </dl>
  );
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

  return (
    <Dialog
      title="Expert evidence"
      titleId="evidence-title"
      onClose={onClose}
      className="evidence-drawer"
    >
      <p className="muted">
        Normalized local evidence. Raw packet payloads and intentionally redacted fields are not
        restored.
      </p>
      <label htmlFor="evidence-select">Evidence record</label>
      <select
        id="evidence-select"
        value={selected}
        onChange={(event) => {
          setItem(null);
          setError('');
          setSelected(event.target.value);
        }}
      >
        {ids.map((id) => (
          <option key={id} value={id}>
            {id}
          </option>
        ))}
      </select>
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
      {!item && !error && <p role="status">Loading normalized evidence…</p>}
      {item && (
        <article aria-label="Evidence record">
          <div className="record-meta">
            <span className="tag">{human(item.epistemic_class)}</span>
            <code>{item.id}</code>
          </div>
          <h3>{human(item.category)}</h3>
          <p>{item.summary}</p>
          <dl className="facts">
            <div>
              <dt>Source capability</dt>
              <dd>{item.source.capability}</dd>
            </div>
            <div>
              <dt>Tool / version</dt>
              <dd>
                {item.source.tool} / {item.source.version}
              </dd>
            </div>
            <div>
              <dt>Packet frames</dt>
              <dd>
                {item.frame_refs?.length
                  ? item.frame_refs.join(', ')
                  : 'No explicit frame references; inspect scope.'}
              </dd>
            </div>
          </dl>
          <h3>Scope</h3>
          <Values value={item.scope} />
          {item.display_filter && (
            <>
              <h3>Display filter</h3>
              <pre>{item.display_filter}</pre>
            </>
          )}
          <h3>Normalized values</h3>
          <Values value={item.value} />
          <TextList title="Evidence limitations" values={item.limitations} />
        </article>
      )}
    </Dialog>
  );
}
