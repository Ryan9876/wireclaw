import type { Case } from './api';

const stages = [
  ['NEW', 'Case created'],
  ['INGESTING', 'Uploading capture'],
  ['VALIDATING_CAPTURE', 'Validating capture'],
  ['BASELINE_ANALYSIS', 'Capture quality & baseline'],
  ['INVESTIGATING', 'Deterministic investigation'],
  ['ASSEMBLING_REPORT', 'Assembling report'],
  ['COMPLETE', 'Complete'],
] as const;
export function Progress({ record }: { record: Case }) {
  const state = record.state === 'FAILED' ? record.history.at(-2)?.state : record.state;
  const current = stages.findIndex(([name]) => name === state);
  return (
    <section className="panel progress" aria-labelledby="progress-heading">
      <div className="section-heading">
        <h2 id="progress-heading">Investigation stages</h2>
        <span className="tag">{record.state}</span>
      </div>
      <p role="status" aria-live="polite" aria-atomic="true" className="muted">
        {record.state === 'FAILED'
          ? 'Investigation failed. Prior evidence is preserved where available.'
          : `Current backend state: ${record.state}.`}
      </p>
      <ol className="stages">
        {stages.map(([name, label], index) => {
          const recorded = index < current && record.history.some((item) => item.state === name);
          const active = index === current;
          return (
            <li
              key={name}
              className={active ? 'active' : recorded ? 'recorded' : ''}
              aria-current={active ? 'step' : undefined}
            >
              <span className="stage-marker" aria-hidden="true">
                {recorded ? '✓' : index + 1}
              </span>
              <div>
                <strong>{label}</strong>
                <span>
                  {active
                    ? record.state === 'FAILED'
                      ? 'Stopped here'
                      : 'Current state'
                    : recorded
                      ? 'Recorded'
                      : 'Not yet recorded'}
                </span>
              </div>
            </li>
          );
        })}
      </ol>
      <details>
        <summary>Recorded lifecycle history</summary>
        <ol className="history">
          {record.history.map((item) => (
            <li key={item.seq}>
              <code>{item.state}</code>
              <time dateTime={item.at}>{item.at}</time>
            </li>
          ))}
        </ol>
      </details>
      <p className="field-help">
        Stages come from persisted backend state. Fast transitions may appear only in history; no
        estimated progress percentage is shown.
      </p>
    </section>
  );
}
