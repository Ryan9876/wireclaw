import type { Case } from './api';

type WaveMotion = 'calm' | 'moderate' | 'reasoning' | 'settling';

const progressCopy: Partial<Record<Case['state'], { label: string; motion: WaveMotion }>> = {
  INGESTING: { label: 'Preparing capture…', motion: 'calm' },
  VALIDATING_CAPTURE: { label: 'Checking capture…', motion: 'calm' },
  BASELINE_ANALYSIS: { label: 'Analyzing network traffic…', motion: 'moderate' },
  INVESTIGATING: { label: 'Investigating the likely cause…', motion: 'reasoning' },
  ASSEMBLING_REPORT: { label: 'Preparing your report…', motion: 'settling' },
};

export function ProcessingWave({
  label,
  motion,
  testId,
}: {
  label: string;
  motion: WaveMotion;
  testId?: string;
}) {
  return (
    <div
      className="processing"
      role="status"
      aria-live="polite"
      aria-atomic="true"
      data-testid={testId}
      data-motion={motion}
    >
      <svg className="processing-claw" viewBox="0 0 56 40" aria-hidden="true" focusable="false">
        <path className="claw-arm" d="M3 29c8-5 16-6 23-5l3 7c-8-1-16 1-24 6Z" />
        <path
          className="claw-lower-jaw"
          d="M20 26c1-7 7-11 15-10 5 1 9 4 11 8l7 3-7 2c-3 5-9 8-16 7-7-1-11-4-10-10Z"
        />
        <path
          className="claw-palm"
          d="M23 24c2-4 6-6 11-6 2 0 4 1 6 2-3 4-5 9-5 14-7 1-13-2-12-10Z"
        />
        <g className="claw-upper-jaw">
          <path d="M27 23c2-8 10-15 18-15 4 0 7 1 9 3l-10 4c-2 4-5 8-10 12Z" />
          <path className="claw-highlight" d="M34 20c4-5 8-7 12-8" />
        </g>
      </svg>
      <span>{label}</span>
    </div>
  );
}

export function Progress({ record }: { record: Case }) {
  if (record.state === 'COMPLETE') return null;
  if (record.state === 'FAILED') {
    return (
      <p className="processing processing-error" role="status" aria-live="polite">
        <span className="processing-error-mark" aria-hidden="true">
          !
        </span>
        <span>Investigation stopped. Review the error details below.</span>
      </p>
    );
  }
  const current = progressCopy[record.state];
  if (!current) return <p className="processing">Waiting for a capture…</p>;
  const reasoning = record.state === 'INVESTIGATING' && record.provider_mode !== 'none';
  const deterministicInvestigation = record.state === 'INVESTIGATING' && !reasoning;
  return (
    <ProcessingWave
      label={
        reasoning
          ? 'Investigating the likely cause…'
          : deterministicInvestigation
            ? 'Analyzing network traffic…'
            : current.label
      }
      motion={reasoning ? 'reasoning' : deterministicInvestigation ? 'moderate' : current.motion}
      testId="processing-wave"
    />
  );
}
