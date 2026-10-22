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
      <svg className="processing-wave" viewBox="0 0 54 24" aria-hidden="true">
        <path className="wave-back" d="M-20 12C-12 5-4 5 4 12s16 7 24 0 16-7 24 0 16 7 24 0" />
        <path className="wave-front" d="M-20 12c8 7 16 7 24 0s16-7 24 0 16 7 24 0 16-7 24 0" />
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
