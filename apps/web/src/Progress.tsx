import type { Case } from './api';

const labels: Record<Case['state'], string> = {
  NEW: 'Case created · waiting for capture',
  INGESTING: 'Uploading capture',
  VALIDATING_CAPTURE: 'Validating capture',
  BASELINE_ANALYSIS: 'Assessing capture quality and baseline',
  INVESTIGATING: 'Analyzing deterministic evidence',
  ASSEMBLING_REPORT: 'Assembling report',
  COMPLETE: 'Investigation complete',
  FAILED: 'Investigation failed · prior evidence preserved where available',
};
export function Progress({ record }: { record: Case }) {
  return (
    <p className="processing" role="status" aria-live="polite" aria-atomic="true">
      <span
        className={
          record.state === 'FAILED' || record.state === 'COMPLETE' ? 'status-dot' : 'activity'
        }
        aria-hidden="true"
      />
      <span>{labels[record.state]}</span>
    </p>
  );
}
