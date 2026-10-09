import { validReport, validEvidence, validCase, validDeletion } from './generated/validators';
import type { components } from './generated/api';
import type { Report } from './generated/investigation-result';
import type { Evidence } from './generated/evidence';

export type { Report, Evidence };
export type Case = components['schemas']['CaseResponse'];
export type Deletion = components['schemas']['DeletionResponse'];
export const states = [
  'NEW',
  'INGESTING',
  'VALIDATING_CAPTURE',
  'BASELINE_ANALYSIS',
  'INVESTIGATING',
  'ASSEMBLING_REPORT',
  'COMPLETE',
  'FAILED',
] as const;
export const validCaseId = (id: string) => /^[a-f0-9]{32}$/.test(id);

export class ApiError extends Error {
  constructor(
    public code: string,
    public status = 0,
  ) {
    super(code);
  }
}

const explanations: Record<string, string> = {
  network_unavailable:
    'The local API could not be reached. Work may still be running. Refresh status before retrying.',
  contract_mismatch:
    'The local API returned an incompatible response. Results are hidden; refresh status or check application versions.',
  malformed_capture: 'The selected file is not a readable packet capture.',
  unsupported_capture: 'This capture format is unsupported.',
  capture_size_limit: 'The capture exceeds the configured local size limit.',
  request_size_limit: 'The request exceeds the configured local size limit.',
  case_not_found:
    'This case no longer exists in the local API. It may have been deleted or belong to a different data root.',
  service_busy: 'The local API is busy with another operation. Wait, then refresh status.',
  service_interrupted:
    'The service restarted during analysis. Prior evidence is preserved; you can retry investigation.',
  report_not_ready: 'The report is not ready. Refresh status to recover the current case.',
  invalid_request: 'The local API rejected the request. Check the selected capture and symptom.',
  run_count_limit:
    'This case reached its analysis-run limit. Start a new case if further analysis is needed.',
  tool_unavailable:
    'A required local packet tool is unavailable. Check the local analyzer installation.',
};
export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    return (
      explanations[error.code] ??
      `The local operation failed (${error.code}). Prior evidence is preserved where available.`
    );
  }
  return 'The local operation could not finish. Refresh status before retrying.';
}

async function request(path: string, init: RequestInit = {}): Promise<unknown> {
  let response: Response;
  try {
    response = await fetch(`/api/${path}`, {
      ...init,
      credentials: 'same-origin',
      cache: 'no-store',
      redirect: 'error',
    });
  } catch (error) {
    if (error instanceof DOMException && error.name === 'AbortError') throw error;
    throw new ApiError('network_unavailable');
  }
  let data: unknown;
  try {
    data = await response.json();
  } catch {
    throw new ApiError('contract_mismatch');
  }
  if (!response.ok) {
    const code = (data as { error?: { code?: unknown } })?.error?.code;
    throw new ApiError(
      typeof code === 'string' && /^[a-z_]{1,64}$/.test(code) ? code : 'operation_failed',
      response.status,
    );
  }
  return data;
}

function casePath(id: string): string {
  if (!validCaseId(id)) throw new ApiError('invalid_case_id');
  return `cases/${id}`;
}
function checkCase(value: unknown, id?: string): Case {
  if (
    !validCase(value) ||
    !validCaseId(value.id) ||
    (id && value.id !== id) ||
    !states.includes(value.state as (typeof states)[number]) ||
    value.provider_mode !== 'none'
  ) {
    throw new ApiError('contract_mismatch');
  }
  return value;
}
export const api = {
  async limits(signal?: AbortSignal): Promise<number> {
    const data = (await request('config/capabilities', { signal })) as {
      provider_mode?: unknown;
      limits?: { max_capture_bytes?: unknown };
    };
    const size = data?.limits?.max_capture_bytes;
    if (
      data?.provider_mode !== 'none' ||
      typeof size !== 'number' ||
      !Number.isSafeInteger(size) ||
      size < 1
    )
      throw new ApiError('contract_mismatch');
    return size;
  },
  async create(symptom: string): Promise<Case> {
    return checkCase(
      await request('cases', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ symptom }),
      }),
    );
  },
  async get(id: string, signal?: AbortSignal): Promise<Case> {
    return checkCase(await request(casePath(id), { signal }), id);
  },
  async upload(id: string, file: File): Promise<Case> {
    return checkCase(
      await request(`${casePath(id)}/capture`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/octet-stream' },
        body: file,
      }),
      id,
    );
  },
  async investigate(id: string): Promise<Case> {
    return checkCase(await request(`${casePath(id)}/investigate`, { method: 'POST' }), id);
  },
  async report(id: string, signal?: AbortSignal): Promise<Report> {
    const data = await request(`${casePath(id)}/report`, { signal });
    if (!validReport(data) || data.case_id !== id) throw new ApiError('contract_mismatch');
    return data;
  },
  async evidence(id: string, evidenceId: string, signal?: AbortSignal): Promise<Evidence> {
    if (!/^[A-Za-z0-9_.-]{1,256}$/.test(evidenceId)) throw new ApiError('invalid_evidence_id');
    const data = await request(`${casePath(id)}/evidence/${encodeURIComponent(evidenceId)}`, {
      signal,
    });
    if (!validEvidence(data) || data.id !== evidenceId) throw new ApiError('contract_mismatch');
    return data;
  },
  async delete(id: string): Promise<Deletion> {
    const data = await request(casePath(id), { method: 'DELETE' });
    if (!validDeletion(data) || !data.deleted) throw new ApiError('contract_mismatch');
    return data;
  },
};

export function revision(value: Case): string {
  return JSON.stringify([
    value.id,
    value.state,
    value.updated,
    value.history.at(-1)?.seq,
    value.evidence_count,
    value.artifacts.filter((a) => a.kind === 'report').map((a) => a.sha256),
    value.runs.map((r) => [r.id, r.status]),
  ]);
}
export const isRunning = (value: Case) => value.runs.some((run) => run.status === 'running');
