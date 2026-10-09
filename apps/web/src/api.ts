import { validReport, validEvidence, validCase, validDeletion } from './generated/validators';
import type { components } from './generated/api';
import type { Report } from './generated/investigation-result';
import type { Evidence } from './generated/evidence';

export type { Report, Evidence };
export type Case = components['schemas']['CaseResponse'];
export type Deletion = components['schemas']['DeletionResponse'];
export type EvidenceCapture = {
  artifact_id: string;
  sha256: string;
  bytes: number;
  provenance: {
    artifact_id: string;
    parent_sha256: string;
    case_id: string;
    finding_id: string;
    evidence_ids: string[];
    extraction_mode: string;
    display_filter: string;
  };
};
export type BridgeGrant = {
  request_id: string;
  token: string;
  bridge_origin: string;
  expires_unix: number;
};
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
const validArtifactId = validCaseId;
const validFindingId = (id: string) => /^[A-Za-z0-9_.-]{1,128}$/.test(id);
const validSHA256 = (value: string) => /^[a-f0-9]{64}$/.test(value);

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
  bridge_unavailable:
    'The native Wireshark bridge is not running. Packet evidence remains available locally.',
  wireshark_unavailable:
    'The native bridge is running, but an approved Wireshark executable was not found.',
  wireshark_launch_failed: 'Wireshark could not be launched. The capture remains unchanged.',
  contract_mismatch:
    'The local API returned an incompatible response. Results are hidden; refresh status or check application versions.',
  malformed_capture: 'The selected file is not a readable packet capture.',
  unsupported_capture: 'This capture format is unsupported.',
  capture_size_limit: 'The capture exceeds the configured local size limit.',
  evidence_capture_size_limit: 'The focused evidence capture exceeds the configured local size limit.',
  evidence_capture_count_limit: 'This case reached the configured focused-capture limit.',
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
async function getBridgeOrigin(signal?: AbortSignal): Promise<string> {
  const data = (await request('config/capabilities', { signal })) as {
    bridge?: { origin?: unknown };
  };
  if (typeof data.bridge?.origin !== 'string') throw new ApiError('contract_mismatch');
  let url: URL;
  try {
    url = new URL(data.bridge.origin);
  } catch {
    throw new ApiError('contract_mismatch');
  }
  if (
    url.protocol !== 'http:' ||
    url.hostname !== '127.0.0.1' ||
    !url.port ||
    url.pathname !== '/' ||
    url.search ||
    url.hash
  )
    throw new ApiError('contract_mismatch');
  return url.origin;
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
  async bridgeHealth(signal?: AbortSignal): Promise<boolean> {
    let origin: string;
    try {
      origin = await getBridgeOrigin(signal);
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      return false;
    }
    try {
      const response = await fetch(`${origin}/v1/health`, {
        signal,
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
      });
      if (!response.ok) return false;
      const data = (await response.json()) as { status?: unknown; wireshark_available?: unknown };
      return data.status === 'ok' && data.wireshark_available === true;
    } catch (error) {
      if (error instanceof DOMException && error.name === 'AbortError') throw error;
      return false;
    }
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
  async evidenceCapture(id: string, findingId: string): Promise<EvidenceCapture> {
    if (!validFindingId(findingId)) throw new ApiError('invalid_finding_id');
    const data = (await request(`${casePath(id)}/artifacts/evidence-capture`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ finding_id: findingId }),
    })) as Partial<EvidenceCapture>;
    if (
      typeof data.artifact_id !== 'string' ||
      !validArtifactId(data.artifact_id) ||
      typeof data.sha256 !== 'string' ||
      !validSHA256(data.sha256) ||
      typeof data.bytes !== 'number' ||
      !Number.isSafeInteger(data.bytes) ||
      data.bytes < 1 ||
      !data.provenance ||
      data.provenance.artifact_id !== data.artifact_id ||
      data.provenance.case_id !== id ||
      data.provenance.finding_id !== findingId
    )
      throw new ApiError('contract_mismatch');
    return data as EvidenceCapture;
  },
  async bridgeGrant(id: string, artifactId: string, findingId: string): Promise<BridgeGrant> {
    if (!validArtifactId(artifactId) || !validFindingId(findingId))
      throw new ApiError('invalid_request');
    const data = (await request(`${casePath(id)}/bridge-grants`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ artifact_id: artifactId, finding_id: findingId }),
    })) as Partial<BridgeGrant>;
    if (
      typeof data.request_id !== 'string' ||
      !validCaseId(data.request_id) ||
      typeof data.token !== 'string' ||
      data.token.length < 32 ||
      data.token.length > 128 ||
      typeof data.bridge_origin !== 'string' ||
      typeof data.expires_unix !== 'number'
    )
      throw new ApiError('contract_mismatch');
    const expected = await getBridgeOrigin();
    if (data.bridge_origin !== expected) throw new ApiError('contract_mismatch');
    return data as BridgeGrant;
  },
  async openBridge(grant: BridgeGrant): Promise<void> {
    if (grant.expires_unix * 1000 <= Date.now()) throw new ApiError('grant_expired');
    let response: Response;
    try {
      response = await fetch(`${grant.bridge_origin}/v1/open`, {
        method: 'POST',
        mode: 'cors',
        credentials: 'omit',
        cache: 'no-store',
        redirect: 'error',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ request_id: grant.request_id, token: grant.token }),
      });
    } catch {
      throw new ApiError('bridge_unavailable');
    }
    let data: unknown = null;
    try {
      data = await response.json();
    } catch {
      if (!response.ok) throw new ApiError('bridge_unavailable', response.status);
    }
    if (!response.ok) {
      const code = (data as { error?: { code?: unknown } })?.error?.code;
      throw new ApiError(typeof code === 'string' ? code : 'bridge_unavailable', response.status);
    }
    if ((data as { opened?: unknown })?.opened !== true) throw new ApiError('contract_mismatch');
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
    value.artifacts.map((a) => [a.kind, a.sha256]),
    value.runs.map((r) => [r.id, r.status]),
  ]);
}
export const isRunning = (value: Case) => value.runs.some((run) => run.status === 'running');
