import { describe, expect, it, vi } from 'vitest';
import { api, ApiError, errorMessage, revision, type Case } from '../src/api';
import supported from './fixtures/supported.json';

function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
describe('fixed same-origin API contract', () => {
  it('does not invalidate report content when only derived artifact bookkeeping changes', () => {
    const before = structuredClone(supported.case) as unknown as Case;
    const after = structuredClone(supported.case) as unknown as Case;
    after.artifacts.push({
      ...after.artifacts[0],
      id: 'derived-artifact',
      kind: 'evidence_capture',
      sha256: 'a'.repeat(64),
    });
    expect(revision(after)).toBe(revision(before));
  });
  it('creates with context, uploads octet stream, and invokes the real endpoint shapes', async () => {
    const fetch = vi.fn().mockImplementation(async () => response(supported.case));
    vi.stubGlobal('fetch', fetch);
    await api.create('app is slow');
    const capture = new File(['local packet bytes'], 'trace.pcap');
    await api.upload(supported.case.id, capture);
    await api.investigate(supported.case.id);
    expect(fetch.mock.calls.map((call) => call[0])).toEqual([
      '/api/cases',
      `/api/cases/${supported.case.id}/capture`,
      `/api/cases/${supported.case.id}/investigate`,
    ]);
    expect(fetch.mock.calls[0][1].body).toBe(JSON.stringify({ symptom: 'app is slow' }));
    expect(fetch.mock.calls[1][1].body).toBe(capture);
    expect(fetch.mock.calls[1][1].headers).toEqual({ 'Content-Type': 'application/octet-stream' });
    expect(fetch.mock.calls.every((call) => call[1].redirect === 'error')).toBe(true);
  });
  it('validates the backend-generated report and evidence', async () => {
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(response(supported.report))
        .mockResolvedValueOnce(response(supported.evidence[0])),
    );
    expect(await api.report(supported.case.id)).toEqual(supported.report);
    expect(await api.evidence(supported.case.id, supported.evidence[0].id)).toEqual(
      supported.evidence[0],
    );
  });
  it('distinguishes bridge health from missing Wireshark and API failure', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(response({ bridge: { origin: 'http://127.0.0.1:8766' } }))
      .mockResolvedValueOnce(response({ status: 'ok', wireshark_available: false }))
      .mockResolvedValueOnce(response({ bridge: { origin: 'http://127.0.0.1:8766' } }))
      .mockRejectedValueOnce(new Error('offline'))
      .mockRejectedValueOnce(new Error('offline'));
    vi.stubGlobal('fetch', fetch);
    await expect(api.bridgeHealth()).resolves.toBe('wireshark_unavailable');
    await expect(api.bridgeHealth()).resolves.toBe('bridge_unavailable');
    await expect(api.bridgeHealth()).resolves.toBe('api_unavailable');
  });
  it('accepts persisted Gate 4 finding fields without inventing domains', async () => {
    const report = structuredClone(supported.report);
    for (const finding of report.findings) {
      delete (finding as { fault_domains?: unknown }).fault_domains;
      delete (finding as { epistemic_class?: unknown }).epistemic_class;
    }
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(report)));
    expect((await api.report(supported.case.id)).findings[0].fault_domains).toBeUndefined();
  });
  it.each(['https://evil.invalid', '../outside', 'a'.repeat(31)])(
    'rejects arbitrary case reference %s before network access',
    async (id) => {
      const fetch = vi.fn();
      vi.stubGlobal('fetch', fetch);
      await expect(api.get(id)).rejects.toThrow('invalid_case_id');
      expect(fetch).not.toHaveBeenCalled();
    },
  );
  it('rejects arbitrary evidence paths before network access', async () => {
    const fetch = vi.fn();
    vi.stubGlobal('fetch', fetch);
    await expect(api.evidence(supported.case.id, '../raw')).rejects.toThrow('invalid_evidence_id');
    expect(fetch).not.toHaveBeenCalled();
  });
  it('rejects wrong-case reports', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(response({ ...supported.report, case_id: 'd'.repeat(32) })),
    );
    await expect(api.report(supported.case.id)).rejects.toThrow('contract_mismatch');
  });
  it('rejects malformed report confidence rather than reinterpreting diagnosis', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        response({
          ...supported.report,
          conclusion: { ...supported.report.conclusion, confidence: 'certain' },
        }),
      ),
    );
    await expect(api.report(supported.case.id)).rejects.toThrow('contract_mismatch');
  });
  it('rejects restored raw fields outside the evidence schema', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(response({ ...supported.evidence[0], raw_payload: 'secret' })),
    );
    await expect(api.evidence(supported.case.id, supported.evidence[0].id)).rejects.toThrow(
      'contract_mismatch',
    );
  });
  it('rejects non-rules provider mode and unknown lifecycle states', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(response({ ...supported.case, provider_mode: 'mystery' }))
      .mockResolvedValueOnce(response({ ...supported.case, state: 'MAGIC' }));
    vi.stubGlobal('fetch', fetch);
    await expect(api.get(supported.case.id)).rejects.toThrow('contract_mismatch');
    await expect(api.get(supported.case.id)).rejects.toThrow('contract_mismatch');
  });
  it.each(['none', 'embedded_local', 'openai_compatible_local', 'openai_compatible_cloud'])(
    'accepts known provider mode %s on cases and capabilities',
    async (mode) => {
      const value = { ...supported.case, provider_mode: mode };
      const fetch = vi
        .fn()
        .mockResolvedValueOnce(response(value))
        .mockResolvedValueOnce(
          response({ provider_mode: mode, limits: { max_capture_bytes: 20 } }),
        );
      vi.stubGlobal('fetch', fetch);
      await expect(api.get(supported.case.id)).resolves.toMatchObject({ provider_mode: mode });
      await expect(api.limits()).resolves.toBe(20);
    },
  );
  it('validates and returns normalized safe AI status', async () => {
    const status = {
      effective_provider_mode: 'none',
      embedded_availability: 'unavailable',
      model: 'wireclaw-qwen3-4b-instruct-2507-q4_k_m',
      failure_code: 'docker-connectivity',
    };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response({ ai: status })));
    await expect(api.aiStatus()).resolves.toEqual(status);
  });
  it('rejects unknown provider modes in the AI status contract', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        response({
          ai: {
            effective_provider_mode: 'shell_agent',
            embedded_availability: 'ready',
            model: 'unexpected',
            failure_code: null,
          },
        }),
      ),
    );
    await expect(api.aiStatus()).rejects.toThrow('contract_mismatch');
  });
  it('handles API errors without echoing raw untrusted messages', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(response({ error: { code: '<script>SECRET</script>' } }, 422)),
    );
    await expect(api.create('test')).rejects.toThrow('operation_failed');
    expect(errorMessage(new ApiError('network_unavailable'))).toContain(
      'Work may still be running',
    );
  });
  it('does not claim deletion when the backend fails or returns deleted=false', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(
        response({
          deleted: false,
          original_deleted: false,
          registered_artifacts_deleted: false,
          cleanup_pending: true,
        }),
      ),
    );
    await expect(api.delete(supported.case.id)).rejects.toThrow('contract_mismatch');
  });
  it('maps lost connectivity and non-JSON responses to safe messages', async () => {
    const fetch = vi
      .fn()
      .mockRejectedValueOnce(new Error('PRIVATE path'))
      .mockResolvedValueOnce(new Response('private stack', { status: 500 }));
    vi.stubGlobal('fetch', fetch);
    await expect(api.get(supported.case.id)).rejects.toThrow('network_unavailable');
    await expect(api.get(supported.case.id)).rejects.toThrow('contract_mismatch');
  });
});

describe('stateless follow-up client', () => {
  it('sends only the current bounded question and validates the response', async () => {
    const answer = { answer: 'More evidence is needed.', evidence_ids: ['ev_1'] };
    const fetch = vi.fn().mockResolvedValue(response(answer));
    vi.stubGlobal('fetch', fetch);
    expect(await api.followup(supported.case.id, 'Why?')).toEqual(answer);
    expect(fetch).toHaveBeenCalledWith(
      `/api/cases/${supported.case.id}/followups`,
      expect.objectContaining({ method: 'POST', body: JSON.stringify({ question: 'Why?' }) }),
    );
  });
  it.each(['', ' '.repeat(5), 'x'.repeat(2001)])(
    'rejects invalid question before network access',
    async (question) => {
      const fetch = vi.fn();
      vi.stubGlobal('fetch', fetch);
      await expect(api.followup(supported.case.id, question)).rejects.toThrow('invalid_request');
      expect(fetch).not.toHaveBeenCalled();
    },
  );
  it.each([
    { answer: '', evidence_ids: [] },
    { answer: 'Answer', evidence_ids: ['../raw'] },
    { answer: 'Answer', evidence_ids: [], report: {} },
  ])('rejects incompatible follow-up data', async (answer) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(answer)));
    await expect(api.followup(supported.case.id, 'Why?')).rejects.toThrow('contract_mismatch');
  });
});

describe('recent capture metadata client', () => {
  const row = {
    id: supported.case.id,
    name: 'trace.pcap',
    capture_bytes: 127,
    created: supported.case.created,
    updated: supported.case.updated,
    state: 'COMPLETE',
  };
  it('requests a bounded metadata-only list with cancellation', async () => {
    const fetch = vi.fn().mockResolvedValue(response([row]));
    vi.stubGlobal('fetch', fetch);
    const controller = new AbortController();
    expect(await api.recent(controller.signal)).toEqual([row]);
    expect(fetch.mock.calls[0][0]).toBe('/api/cases?limit=10');
    expect(fetch.mock.calls[0][1].signal).toBe(controller.signal);
  });
  it.each(
    [
      [{ ...row, symptom: 'private context' }],
      [{ ...row, id: '../capture' }],
      [{ ...row, capture_bytes: -1 }],
      [{ ...row, capture_bytes: 1.5 }],
      [{ ...row, state: 'UNKNOWN' }],
      [{ ...row, name: 'bad\u0000name' }],
      [{ ...row, created: 'yesterday' }],
      Array.from({ length: 11 }, () => row),
      [row, row],
      { cases: [row] },
    ].map((value) => ({ value })),
  )('rejects incompatible history data $value', async ({ value }) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(value)));
    await expect(api.recent()).rejects.toThrow('contract_mismatch');
  });
  it('renames with only display_name and validates the returned case identity', async () => {
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(response(supported.case))
      .mockResolvedValueOnce(response({ ...supported.case, id: 'b'.repeat(32) }));
    vi.stubGlobal('fetch', fetch);
    const signal = new AbortController().signal;
    await api.rename(row.id, 'Office trace', signal);
    expect(fetch.mock.calls[0][0]).toBe(`/api/cases/${row.id}`);
    expect(fetch.mock.calls[0][1]).toMatchObject({ method: 'PATCH', signal });
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({ display_name: 'Office trace' });
    await expect(api.rename(row.id, 'Office trace')).rejects.toThrow('contract_mismatch');
  });
  it.each(['', ' ', 'x'.repeat(121), 'line\nname', 'bad\u200ename'])(
    'rejects invalid rename before network access %s',
    async (name) => {
      const fetch = vi.fn();
      vi.stubGlobal('fetch', fetch);
      await expect(api.rename(row.id, name)).rejects.toThrow('invalid_request');
      expect(fetch).not.toHaveBeenCalled();
    },
  );
  it('sends only the capture basename on creation', async () => {
    const fetch = vi.fn().mockResolvedValue(response(supported.case));
    vi.stubGlobal('fetch', fetch);
    await api.create('slow', 'C:\\captures\\trace.pcap');
    expect(JSON.parse(fetch.mock.calls[0][1].body)).toEqual({
      symptom: 'slow',
      capture_name: 'trace.pcap',
    });
  });
});

describe('multi-capture API contract', () => {
  it('creates, uploads, updates, and removes a selected capture', async () => {
    const capture = supported.case.captures[0];
    const fetch = vi
      .fn()
      .mockResolvedValueOnce(response(capture))
      .mockResolvedValueOnce(response({ ...capture, bytes: 17 }))
      .mockResolvedValueOnce(response({ ...capture, vantage_type: 'server' }))
      .mockResolvedValueOnce(
        response({
          deleted: true,
          original_deleted: true,
          registered_artifacts_deleted: true,
          cleanup_pending: false,
        }),
      );
    vi.stubGlobal('fetch', fetch);
    const created = await api.createCapture(supported.case.id, 'server.pcap');
    const file = new File(['packet bytes'], 'server.pcap');
    await api.uploadCaptureData(supported.case.id, created.id, file);
    await api.updateCapture(supported.case.id, created.id, { vantage_type: 'server' });
    await api.removeCapture(supported.case.id, created.id);
    expect(fetch.mock.calls.map((call) => call[0])).toEqual([
      `/api/cases/${supported.case.id}/captures`,
      `/api/cases/${supported.case.id}/captures/${created.id}/data`,
      `/api/cases/${supported.case.id}/captures/${created.id}`,
      `/api/cases/${supported.case.id}/captures/${created.id}`,
    ]);
    expect(fetch.mock.calls[1][1]).toMatchObject({ method: 'PUT', body: file });
    expect(fetch.mock.calls[2][1]).toMatchObject({
      method: 'PATCH',
      body: JSON.stringify({ vantage_type: 'server' }),
    });
    expect(fetch.mock.calls[3][1].method).toBe('DELETE');
  });

  it('rejects unrecognized fields on capture responses', async () => {
    const capture = { ...supported.case.captures[0], raw_path: '/private/capture' };
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(capture)));
    await expect(api.createCapture(supported.case.id, 'trace.pcap')).rejects.toThrow(
      'contract_mismatch',
    );
  });

  it('rejects cases with malformed capture rows', async () => {
    const invalid = structuredClone(supported.case);
    invalid.captures[0].vantage_type = 'invented';
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(response(invalid)));
    await expect(api.get(supported.case.id)).rejects.toThrow('contract_mismatch');
  });
});
