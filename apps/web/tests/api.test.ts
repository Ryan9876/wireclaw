import { describe, expect, it, vi } from 'vitest';
import { api, ApiError, errorMessage } from '../src/api';
import supported from './fixtures/supported.json';

function response(value: unknown, status = 200) {
  return new Response(JSON.stringify(value), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
describe('fixed same-origin API contract', () => {
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
      .mockResolvedValueOnce(response({ ...supported.case, provider_mode: 'cloud' }))
      .mockResolvedValueOnce(response({ ...supported.case, state: 'MAGIC' }));
    vi.stubGlobal('fetch', fetch);
    await expect(api.get(supported.case.id)).rejects.toThrow('contract_mismatch');
    await expect(api.get(supported.case.id)).rejects.toThrow('contract_mismatch');
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
