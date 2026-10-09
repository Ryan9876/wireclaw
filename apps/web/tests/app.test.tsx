import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import { api, ApiError, type Case, type Evidence, type Report } from '../src/api';
import rawSupported from './fixtures/supported.json';
import rawInsufficient from './fixtures/insufficient.json';
import rawLimited from './fixtures/limited.json';

type Fixture = { case: Case; report: Report; evidence: Evidence[] };
const supported = rawSupported as unknown as Fixture;
const insufficient = rawInsufficient as unknown as Fixture;
const limited = rawLimited as unknown as Fixture;
let current: Case;
function fixture(value: Fixture = supported) {
  current = structuredClone(value.case) as Case;
  vi.spyOn(api, 'get').mockImplementation(async () => structuredClone(current));
  vi.spyOn(api, 'report').mockResolvedValue(value.report as Report);
  vi.spyOn(api, 'evidence').mockImplementation(async (_id, evidenceId) => {
    const record = value.evidence.find((item) => item.id === evidenceId);
    if (!record) throw new ApiError('evidence_not_found');
    return record as Evidence;
  });
  vi.spyOn(api, 'create').mockImplementation(async (symptom) => {
    current = {
      ...current,
      symptom,
      state: 'NEW',
      original_id: null,
      capture_sha: null,
      quality: null,
      runs: [],
      artifacts: [],
      history: current.history.slice(0, 1),
      evidence_count: 0,
    };
    return current;
  });
  vi.spyOn(api, 'upload').mockImplementation(async () => {
    current = {
      ...value.case,
      state: 'BASELINE_ANALYSIS',
      history: value.case.history.slice(0, 4),
      runs: value.case.runs.slice(0, 1),
    } as Case;
    return current;
  });
  vi.spyOn(api, 'investigate').mockImplementation(async () => {
    current = structuredClone(value.case) as Case;
    return current;
  });
  vi.spyOn(api, 'delete').mockResolvedValue({
    deleted: true,
    original_deleted: true,
    registered_artifacts_deleted: true,
    cleanup_pending: false,
  });
}
function openExisting(value: Fixture = supported) {
  fixture(value);
  window.history.replaceState(null, '', `/#case=${value.case.id}`);
  return render(<App />);
}
async function fillIntake() {
  const user = userEvent.setup();
  await user.upload(screen.getByLabelText('Select capture'), new File(['capture'], 'trace.pcap'));
  await user.type(screen.getByLabelText('Symptom / problem description'), 'application is slow');
  return user;
}
beforeEach(() => {
  vi.spyOn(api, 'limits').mockResolvedValue(256 * 1024 * 1024);
});

describe('primary intake and recovery workflow', () => {
  it('starts with a labeled intake and disabled investigation action', async () => {
    fixture();
    render(<App />);
    expect(screen.getByRole('heading', { name: 'Start an investigation' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Investigate capture' })).toBeDisabled();
    await waitFor(() => expect(screen.getByText(/Local limit:/)).toBeVisible());
    expect(api.create).not.toHaveBeenCalled();
  });
  it('selects file, preserves symptom, and runs create/upload/investigate in order', async () => {
    fixture();
    render(<App />);
    const user = await fillIntake();
    expect(screen.getByText('trace.pcap')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Investigate capture' }));
    expect(await screen.findByRole('heading', { name: 'Supported finding' })).toBeVisible();
    expect(api.create).toHaveBeenCalledWith('application is slow');
    expect(api.upload).toHaveBeenCalledTimes(1);
    expect(api.investigate).toHaveBeenCalledTimes(1);
    expect(window.location.hash).toBe(`#case=${supported.case.id}`);
  });
  it('handles file drop and rejects multiple or empty captures', async () => {
    fixture();
    render(<App />);
    const drop = screen.getByText('Drop a packet capture here').parentElement!;
    const first = new File(['capture'], 'dropped.pcap');
    fireEvent.drop(drop, { dataTransfer: { files: [first] } });
    expect(screen.getByText('dropped.pcap')).toBeVisible();
    fireEvent.drop(drop, { dataTransfer: { files: [first, first] } });
    expect(screen.getByRole('alert')).toHaveTextContent('exactly one');
    fireEvent.drop(drop, { dataTransfer: { files: [new File([], 'empty.pcap')] } });
    expect(screen.getByRole('alert')).toHaveTextContent('empty');
  });
  it('enforces the actual configured size limit', async () => {
    vi.mocked(api.limits).mockResolvedValue(2);
    fixture();
    render(<App />);
    await waitFor(() => expect(screen.getByText(/Local limit: 2 bytes/)).toBeVisible());
    fireEvent.change(screen.getByLabelText('Select capture'), {
      target: { files: [new File(['123'], 'large.pcap')] },
    });
    expect(screen.getByRole('alert')).toHaveTextContent('exceeds');
  });
  it('allows selection removal and leaves investigation disabled', async () => {
    fixture();
    render(<App />);
    const user = await fillIntake();
    await user.click(screen.getByRole('button', { name: 'Remove selection' }));
    expect(screen.queryByText('trace.pcap')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Investigate capture' })).toBeDisabled();
  });
  it('reports API initialization failure and supports retry', async () => {
    vi.mocked(api.limits).mockRejectedValueOnce(new ApiError('network_unavailable'));
    fixture();
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be reached');
    await userEvent.click(screen.getByRole('button', { name: 'Retry API connection' }));
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  });
  it('preserves failed upload case and never calls investigation', async () => {
    fixture();
    vi.mocked(api.upload).mockImplementation(async () => {
      current = { ...current, state: 'FAILED', last_error: 'malformed_capture' };
      throw new ApiError('malformed_capture');
    });
    render(<App />);
    const user = await fillIntake();
    await user.click(screen.getByRole('button', { name: 'Investigate capture' }));
    expect(await screen.findByRole('heading', { name: 'Investigation failed' })).toBeVisible();
    expect(api.investigate).not.toHaveBeenCalled();
    expect(screen.getByRole('button', { name: 'Delete case' })).toBeEnabled();
    expect(screen.getByRole('heading', { name: 'Resume capture intake' })).toBeVisible();
  });
  it('recovers a completed case without any mutation', async () => {
    openExisting();
    expect(await screen.findByRole('heading', { name: 'Supported finding' })).toBeVisible();
    expect(api.create).not.toHaveBeenCalled();
    expect(api.upload).not.toHaveBeenCalled();
    expect(api.investigate).not.toHaveBeenCalled();
  });
  it('recovers the idle upload checkpoint with an explicit Continue action', async () => {
    openExisting();
    current.state = 'BASELINE_ANALYSIS';
    current.runs = [];
    expect(await screen.findByRole('button', { name: 'Continue investigation' })).toBeEnabled();
    expect(api.investigate).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Continue investigation' }));
    expect(await screen.findByRole('heading', { name: 'Supported finding' })).toBeVisible();
  });
  it('renders actual backend progress without a fake percentage', async () => {
    openExisting();
    current.state = 'INVESTIGATING';
    current.runs = [{ ...current.runs[0], status: 'running' }];
    expect(await screen.findByText('Current backend state: INVESTIGATING.')).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Supported finding' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Delete case' })).toBeDisabled();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });
  it('rejects an invalid recovery path and does not issue a case lookup', async () => {
    fixture();
    render(<App />);
    await userEvent.click(screen.getByText('Recover an existing local case'));
    await userEvent.type(screen.getByLabelText('Case ID'), '../outside');
    await userEvent.click(screen.getByRole('button', { name: 'Recover case' }));
    expect(screen.getByRole('alert')).toHaveTextContent('32-character');
    expect(api.get).not.toHaveBeenCalled();
  });
});

describe('evidence and uncertainty presentation', () => {
  it('presents supported result with backend confidence and fault domains', async () => {
    openExisting();
    await screen.findByRole('heading', { name: 'Supported finding' });
    expect(screen.getAllByText('Local network · Network path')[0]).toBeVisible();
    expect(screen.getByText(/confidence · Inferred/)).toBeVisible();
    expect(screen.getByText(/does not prove a root cause/)).toBeVisible();
    expect(screen.getByRole('button', { name: 'Open Full Capture in Wireshark' })).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Open Evidence Capture in Wireshark' }),
    ).toBeDisabled();
  });
  it('treats insufficient_evidence as a completed result with next evidence', async () => {
    openExisting(insufficient as Fixture);
    expect(await screen.findByRole('heading', { name: 'Insufficient evidence' })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'Remaining hypotheses' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Investigation failed' })).not.toBeInTheDocument();
  });
  it('keeps capture limitations visible outside the expert view', async () => {
    openExisting(limited as Fixture);
    expect(await screen.findByRole('heading', { name: /Capture quality: limited/i })).toBeVisible();
    expect(
      screen.getAllByText(limited.report.capture_quality.limitations[0]).length,
    ).toBeGreaterThan(0);
  });
  it('preserves measured classes and incomplete-subtotal qualification', async () => {
    openExisting();
    await screen.findByRole('heading', { name: 'Supported finding' });
    expect(screen.getByText(/Stage subtotal:/)).toBeVisible();
    expect(screen.getByText(/derived \(measured\)/i)).toBeVisible();
    expect(screen.getByText(/not complete end-to-end transaction time/)).toBeVisible();
  });
  it('shows normalized evidence, tool version, and scope in a secondary drawer', async () => {
    openExisting();
    await screen.findByRole('heading', { name: 'Supported finding' });
    await userEvent.click(screen.getByRole('button', { name: 'Show packet evidence' }));
    const dialog = screen.getByRole('dialog', { name: 'Expert evidence' });
    expect(await within(dialog).findByRole('heading', { name: 'Normalized values' })).toBeVisible();
    expect(within(dialog).getByText('Tool / version')).toBeVisible();
    expect(within(dialog).getByText('Scope')).toBeVisible();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Close expert evidence' }));
    expect(screen.queryByRole('dialog')).not.toBeInTheDocument();
  });
  it('renders untrusted symptom as text rather than executable HTML', async () => {
    openExisting();
    current.symptom = '<img src=x onerror="alert(1)">';
    vi.mocked(api.report).mockResolvedValue({
      ...supported.report,
      symptom: current.symptom,
    } as Report);
    expect(await screen.findByText(current.symptom)).toBeVisible();
    expect(document.querySelector('img')).toBeNull();
  });
});

describe('deliberate deletion', () => {
  it('requires confirmation and accurately reports successful file removal', async () => {
    openExisting();
    await screen.findByRole('heading', { name: 'Supported finding' });
    await userEvent.click(screen.getByRole('button', { name: 'Delete case' }));
    const dialog = screen.getByRole('dialog', { name: 'Delete this case?' });
    expect(dialog).toHaveTextContent(supported.case.id);
    expect(api.delete).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep case' }));
    expect(api.delete).not.toHaveBeenCalled();
    await userEvent.click(screen.getByRole('button', { name: 'Delete case' }));
    await userEvent.click(screen.getByRole('button', { name: 'Delete case and stored files' }));
    expect(await screen.findByText(/deleted, including its stored original/)).toBeVisible();
    expect(window.location.hash).toBe('');
    expect(screen.queryByRole('heading', { name: 'Supported finding' })).not.toBeInTheDocument();
  });
  it('does not claim physical cleanup when cleanup_pending is true', async () => {
    openExisting();
    vi.mocked(api.delete).mockResolvedValue({
      deleted: true,
      original_deleted: false,
      registered_artifacts_deleted: false,
      cleanup_pending: true,
    });
    await screen.findByRole('heading', { name: 'Supported finding' });
    await userEvent.click(screen.getByRole('button', { name: 'Delete case' }));
    await userEvent.click(screen.getByRole('button', { name: 'Delete case and stored files' }));
    expect(await screen.findByText(/cleanup is pending/)).toBeVisible();
  });
  it('keeps the case and dialog after a failed deletion', async () => {
    openExisting();
    vi.mocked(api.delete).mockRejectedValue(new ApiError('service_busy'));
    await screen.findByRole('heading', { name: 'Supported finding' });
    await userEvent.click(screen.getByRole('button', { name: 'Delete case' }));
    await userEvent.click(screen.getByRole('button', { name: 'Delete case and stored files' }));
    await waitFor(() =>
      expect(screen.getByRole('dialog')).toHaveTextContent('busy with another operation'),
    );
    expect(window.location.hash).toBe(`#case=${supported.case.id}`);
  });
});

describe('report freshness races', () => {
  it('replaces the completed report after a later persisted revision', async () => {
    openExisting();
    await screen.findByRole('heading', { name: 'Supported finding' });
    current = { ...current, updated: '2030-01-01T00:00:00Z' };
    vi.mocked(api.report).mockResolvedValue({
      ...supported.report,
      conclusion: { ...supported.report.conclusion, statement: 'Later persisted report revision.' },
    } as Report);
    expect(
      await screen.findByText('Later persisted report revision.', {}, { timeout: 3000 }),
    ).toBeVisible();
    expect(
      within(screen.getByRole('region', { name: 'Supported finding' })).queryByText(
        supported.report.conclusion.statement,
      ),
    ).not.toBeInTheDocument();
  });
  it('hides a report when the verification snapshot changed during retrieval', async () => {
    openExisting();
    vi.mocked(api.report).mockImplementation(async () => {
      current = { ...current, state: 'FAILED', last_error: 'service_interrupted' };
      return supported.report as Report;
    });
    expect(await screen.findByRole('heading', { name: 'Investigation failed' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Supported finding' })).not.toBeInTheDocument();
  });
  it('does not restore a late report after changing to a new case', async () => {
    let resolve!: (value: Report) => void;
    openExisting();
    vi.mocked(api.report).mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    await waitFor(() => expect(resolve).toBeDefined());
    await userEvent.click(screen.getByRole('button', { name: 'New case' }));
    await act(async () => {
      resolve(supported.report as Report);
    });
    expect(screen.getByRole('heading', { name: 'Start an investigation' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Supported finding' })).not.toBeInTheDocument();
  });
  it('hides results on lost status connectivity and supports explicit recovery', async () => {
    openExisting();
    await screen.findByRole('heading', { name: 'Supported finding' });
    vi.mocked(api.get).mockRejectedValue(new ApiError('network_unavailable'));
    expect(await screen.findByRole('alert', {}, { timeout: 3000 })).toHaveTextContent(
      'could not be reached',
    );
    expect(screen.queryByRole('heading', { name: 'Supported finding' })).not.toBeInTheDocument();
    vi.mocked(api.get).mockResolvedValue(current);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
    expect(await screen.findByRole('heading', { name: 'Supported finding' })).toBeVisible();
  });
});
