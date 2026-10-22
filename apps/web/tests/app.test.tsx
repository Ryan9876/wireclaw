import { act, fireEvent, render, screen, waitFor, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { App } from '../src/App';
import { Progress } from '../src/Progress';
import {
  api,
  ApiError,
  type Case,
  type Evidence,
  type NativeBridgeState,
  type Report,
} from '../src/api';
import rawSupported from './fixtures/supported.json';
import rawInsufficient from './fixtures/insufficient.json';
import rawLimited from './fixtures/limited.json';

type Fixture = { case: Case; report: Report; evidence: Evidence[] };
const supported = rawSupported as unknown as Fixture;
const insufficient = rawInsufficient as unknown as Fixture;
const limited = rawLimited as unknown as Fixture;
let current: Case;
function fixture(
  value: Fixture = supported,
  bridgeState: NativeBridgeState = 'bridge_unavailable',
) {
  current = structuredClone(value.case) as Case;
  vi.spyOn(api, 'get').mockImplementation(async () => structuredClone(current));
  vi.spyOn(api, 'report').mockResolvedValue(value.report as Report);
  vi.spyOn(api, 'bridgeHealth').mockResolvedValue(bridgeState);
  vi.spyOn(api, 'bridgeGrant').mockResolvedValue({
    request_id: 'a'.repeat(32),
    token: 'x'.repeat(32),
    bridge_origin: 'http://127.0.0.1:8766',
    expires_unix: Math.floor(Date.now() / 1000) + 30,
  });
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
function openExisting(
  value: Fixture = supported,
  bridgeState: NativeBridgeState = 'bridge_unavailable',
) {
  fixture(value, bridgeState);
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
  vi.spyOn(api, 'aiStatus').mockResolvedValue({
    effective_provider_mode: 'none',
    embedded_availability: 'not_applicable',
    model: null,
    failure_code: null,
  });
});

describe('primary intake and recovery workflow', () => {
  it.each([
    [
      {
        effective_provider_mode: 'embedded_local',
        embedded_availability: 'ready',
        model: 'wireclaw-qwen3-4b-instruct-2507-q4_k_m',
        failure_code: null,
      },
      'Local embedded AI ready',
    ],
    [
      {
        effective_provider_mode: 'none',
        embedded_availability: 'not_applicable',
        model: null,
        failure_code: null,
      },
      'Rules-only mode',
    ],
    [
      {
        effective_provider_mode: 'none',
        embedded_availability: 'unavailable',
        model: 'wireclaw-qwen3-4b-instruct-2507-q4_k_m',
        failure_code: 'docker-connectivity',
      },
      'Local embedded AI unavailable — deterministic analysis remains available',
    ],
    [
      {
        effective_provider_mode: 'openai_compatible_local',
        embedded_availability: 'not_applicable',
        model: null,
        failure_code: null,
      },
      'Custom local provider',
    ],
    [
      {
        effective_provider_mode: 'openai_compatible_cloud',
        embedded_availability: 'not_applicable',
        model: null,
        failure_code: null,
      },
      'Cloud provider',
    ],
  ] as const)('shows the safe provider state %s', async (status, label) => {
    fixture();
    vi.spyOn(api, 'aiStatus').mockResolvedValue(status);
    render(<App />);
    expect(await screen.findByText(new RegExp(label))).toBeVisible();
    expect(document.body.textContent).not.toContain('/private/');
    expect(document.body.textContent).not.toContain('host.docker.internal');
  });

  it('starts with a labeled intake and disabled investigation action', async () => {
    fixture();
    render(<App />);
    expect(screen.getByRole('heading', { name: 'Start with a capture' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
    await waitFor(() => expect(screen.getByText(/Local limit:/)).toBeVisible());
    expect(api.create).not.toHaveBeenCalled();
  });
  it('selects file, preserves symptom, and runs create/upload/investigate in order', async () => {
    fixture();
    render(<App />);
    const user = await fillIntake();
    expect(screen.getByText('trace.pcap')).toBeVisible();
    await user.click(screen.getByRole('button', { name: 'Send' }));
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
    expect(api.create).toHaveBeenCalledWith('application is slow', 'trace.pcap');
    expect(api.upload).toHaveBeenCalledTimes(1);
    expect(api.investigate).toHaveBeenCalledTimes(1);
    expect(window.location.hash).toBe(`#case=${supported.case.id}`);
  });
  it('handles file drop and rejects multiple or empty captures', async () => {
    fixture();
    render(<App />);
    const drop = screen.getByText('Drop PCAP or PCAPNG').parentElement!;
    const first = new File(['capture'], 'dropped.pcap');
    fireEvent.drop(drop, { dataTransfer: { files: [first] } });
    expect(screen.getByText('dropped.pcap')).toBeVisible();
    fireEvent.change(screen.getByLabelText('Select capture'), {
      target: { files: [first, first] },
    });
    expect(screen.getByRole('alert')).toHaveTextContent('exactly one');
    fireEvent.drop(screen.getByText('Drop PCAP or PCAPNG').parentElement!, {
      dataTransfer: { files: [new File([], 'empty.pcap')] },
    });
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
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
  });
  it('reports API initialization failure and supports retry', async () => {
    vi.mocked(api.limits).mockRejectedValueOnce(new ApiError('network_unavailable'));
    fixture();
    render(<App />);
    expect(await screen.findByRole('alert')).toHaveTextContent('could not be reached');
    await userEvent.click(screen.getByRole('button', { name: 'Retry API connection' }));
    await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  });
  it('does not offer evidence generation when the API is unavailable', async () => {
    openExisting(supported, 'api_unavailable');
    await userEvent.click(await screen.findByRole('heading', { name: "Here's what I found" }));
    await userEvent.click(
      within(screen.getAllByTestId('osi-layer-card')[1]).getByText('Technical evidence'),
    );
    await waitFor(() => expect(screen.getByText(/The local API is unavailable/)).toBeVisible());
    expect(
      screen.queryByRole('button', { name: 'Create evidence capture without opening Wireshark' }),
    ).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Copy Wireshark Display Filter' })).toBeVisible();
    expect(screen.getByRole('button', { name: 'Show Packet Evidence' })).toBeVisible();
  });
  it('preserves failed upload case and never calls investigation', async () => {
    fixture();
    vi.mocked(api.upload).mockImplementation(async () => {
      current = { ...current, state: 'FAILED', last_error: 'malformed_capture' };
      throw new ApiError('malformed_capture');
    });
    render(<App />);
    const user = await fillIntake();
    await user.click(screen.getByRole('button', { name: 'Send' }));
    expect(await screen.findByRole('heading', { name: 'Investigation failed' })).toBeVisible();
    expect(api.investigate).not.toHaveBeenCalled();
    await userEvent.click(screen.getByText('Case details'));
    expect(screen.getByRole('button', { name: 'Delete case' })).toBeEnabled();
    expect(screen.getByRole('heading', { name: 'Resume capture intake' })).toBeVisible();
  });
  it('recovers a completed case without any mutation', async () => {
    openExisting();
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
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
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
  });
  it('renders actual backend progress without a fake percentage', async () => {
    openExisting();
    current.state = 'INVESTIGATING';
    current.runs = [{ ...current.runs[0], status: 'running' }];
    expect(await screen.findByText('Analyzing network traffic…')).toBeVisible();
    expect(screen.queryByRole('heading', { name: "Here's what I found" })).not.toBeInTheDocument();
    await userEvent.click(screen.getByText('Case details'));
    expect(screen.getByRole('button', { name: 'Delete case' })).toBeDisabled();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
  });
  it('rejects an invalid recovery path and does not issue a case lookup', async () => {
    fixture();
    render(<App />);
    await userEvent.click(screen.getByText('Recover existing case'));
    await userEvent.type(screen.getByLabelText('Case ID'), '../outside');
    await userEvent.click(screen.getByRole('button', { name: 'Recover case' }));
    expect(screen.getByRole('alert')).toHaveTextContent('32-character');
    expect(api.get).not.toHaveBeenCalled();
  });
});

describe('evidence and uncertainty presentation', () => {
  it('marks an embedded provider fallback on the report without hiding deterministic findings', async () => {
    const fallback = structuredClone(supported);
    fallback.case.provider_mode = 'embedded_local';
    fallback.case.ai_status = {
      effective_provider_mode: 'embedded_local',
      embedded_availability: 'ready',
      model: 'wireclaw-qwen3-4b-instruct-2507-q4_k_m',
      failure_code: null,
    };
    fallback.report.reasoning = {
      mode: 'model_fallback',
      status: 'fallback',
      steps: 1,
      failure_code: 'provider_timeout',
      provider_mode: 'embedded_local',
      model: 'wireclaw-qwen3-4b-instruct-2507-q4_k_m',
      embedded_availability: 'ready',
      embedded_failure_code: null,
    };
    openExisting(fallback);
    expect(await screen.findByText(/Local embedded AI unavailable/)).toBeVisible();
    expect(screen.getByRole('heading', { name: "Here's what I found" })).toBeVisible();
  });

  it('presents plain-language support and keeps fault domains in technical evidence', async () => {
    openExisting();
    await screen.findByRole('heading', { name: "Here's what I found" });
    const transport = screen.getAllByTestId('osi-layer-card')[1];
    expect(within(transport as HTMLElement).getByText(/Medium support/)).toBeVisible();
    expect(screen.getByText(/does not prove a root cause/)).toBeVisible();
    await userEvent.click(within(transport as HTMLElement).getByText('Technical evidence'));
    expect(screen.getByText('Local network · Network path')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Open Full Capture in Wireshark' })).toBeDisabled();
    expect(
      screen.getByRole('button', { name: 'Open Evidence Capture in Wireshark' }),
    ).toBeDisabled();
  });
  it('keeps bridge ready after a finding or extraction API failure', async () => {
    fixture();
    vi.mocked(api.bridgeHealth).mockResolvedValue('ready');
    vi.mocked(api.bridgeGrant).mockRejectedValue(new ApiError('finding_not_found', 404));
    window.history.replaceState(null, '', `/#case=${supported.case.id}`);
    render(<App />);
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.click(
      within(screen.getAllByTestId('osi-layer-card')[1]).getByText('Technical evidence'),
    );
    const full = await screen.findByRole('button', { name: 'Open Full Capture in Wireshark' });
    await waitFor(() => expect(full).toBeEnabled());
    await userEvent.click(full);
    expect(await screen.findByText(/finding_not_found/)).toBeVisible();
    expect(full).toBeEnabled();
    expect(screen.getByText(/Native bridge available/)).toBeVisible();
  });
  it('treats insufficient_evidence as a completed result with next evidence', async () => {
    openExisting(insufficient as Fixture);
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
    expect(screen.getByRole('heading', { name: 'What to check next' })).toBeVisible();
    await userEvent.click(screen.getByText('Technical report details'));
    expect(screen.getByRole('heading', { name: 'Remaining possibilities' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: 'Investigation failed' })).not.toBeInTheDocument();
  });
  it('keeps capture limitations visible outside the expert view', async () => {
    openExisting(limited as Fixture);
    expect(await screen.findByText(/Capture quality was limited/i)).toBeVisible();
    const summary = document.querySelector('.quality-note')!;
    expect(summary).toHaveTextContent('Possible capture drops');
    expect(summary).not.toHaveTextContent('capture_drops');
    await userEvent.click(screen.getByText('Technical report details'));
    const quality = screen.getByRole('heading', {
      name: 'Capture quality: limited',
    }).parentElement!;
    expect(quality).toHaveTextContent('Possible capture drops');
    expect(quality).toHaveTextContent('Possible duplicate capture artifacts');
    expect(quality).not.toHaveTextContent('duplicate_capture_artifacts');
    const investigationLimits = screen.getByText(
      'Additional investigation limitations',
    ).parentElement!;
    expect(investigationLimits).toHaveTextContent('Possible capture drops');
    expect(investigationLimits).toHaveTextContent('Possible duplicate capture artifacts');
    expect(investigationLimits).not.toHaveTextContent('duplicate_capture_artifacts');
  });
  it('preserves measured classes and incomplete-subtotal qualification', async () => {
    openExisting();
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.click(screen.getByText('Technical report details'));
    expect(screen.getByText(/Stage subtotal:/)).toBeVisible();
    expect(screen.getByText(/derived \(measured\)/i)).toBeVisible();
    expect(screen.getByText(/not complete end-to-end transaction time/)).toBeVisible();
  });
  it('shows normalized evidence, tool version, and scope in a secondary drawer', async () => {
    openExisting();
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.click(screen.getByRole('button', { name: 'Show Packet Evidence' }));
    const dialog = screen.getByRole('dialog', { name: 'Expert evidence' });
    expect(await within(dialog).findByRole('heading', { name: 'Normalized values' })).toBeVisible();
    expect(within(dialog).getByLabelText('Evidence record')).toBeVisible();
    expect(within(dialog).getByRole('article', { name: 'analyze rtt' })).toBeVisible();
    expect(
      within(dialog).queryByRole('article', { name: 'Evidence record' }),
    ).not.toBeInTheDocument();
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
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });
});

describe('conversation-first OSI analysis presentation', () => {
  it('stacks the standard OSI cards in conversational order and emphasizes the strongest supported layer', async () => {
    openExisting();
    const result = await screen.findByRole('region', { name: 'Analysis results' });
    const cards = within(result).getAllByTestId('osi-layer-card');
    expect(cards.map((card) => card.getAttribute('data-layer'))).toEqual(['7', '4', '3', '2']);
    expect(within(cards[1]).getByText('Strongest signal')).toBeVisible();
    expect(within(cards[1]).getByText(/Medium support/i)).toBeVisible();
    expect(within(cards[0]).getByText('Not assessable from this capture')).toBeVisible();
  });

  it('does not describe an unassessable layer as healthy or ruled out', async () => {
    openExisting();
    const result = await screen.findByRole('region', { name: 'Analysis results' });
    const application = within(result).getAllByTestId('osi-layer-card')[0];
    expect(application).toHaveTextContent(
      "This capture doesn't contain enough application-layer evidence to judge this layer.",
    );
    expect(application).toHaveTextContent(
      'The missing evidence does not prove that this layer is fault-free.',
    );
    expect(application).not.toHaveTextContent(
      /the layer is (?:healthy|ruled out)|working normally/i,
    );
    expect(application).not.toHaveTextContent(/support was available to rate/i);
  });

  it('keeps packet details hidden until requested and preserves evidence and Wireshark actions', async () => {
    openExisting();
    const result = await screen.findByRole('region', { name: 'Analysis results' });
    expect(
      within(result).getByRole('button', { name: 'Open Full Capture in Wireshark' }),
    ).not.toBeVisible();
    await userEvent.click(within(result).getByRole('button', { name: /View evidence/i }));
    const drawer = await screen.findByRole('dialog', { name: 'Expert evidence' });
    expect(await within(drawer).findByText('Tool / version')).toBeVisible();
    await userEvent.click(within(result).getByText('Technical evidence'));
    expect(
      within(result).getByRole('button', { name: 'Open Full Capture in Wireshark' }),
    ).toBeVisible();
    expect(
      within(result).getByRole('button', { name: 'Open Evidence Capture in Wireshark' }),
    ).toBeVisible();
    expect(within(result).getByText('Wireshark display filter')).toBeVisible();
  });

  it('shows a visible recovery action in the header', () => {
    fixture();
    render(<App />);
    expect(screen.getByText('Recover existing case')).toBeVisible();
  });

  it('keeps recovery in the upper header and removes the old intake helper copy', async () => {
    fixture();
    render(<App />);
    const header = screen.getByRole('banner');
    expect(within(header).getByText('Recover existing case')).toBeVisible();
    expect(screen.queryByText('Your capture stays in your local Wireclaw workspace.')).toBeNull();
    expect(screen.queryByText(/Context is not packet evidence/)).toBeNull();
    expect(screen.getByRole('img', { name: 'Wireclaw' })).toBeVisible();
  });

  it('maps persisted lifecycle states to the appropriate processing wave and stops on error', async () => {
    const ingesting = structuredClone(supported);
    ingesting.case.state = 'INGESTING';
    openExisting(ingesting);
    expect(await screen.findByText('Preparing capture…')).toBeVisible();
    expect(screen.getByTestId('processing-wave')).toHaveAttribute('data-motion', 'calm');
  });

  it.each([
    ['VALIDATING_CAPTURE', 'Checking capture…', 'calm', 'none'],
    ['BASELINE_ANALYSIS', 'Analyzing network traffic…', 'moderate', 'none'],
    ['INVESTIGATING', 'Investigating the likely cause…', 'reasoning', 'openai_compatible_local'],
    ['ASSEMBLING_REPORT', 'Preparing your report…', 'settling', 'none'],
  ] as const)('maps %s to the matching wave state', (state, label, motion, providerMode) => {
    const record = { ...supported.case, state, provider_mode: providerMode } as Case;
    render(<Progress record={record} />);
    expect(screen.getByTestId('processing-wave')).toHaveTextContent(label);
    expect(screen.getByTestId('processing-wave')).toHaveAttribute('data-motion', motion);
  });

  it('removes the wave on completion and stops it immediately on error', () => {
    const complete = { ...supported.case, state: 'COMPLETE' } as Case;
    const { rerender } = render(<Progress record={complete} />);
    expect(screen.queryByTestId('processing-wave')).toBeNull();
    rerender(<Progress record={{ ...complete, state: 'FAILED' }} />);
    expect(screen.queryByTestId('processing-wave')).toBeNull();
    expect(screen.getByRole('status')).toHaveTextContent('Investigation stopped.');
  });
});

describe('deliberate deletion', () => {
  it('requires confirmation and accurately reports successful file removal', async () => {
    openExisting();
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.click(screen.getByText('Case details'));
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
    expect(screen.queryByRole('heading', { name: "Here's what I found" })).not.toBeInTheDocument();
  });
  it('does not claim physical cleanup when cleanup_pending is true', async () => {
    openExisting();
    vi.mocked(api.delete).mockResolvedValue({
      deleted: true,
      original_deleted: false,
      registered_artifacts_deleted: false,
      cleanup_pending: true,
    });
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.click(screen.getByText('Case details'));
    await userEvent.click(screen.getByRole('button', { name: 'Delete case' }));
    await userEvent.click(screen.getByRole('button', { name: 'Delete case and stored files' }));
    expect(await screen.findByText(/cleanup is pending/)).toBeVisible();
  });
  it('keeps the case and dialog after a failed deletion', async () => {
    openExisting();
    vi.mocked(api.delete).mockRejectedValue(new ApiError('service_busy'));
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.click(screen.getByText('Case details'));
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
    await screen.findByRole('heading', { name: "Here's what I found" });
    current = { ...current, updated: '2030-01-01T00:00:00Z' };
    vi.mocked(api.report).mockResolvedValue({
      ...supported.report,
      conclusion: { ...supported.report.conclusion, statement: 'Later persisted report revision.' },
    } as Report);
    expect(
      await screen.findByText('Later persisted report revision.', {}, { timeout: 3000 }),
    ).toBeVisible();
    expect(screen.getByText('Later persisted report revision.')).toBeVisible();
    expect(screen.getByText('Later persisted report revision.')).not.toHaveTextContent(
      /TCP stream 0 has a measured median ACK RTT/,
    );
  });
  it('hides a report when the verification snapshot changed during retrieval', async () => {
    openExisting();
    vi.mocked(api.report).mockImplementation(async () => {
      current = { ...current, state: 'FAILED', last_error: 'service_interrupted' };
      return supported.report as Report;
    });
    expect(await screen.findByRole('heading', { name: 'Investigation failed' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: "Here's what I found" })).not.toBeInTheDocument();
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
    expect(screen.getByRole('heading', { name: 'Start with a capture' })).toBeVisible();
    expect(screen.queryByRole('heading', { name: "Here's what I found" })).not.toBeInTheDocument();
  });
  it('hides results on lost status connectivity and supports explicit recovery', async () => {
    openExisting();
    await screen.findByRole('heading', { name: "Here's what I found" });
    vi.mocked(api.get).mockRejectedValue(new ApiError('network_unavailable'));
    expect(await screen.findByRole('alert', {}, { timeout: 3000 })).toHaveTextContent(
      'could not be reached',
    );
    expect(screen.queryByRole('heading', { name: "Here's what I found" })).not.toBeInTheDocument();
    vi.mocked(api.get).mockResolvedValue(current);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
  });
});

describe('approved conversation window', () => {
  it('renders_minimal_empty_capture_state_and_requires_symptom_before_send', async () => {
    fixture();
    render(<App />);
    expect(screen.getByRole('img', { name: 'Wireclaw' })).toHaveAttribute(
      'src',
      '/brand/wireclaw-logo.jpeg',
    );
    expect(screen.getByText('Drop PCAP or PCAPNG')).toBeVisible();
    expect(screen.getByRole('button', { name: 'Choose file' })).toBeVisible();
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    expect(screen.queryByRole('tablist')).not.toBeInTheDocument();
    const drop = screen.getByText('Drop PCAP or PCAPNG').parentElement!;
    fireEvent.dragOver(drop);
    expect(drop).toHaveClass('dragging');
    fireEvent.drop(drop, { dataTransfer: { files: [new File(['capture'], 'trace.pcap')] } });
    expect(screen.queryByText('Drop PCAP or PCAPNG')).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
    await userEvent.type(screen.getByLabelText('Symptom / problem description'), 'slow download');
    expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled();
  });
  it('shows_compact_processing_from_api_state_without_percentage', async () => {
    openExisting();
    current.state = 'INVESTIGATING';
    current.runs = [{ ...current.runs[0], status: 'running' }];
    const status = await screen.findByText('Analyzing network traffic…');
    expect(status.closest('[role="status"]')).toHaveAttribute('aria-live', 'polite');
    expect(screen.queryByRole('heading', { name: 'Investigation stages' })).not.toBeInTheDocument();
    expect(screen.queryByRole('progressbar')).not.toBeInTheDocument();
    expect(document.body.textContent).not.toMatch(/\d+%/);
  });
  it('renders_authoritative_conclusion_with_nearby_evidence_and_both_wireshark_actions', async () => {
    openExisting(supported);
    await screen.findByRole('heading', { name: "Here's what I found" });
    const result = screen.getByRole('region', { name: 'Analysis results' });
    expect(
      within(result).getAllByText(
        'TCP acknowledgements took about 200 ms to return at the median, measured across 3 samples.',
      ),
    ).toHaveLength(2);
    expect(
      within(result).getByRole('button', { name: 'View evidence for Transport / TCP' }),
    ).toBeVisible();
    expect(
      within(result).getByRole('button', { name: 'Open Full Capture in Wireshark' }),
    ).not.toBeVisible();
    await userEvent.click(
      within(screen.getAllByTestId('osi-layer-card')[1]).getByText('Technical evidence'),
    );
    expect(screen.getByRole('button', { name: 'Open Full Capture in Wireshark' })).toBeVisible();
    expect(
      screen.getByRole('button', { name: 'Open Evidence Capture in Wireshark' }),
    ).toBeVisible();
    expect(screen.getByText(/does not prove a root cause/)).toBeVisible();
  });
  it('disables_followup_when_provider_mode_is_rules_only', async () => {
    openExisting();
    await screen.findByRole('heading', { name: "Here's what I found" });
    expect(screen.getByLabelText('Question about this report')).toBeDisabled();
    expect(screen.getByText(/Follow-up is unavailable in rules-only mode/)).toBeVisible();
  });
  it('bookmarked_case_id_restores_existing_case_without_creating_a_case', async () => {
    openExisting();
    await screen.findByRole('heading', { name: "Here's what I found" });
    expect(api.get).toHaveBeenCalledWith(supported.case.id, expect.any(AbortSignal));
    expect(api.create).not.toHaveBeenCalled();
    expect(api.investigate).not.toHaveBeenCalled();
  });
  it('followup_ui_retains_visible_turns_but_sends_only_current_question', async () => {
    const enabled = structuredClone(supported);
    enabled.case.provider_mode = 'openai_compatible_local';
    enabled.case.ai_status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    const fetch = vi.fn().mockImplementation(
      async () =>
        new Response(
          JSON.stringify({
            answer: 'The capture cannot identify the exact device.',
            evidence_ids: [enabled.evidence[0].id],
          }),
          { status: 200 },
        ),
    );
    vi.stubGlobal('fetch', fetch);
    openExisting(enabled);
    await screen.findByRole('heading', { name: "Here's what I found" });
    const composer = screen.getByLabelText('Question about this report');
    await userEvent.type(composer, 'Which device?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    expect(await screen.findByText('The capture cannot identify the exact device.')).toBeVisible();
    await userEvent.type(composer, 'What would validate this?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    await waitFor(() =>
      expect(screen.getAllByText('The capture cannot identify the exact device.')).toHaveLength(2),
    );
    expect(screen.getByText('Which device?')).toBeVisible();
    expect(screen.getByText('What would validate this?')).toBeVisible();
    expect(fetch.mock.calls.map((call) => JSON.parse(call[1].body))).toEqual([
      { question: 'Which device?' },
      { question: 'What would validate this?' },
    ]);
  });
  it('shows the reasoning wave only while a follow-up provider request is pending', async () => {
    const enabled = structuredClone(supported);
    enabled.case.provider_mode = 'openai_compatible_local';
    enabled.case.ai_status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    let resolve!: (value: { answer: string; evidence_ids: string[] }) => void;
    vi.spyOn(api, 'followup').mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    openExisting(enabled);
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Why?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    const wave = await screen.findByTestId('followup-wave');
    expect(wave).toHaveAttribute('data-motion', 'reasoning');
    await act(async () =>
      resolve({ answer: 'The capture cannot distinguish the fault domain.', evidence_ids: [] }),
    );
    expect(screen.queryByTestId('followup-wave')).toBeNull();
  });

  it('keeps the complete original analysis before each follow-up question and answer', async () => {
    const enabled = structuredClone(supported);
    enabled.case.provider_mode = 'openai_compatible_local';
    enabled.case.ai_status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    vi.stubGlobal(
      'fetch',
      vi.fn().mockImplementation(
        async () =>
          new Response(JSON.stringify({ answer: 'More evidence is needed.', evidence_ids: [] }), {
            status: 200,
          }),
      ),
    );
    openExisting(enabled);
    const report = await screen.findByRole('region', { name: 'Analysis results' });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Why?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    const question = await screen.findByText('Why?', { exact: true });
    const reply = await screen.findByText('More evidence is needed.');
    const nextStep = within(report).getByRole('heading', { name: 'What to check next' });
    expect(
      report.compareDocumentPosition(question) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(
      nextStep.compareDocumentPosition(question) & Node.DOCUMENT_POSITION_FOLLOWING,
    ).toBeTruthy();
    expect(question.compareDocumentPosition(reply) & Node.DOCUMENT_POSITION_FOLLOWING).toBeTruthy();
    expect(report.parentElement).toHaveClass('conversation-feed');
    await userEvent.click(screen.getByRole('button', { name: 'New case' }));
    expect(screen.queryByText('More evidence is needed.')).not.toBeInTheDocument();
  });
});

describe('follow-up recovery and case isolation', () => {
  function enabledCase() {
    const value = structuredClone(supported);
    value.case.ai_status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    value.case.provider_mode = 'openai_compatible_local';
    return value;
  }
  it('keeps evidence usable after a provider failure and allows another question', async () => {
    const value = enabledCase();
    openExisting(value);
    vi.spyOn(api, 'followup')
      .mockRejectedValueOnce(new ApiError('provider_timeout'))
      .mockResolvedValueOnce({ answer: '<img src=x onerror="alert(1)">', evidence_ids: [] });
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Why?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    expect(await screen.findByRole('alert')).toHaveTextContent('timed out');
    await userEvent.click(
      within(screen.getAllByTestId('osi-layer-card')[1]).getByText('Technical evidence'),
    );
    expect(screen.getByRole('button', { name: 'Show Packet Evidence' })).toBeEnabled();
    await userEvent.type(screen.getByLabelText('Question about this report'), 'What next?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    expect(await screen.findByText('<img src=x onerror="alert(1)">')).toBeVisible();
    expect(document.querySelector('img[src="x"]')).toBeNull();
  });
  it('retains_turns_and_draft_after_temporary_status_failure_and_recovery', async () => {
    openExisting(enabledCase());
    vi.spyOn(api, 'followup').mockResolvedValue({
      answer: 'Retained explanation.',
      evidence_ids: [],
    });
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Why?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    await screen.findByText('Retained explanation.');
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Unsent draft');
    vi.mocked(api.get).mockRejectedValue(new ApiError('network_unavailable'));
    expect(await screen.findByRole('alert', {}, { timeout: 3000 })).toHaveTextContent(
      'could not be reached',
    );
    expect(screen.queryByRole('heading', { name: "Here's what I found" })).not.toBeInTheDocument();
    expect(screen.getByLabelText('Question about this report')).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
    expect(screen.getByRole('button', { name: 'Attach a new capture' })).toBeDisabled();
    expect(screen.getByText('Retained explanation.')).not.toBeVisible();
    expect(screen.getByLabelText('Question about this report')).toHaveValue('Unsent draft');
    vi.mocked(api.get).mockResolvedValue(current);
    await userEvent.click(screen.getByRole('button', { name: 'Refresh status' }));
    await screen.findByRole('heading', { name: "Here's what I found" });
    expect(screen.getByText('Retained explanation.')).toBeVisible();
    expect(screen.getByText('Why?')).toBeVisible();
    expect(screen.getByLabelText('Question about this report')).toHaveValue('Unsent draft');
    expect(screen.getByRole('button', { name: 'Send' })).toBeEnabled();
    expect(api.followup).toHaveBeenCalledTimes(1);
  });
  it('aborts and discards a late explanation when the conversation is discarded', async () => {
    openExisting(enabledCase());
    let resolve!: (value: { answer: string; evidence_ids: string[] }) => void;
    const followup = vi.spyOn(api, 'followup').mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Why?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    await waitFor(() => expect(resolve).toBeDefined());
    const signal = followup.mock.calls[0][2];
    await userEvent.click(screen.getByRole('button', { name: 'New case' }));
    expect(signal?.aborted).toBe(true);
    await act(async () => {
      resolve({ answer: 'Stale response', evidence_ids: [] });
    });
    expect(screen.queryByText('Stale response')).not.toBeInTheDocument();
  });
});

it('uses_validated_file_intake_when_attaching_a_new_capture_from_a_report', async () => {
  openExisting();
  await screen.findByRole('heading', { name: "Here's what I found" });
  await userEvent.upload(
    screen.getByLabelText('Select new capture'),
    new File(['new capture'], 'next.pcapng'),
  );
  expect(screen.getByText('next.pcapng')).toBeVisible();
  expect(screen.getByRole('button', { name: 'Send' })).toBeDisabled();
  expect(screen.queryByRole('heading', { name: "Here's what I found" })).not.toBeInTheDocument();
  expect(api.create).not.toHaveBeenCalled();
});

describe('recent captures', () => {
  const row = {
    id: supported.case.id,
    name: 'trace.pcap',
    capture_bytes: 127,
    created: supported.case.created,
    updated: supported.case.updated,
    state: 'COMPLETE',
  };
  async function history() {
    await userEvent.click(screen.getByRole('button', { name: 'Recent captures' }));
    return screen.findByRole('dialog', { name: 'Recent captures' });
  }
  it('history_popover_lists_bounded_cases_and_opens_without_reinvestigating', async () => {
    fixture();
    vi.spyOn(api, 'recent').mockResolvedValue([row]);
    render(<App />);
    const popover = await history();
    expect(await within(popover).findByText('trace.pcap')).toBeVisible();
    expect(within(popover).getByText('127 bytes')).toBeVisible();
    expect(within(popover).getByText('Complete')).toBeVisible();
    expect(screen.queryByRole('navigation')).not.toBeInTheDocument();
    await userEvent.click(within(popover).getByRole('button', { name: 'Open trace.pcap' }));
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
    expect(screen.queryByRole('dialog', { name: 'Recent captures' })).not.toBeInTheDocument();
    expect(api.create).not.toHaveBeenCalled();
    expect(api.upload).not.toHaveBeenCalled();
    expect(api.investigate).not.toHaveBeenCalled();
    expect(window.location.hash).toBe(`#case=${row.id}`);
  });
  it.each([false, true])(
    'history opening retains keyboard focus with an active case: %s',
    async (active) => {
      if (active) {
        openExisting();
        await screen.findByRole('heading', { name: "Here's what I found" });
      } else {
        fixture();
        render(<App />);
      }
      current = {
        ...current,
        id: 'b'.repeat(32),
        name: 'other.pcap',
        state: 'BASELINE_ANALYSIS',
        runs: [],
      } as Case;
      vi.spyOn(api, 'recent').mockResolvedValue([
        { ...row, id: current.id, name: current.name, state: current.state },
      ]);
      const user = userEvent.setup();
      const trigger = screen.getByRole('button', { name: 'Recent captures' });
      trigger.focus();
      await user.keyboard('{Enter}');
      const popover = await screen.findByRole('dialog', { name: 'Recent captures' });
      const open = await within(popover).findByRole('button', { name: 'Open other.pcap' });
      open.focus();
      await user.keyboard('{Enter}');
      expect(await screen.findByRole('button', { name: 'Continue investigation' })).toBeVisible();
      expect(screen.queryByRole('dialog', { name: 'Recent captures' })).not.toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Recent captures' })).toHaveFocus();
      await user.keyboard('{Enter}');
      expect(await screen.findByRole('dialog', { name: 'Recent captures' })).toBeVisible();
    },
  );
  it('opening the active history row retains follow-up turns and the unsent draft', async () => {
    const enabled = structuredClone(supported);
    enabled.case.provider_mode = 'openai_compatible_local';
    enabled.case.ai_status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    openExisting(enabled);
    vi.spyOn(api, 'recent').mockResolvedValue([row]);
    vi.spyOn(api, 'followup').mockResolvedValue({
      answer: 'The capture cannot identify the device.',
      evidence_ids: [],
    });
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Which device?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    await screen.findByText('The capture cannot identify the device.');
    await userEvent.type(
      screen.getByLabelText('Question about this report'),
      'Unsent validation question',
    );
    const popover = await history();
    await userEvent.click(await within(popover).findByRole('button', { name: 'Open trace.pcap' }));
    expect(screen.queryByRole('dialog', { name: 'Recent captures' })).not.toBeInTheDocument();
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
    expect(screen.getByText('Which device?')).toBeVisible();
    expect(screen.getByText('The capture cannot identify the device.')).toBeVisible();
    expect(screen.getByLabelText('Question about this report')).toHaveValue(
      'Unsent validation question',
    );
    expect(window.location.hash).toBe(`#case=${row.id}`);
    expect(api.create).not.toHaveBeenCalled();
    expect(api.upload).not.toHaveBeenCalled();
    expect(api.investigate).not.toHaveBeenCalled();
  });
  it('rename_updates_only_case_display_name', async () => {
    const enabled = structuredClone(supported);
    enabled.case.provider_mode = 'openai_compatible_local';
    enabled.case.ai_status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    openExisting(enabled);
    vi.spyOn(api, 'recent').mockResolvedValue([row]);
    vi.spyOn(api, 'followup').mockResolvedValue({ answer: 'Retained answer.', evidence_ids: [] });
    vi.spyOn(api, 'rename').mockImplementation(async (_id, name) => {
      current = { ...current, name, display_name: name, updated: '2026-10-20T20:00:00Z' };
      return current;
    });
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Why?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    await screen.findByText('Retained answer.');
    const popover = await history();
    await userEvent.click(await within(popover).findByText('Actions for trace.pcap'));
    await userEvent.click(within(popover).getByRole('button', { name: 'Rename' }));
    await userEvent.clear(within(popover).getByLabelText('Display name'));
    await userEvent.type(within(popover).getByLabelText('Display name'), 'Office trace');
    await userEvent.click(within(popover).getByRole('button', { name: 'Save name' }));
    expect(await within(popover).findByRole('button', { name: 'Open Office trace' })).toBeVisible();
    await userEvent.keyboard('{Escape}');
    expect(screen.getByRole('button', { name: 'Recent captures' })).toHaveFocus();
    expect(await screen.findByText('Office trace')).toBeVisible();
    expect(screen.getByText('Retained answer.')).toBeVisible();
    expect(api.rename).toHaveBeenCalledWith(row.id, 'Office trace', expect.any(AbortSignal));
    expect(api.investigate).not.toHaveBeenCalled();
    expect(api.upload).not.toHaveBeenCalled();
  });
  it('cancelled rename can be dismissed with Escape and returns focus', async () => {
    fixture();
    vi.spyOn(api, 'recent').mockResolvedValue([row]);
    render(<App />);
    const popover = await history();
    await userEvent.click(await within(popover).findByText('Actions for trace.pcap'));
    await userEvent.click(within(popover).getByRole('button', { name: 'Rename' }));
    await userEvent.click(within(popover).getByRole('button', { name: 'Cancel' }));
    await userEvent.keyboard('{Escape}');
    expect(screen.queryByRole('dialog', { name: 'Recent captures' })).not.toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Recent captures' })).toHaveFocus();
  });
  it('history_delete_uses_existing_confirmation', async () => {
    fixture();
    vi.spyOn(api, 'recent').mockResolvedValue([row]);
    render(<App />);
    let popover = await history();
    await userEvent.click(await within(popover).findByText('Actions for trace.pcap'));
    await userEvent.click(within(popover).getByRole('button', { name: 'Delete' }));
    let dialog = await screen.findByRole('dialog', { name: 'Delete this case?' });
    expect(dialog).toHaveTextContent('stored original capture');
    expect(api.delete).not.toHaveBeenCalled();
    await userEvent.click(within(dialog).getByRole('button', { name: 'Keep case' }));
    expect(api.delete).not.toHaveBeenCalled();
    popover = screen.getByRole('dialog', { name: 'Recent captures' });
    await userEvent.click(within(popover).getByRole('button', { name: 'Delete' }));
    dialog = await screen.findByRole('dialog', { name: 'Delete this case?' });
    await userEvent.click(
      within(dialog).getByRole('button', { name: 'Delete case and stored files' }),
    );
    expect(await screen.findByText(/deleted, including its stored original capture/)).toBeVisible();
    expect(api.delete).toHaveBeenCalledWith(row.id);
    expect(screen.queryByRole('button', { name: 'Open trace.pcap' })).not.toBeInTheDocument();
  });
  it('history_popover_shows_empty_and_api_error_states', async () => {
    fixture();
    vi.spyOn(api, 'recent')
      .mockResolvedValueOnce([])
      .mockRejectedValueOnce(new ApiError('network_unavailable'));
    render(<App />);
    let popover = await history();
    expect(await within(popover).findByText('No recent captures.')).toBeVisible();
    await userEvent.keyboard('{Escape}');
    popover = await history();
    expect(await within(popover).findByRole('alert')).toHaveTextContent('could not be reached');
    expect(within(popover).queryByRole('button', { name: /^Open / })).not.toBeInTheDocument();
  });
  it('ignores a late list after the popover closes and reopens', async () => {
    fixture();
    let resolve!: (rows: (typeof row)[]) => void;
    const list = vi
      .spyOn(api, 'recent')
      .mockImplementationOnce(
        () =>
          new Promise((done) => {
            resolve = done;
          }),
      )
      .mockResolvedValueOnce([]);
    render(<App />);
    await history();
    const signal = list.mock.calls[0][0];
    await userEvent.keyboard('{Escape}');
    const popover = await history();
    expect(await within(popover).findByText('No recent captures.')).toBeVisible();
    await act(async () => resolve([row]));
    expect(signal?.aborted).toBe(true);
    expect(screen.queryByText('trace.pcap')).not.toBeInTheDocument();
  });
  it('stale_history_or_followup_response_is_ignored_after_case_switch', async () => {
    const enabled = structuredClone(supported);
    enabled.case.provider_mode = 'openai_compatible_local';
    enabled.case.ai_status = {
      effective_provider_mode: 'openai_compatible_local',
      embedded_availability: 'not_applicable',
      model: null,
      failure_code: null,
    };
    openExisting(enabled);
    let resolve!: (value: { answer: string; evidence_ids: string[] }) => void;
    const followup = vi.spyOn(api, 'followup').mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    const next = {
      ...current,
      id: 'b'.repeat(32),
      name: 'other.pcap',
      state: 'BASELINE_ANALYSIS',
      runs: [],
    } as Case;
    vi.spyOn(api, 'recent').mockResolvedValue([
      { ...row, id: next.id, name: next.name, state: next.state },
    ]);
    await screen.findByRole('heading', { name: "Here's what I found" });
    await userEvent.type(screen.getByLabelText('Question about this report'), 'Why?');
    await userEvent.click(screen.getByRole('button', { name: 'Send' }));
    const popover = await history();
    current = next;
    await userEvent.click(await within(popover).findByRole('button', { name: 'Open other.pcap' }));
    expect(await screen.findByRole('button', { name: 'Continue investigation' })).toBeVisible();
    await act(async () => resolve({ answer: 'Stale answer', evidence_ids: [] }));
    expect(followup.mock.calls[0][2]?.aborted).toBe(true);
    expect(screen.queryByText('Stale answer')).not.toBeInTheDocument();
    expect(api.investigate).not.toHaveBeenCalled();
  });
  it('ignores a late rename result after switching cases', async () => {
    openExisting();
    vi.spyOn(api, 'recent').mockResolvedValue([row]);
    let resolve!: (value: Case) => void;
    const rename = vi.spyOn(api, 'rename').mockImplementation(
      () =>
        new Promise((done) => {
          resolve = done;
        }),
    );
    await screen.findByRole('heading', { name: "Here's what I found" });
    const popover = await history();
    await userEvent.click(await within(popover).findByText('Actions for trace.pcap'));
    await userEvent.click(within(popover).getByRole('button', { name: 'Rename' }));
    await userEvent.type(within(popover).getByLabelText('Display name'), ' changed');
    await userEvent.click(within(popover).getByRole('button', { name: 'Save name' }));
    current = {
      ...current,
      id: 'b'.repeat(32),
      name: 'other.pcap',
      state: 'BASELINE_ANALYSIS',
      runs: [],
    } as Case;
    await act(async () => {
      window.history.replaceState(null, '', `/#case=${current.id}`);
      window.dispatchEvent(new HashChangeEvent('hashchange'));
    });
    expect(await screen.findByRole('button', { name: 'Continue investigation' })).toBeVisible();
    await act(async () => resolve({ ...supported.case, name: 'Stale renamed case' }));
    expect(rename.mock.calls[0][2]?.aborted).toBe(true);
    expect(screen.queryByText('Stale renamed case')).not.toBeInTheDocument();
    expect(screen.getByText('other.pcap')).toBeVisible();
  });
  it('bookmarked_case_id_restores_existing_case_without_creating_a_case', async () => {
    openExisting();
    expect(await screen.findByRole('heading', { name: "Here's what I found" })).toBeVisible();
    expect(api.create).not.toHaveBeenCalled();
    expect(api.upload).not.toHaveBeenCalled();
    expect(api.investigate).not.toHaveBeenCalled();
  });
});
