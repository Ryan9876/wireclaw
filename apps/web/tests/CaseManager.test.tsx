import { fireEvent, render, screen, within } from '@testing-library/react';
import userEvent from '@testing-library/user-event';
import { describe, expect, it, vi } from 'vitest';
import { CaseManager } from '../src/CaseManager';
import type { Case } from '../src/api';
import supported from './fixtures/supported.json';

const record = structuredClone(supported.case) as unknown as Case;

describe('Case Manager', () => {
  it('shows capture identity, size, processing status, and unknown vantage', () => {
    render(
      <CaseManager
        record={record}
        busy={false}
        onAdd={vi.fn()}
        onUpdate={vi.fn()}
        onRemove={vi.fn()}
      />,
    );
    expect(screen.getByText('Case Manager')).toBeVisible();
    expect(screen.getByText('Capture aaaaaaaa')).toBeVisible();
    expect(screen.getByText('Unknown')).toBeVisible();
    expect(screen.getByText('Analyzed')).toBeVisible();
    expect(screen.getByLabelText('Vantage for Capture aaaaaaaa')).toHaveValue('unknown');
  });

  it('updates vantage metadata without uploading and reveals network subtype controls', async () => {
    const user = userEvent.setup();
    const onUpdate = vi.fn();
    const view = render(
      <CaseManager
        record={record}
        busy={false}
        onAdd={vi.fn()}
        onUpdate={onUpdate}
        onRemove={vi.fn()}
      />,
    );
    await user.selectOptions(screen.getByLabelText('Vantage for Capture aaaaaaaa'), 'network');
    expect(onUpdate).toHaveBeenCalledWith(record.captures[0].id, { vantage_type: 'network' });
    const networkRecord = structuredClone(record);
    networkRecord.captures[0].vantage_type = 'network';
    view.rerender(
      <CaseManager
        record={networkRecord}
        busy={false}
        onAdd={vi.fn()}
        onUpdate={onUpdate}
        onRemove={vi.fn()}
      />,
    );
    expect(screen.getByLabelText('Network device type for Capture aaaaaaaa')).toBeVisible();
  });

  it('adds dropped captures and confirms removal while retaining the case', async () => {
    const user = userEvent.setup();
    const onAdd = vi.fn();
    const onRemove = vi.fn();
    render(
      <CaseManager
        record={record}
        busy={false}
        onAdd={onAdd}
        onUpdate={vi.fn()}
        onRemove={onRemove}
      />,
    );
    const file = new File(['pcap'], 'second.pcap');
    fireEvent.drop(screen.getByLabelText('Add capture'), { dataTransfer: { files: [file] } });
    expect(onAdd).toHaveBeenCalledWith([file]);
    await user.click(screen.getByRole('button', { name: 'Remove Capture aaaaaaaa' }));
    expect(screen.getByRole('alertdialog', { name: 'Remove capture?' })).toBeVisible();
    expect(onRemove).not.toHaveBeenCalled();
    await user.click(
      within(screen.getByRole('alertdialog')).getByRole('button', { name: 'Remove capture' }),
    );
    expect(onRemove).toHaveBeenCalledWith(record.captures[0].id);
  });

  it('collapses and expands for the current session', async () => {
    const user = userEvent.setup();
    render(
      <CaseManager
        record={record}
        busy={false}
        onAdd={vi.fn()}
        onUpdate={vi.fn()}
        onRemove={vi.fn()}
      />,
    );
    await user.click(screen.getByRole('button', { name: 'Collapse Case Manager' }));
    expect(screen.queryByText('Analyzed')).not.toBeInTheDocument();
    await user.click(screen.getByRole('button', { name: 'Expand Case Manager' }));
    expect(screen.getByText('Analyzed')).toBeVisible();
  });
});

it('enforces the four-capture limit in the manager', () => {
  const fullCase = structuredClone(record);
  fullCase.captures = Array.from({ length: 4 }, (_, index) => ({
    ...record.captures[0],
    id: index.toString(16).padStart(32, '0'),
    capture_name: `capture-${index + 1}.pcap`,
  }));
  render(
    <CaseManager
      record={fullCase}
      busy={false}
      onAdd={vi.fn()}
      onUpdate={vi.fn()}
      onRemove={vi.fn()}
    />,
  );
  expect(screen.getByText(/4\/4 captures/)).toBeVisible();
  expect(screen.getByRole('button', { name: 'Add capture' })).toBeDisabled();
});
