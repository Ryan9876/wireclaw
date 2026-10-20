import { useEffect, useRef, useState } from 'react';
import { api, errorMessage, type Case, type RecentCase } from './api';
import { fileSize } from './Intake';

const stateLabel = (state: string) =>
  state
    .toLowerCase()
    .replaceAll('_', ' ')
    .replace(/^./, (c) => c.toUpperCase());

export function RecentCaptures({
  activeId,
  disabled,
  onOpen,
  onRename,
  onDelete,
}: {
  activeId: string | null;
  disabled: boolean;
  onOpen: (id: string) => void;
  onRename: (record: Case) => void;
  onDelete: (row: RecentCase) => void;
}) {
  const [open, setOpen] = useState(false);
  const trigger = useRef<HTMLButtonElement>(null);
  return (
    <div className="recent-captures">
      <button
        ref={trigger}
        type="button"
        className="quiet history-trigger"
        aria-label="Recent captures"
        aria-expanded={open}
        aria-controls={open ? 'recent-captures' : undefined}
        disabled={disabled}
        onClick={() => setOpen(!open)}
      >
        <svg
          width="20"
          height="20"
          viewBox="0 0 24 24"
          fill="none"
          stroke="currentColor"
          strokeWidth="1.6"
          aria-hidden="true"
        >
          <path d="M3 11a9 9 0 1 1 2.6 7.4M3 4v7h7M12 7v5l3 2" />
        </svg>
      </button>
      {open && (
        <HistoryPopover
          key={activeId ?? 'intake'}
          disabled={disabled}
          onClose={() => {
            setOpen(false);
            trigger.current?.focus();
          }}
          onOpen={(id) => {
            setOpen(false);
            trigger.current?.focus();
            onOpen(id);
          }}
          onRename={onRename}
          onDelete={onDelete}
        />
      )}
    </div>
  );
}

function HistoryPopover({
  disabled,
  onClose,
  onOpen,
  onRename,
  onDelete,
}: {
  disabled: boolean;
  onClose: () => void;
  onOpen: (id: string) => void;
  onRename: (record: Case) => void;
  onDelete: (row: RecentCase) => void;
}) {
  const [rows, setRows] = useState<RecentCase[] | null>(null);
  const [error, setError] = useState('');
  const [editing, setEditing] = useState<string | null>(null);
  const [name, setName] = useState('');
  const [saving, setSaving] = useState(false);
  const panel = useRef<HTMLDivElement>(null);
  const lifetime = useRef<AbortController | null>(null);
  useEffect(() => {
    const controller = new AbortController();
    lifetime.current = controller;
    panel.current?.focus();
    api.recent(controller.signal).then(
      (result) => {
        if (!controller.signal.aborted) setRows(result);
      },
      (failure) => {
        if (!controller.signal.aborted) setError(errorMessage(failure));
      },
    );
    return () => controller.abort();
  }, []);
  async function rename(id: string) {
    const signal = lifetime.current?.signal;
    if (!signal || signal.aborted || saving) return;
    setSaving(true);
    setError('');
    try {
      const result = await api.rename(id, name, signal);
      if (signal.aborted) return;
      setRows(
        (before) =>
          before?.map((row) =>
            row.id === id ? { ...row, name: result.name, updated: result.updated } : row,
          ) ?? null,
      );
      setEditing(null);
      panel.current?.focus();
      onRename(result);
    } catch (failure) {
      if (!signal.aborted) setError(errorMessage(failure));
    } finally {
      if (!signal.aborted) setSaving(false);
    }
  }
  return (
    <div
      ref={panel}
      id="recent-captures"
      className="history-popover"
      role="dialog"
      aria-labelledby="history-title"
      tabIndex={-1}
      onKeyDown={(event) => {
        if (event.key === 'Escape') {
          event.preventDefault();
          onClose();
        }
      }}
    >
      <div className="dialog-heading">
        <h2 id="history-title">Recent captures</h2>
        <button
          className="quiet"
          type="button"
          onClick={onClose}
          aria-label="Close recent captures"
        >
          Close
        </button>
      </div>
      {error && (
        <p className="error" role="alert">
          {error}
        </p>
      )}
      {!rows && !error && <p role="status">Loading recent captures…</p>}
      {rows?.length === 0 && <p className="muted">No recent captures.</p>}
      {!!rows?.length && (
        <ul className="history-list">
          {rows.map((row) => (
            <li key={row.id}>
              <div className="history-row">
                <button
                  className="quiet history-open"
                  disabled={disabled}
                  aria-label={`Open ${row.name}`}
                  onClick={() => onOpen(row.id)}
                >
                  <strong>{row.name}</strong>
                  <span className="history-meta">
                    {row.capture_bytes !== null && <span>{fileSize(row.capture_bytes)}</span>}
                    <time dateTime={row.updated}>{new Date(row.updated).toLocaleDateString()}</time>
                    <span>{stateLabel(row.state)}</span>
                  </span>
                </button>
                <details className="history-actions">
                  <summary aria-label={`Actions for ${row.name}`}>
                    <span aria-hidden="true">⋯</span>
                    <span className="sr-only">Actions for {row.name}</span>
                  </summary>
                  <div>
                    <button
                      className="quiet"
                      disabled={disabled || saving}
                      onClick={() => {
                        setEditing(row.id);
                        setName(row.name);
                        setError('');
                      }}
                    >
                      Rename
                    </button>
                    <button
                      className="quiet danger"
                      disabled={disabled || saving}
                      onClick={() => onDelete(row)}
                    >
                      Delete
                    </button>
                  </div>
                </details>
              </div>
              {editing === row.id && (
                <form
                  className="history-rename"
                  onSubmit={(event) => {
                    event.preventDefault();
                    void rename(row.id);
                  }}
                >
                  <label htmlFor="history-name">Display name</label>
                  <input
                    id="history-name"
                    autoFocus
                    maxLength={120}
                    value={name}
                    disabled={saving}
                    onChange={(event) => setName(event.target.value)}
                  />
                  <div className="button-row">
                    <button type="submit" disabled={saving || !name.trim()}>
                      {saving ? 'Saving…' : 'Save name'}
                    </button>
                    <button
                      type="button"
                      className="quiet"
                      disabled={saving}
                      onClick={() => {
                        setEditing(null);
                        panel.current?.focus();
                      }}
                    >
                      Cancel
                    </button>
                  </div>
                </form>
              )}
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
