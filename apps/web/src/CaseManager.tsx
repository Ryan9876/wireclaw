import { useRef, useState } from 'react';
import type { Capture, Case, CaptureNetworkSubtype, CaptureVantage } from './api';
import { fileSize } from './Intake';

const vantageLabels: Record<CaptureVantage, string> = {
  unknown: 'Unknown',
  client: 'Client',
  network: 'Network',
  server: 'Server',
  other: 'Other',
};
const subtypes: CaptureNetworkSubtype[] = [
  'Firewall',
  'Router',
  'Switch',
  'Load balancer',
  'Proxy',
  'Wireless',
  'Other network device',
];

export function CaseManager({
  record,
  busy,
  onAdd,
  onUpdate,
  onRemove,
}: {
  record: Case;
  busy: boolean;
  onAdd: (files: File[]) => void;
  onUpdate: (
    captureId: string,
    changes: { vantage_type?: CaptureVantage; vantage_subtype?: CaptureNetworkSubtype | null },
  ) => void;
  onRemove: (captureId: string) => void;
}) {
  const input = useRef<HTMLInputElement>(null);
  const [collapsed, setCollapsed] = useState(false);
  const [removeTarget, setRemoveTarget] = useState<Capture | null>(null);
  const captures = record.captures;
  const remaining = Math.max(0, 4 - captures.length);
  function add(files: FileList | File[]) {
    const selected = Array.from(files).slice(0, remaining);
    if (selected.length) onAdd(selected);
  }
  return (
    <aside className={`case-manager${collapsed ? ' is-collapsed' : ''}`} aria-label="Case Manager">
      <header className="case-manager-header">
        <div>
          <h2>Case Manager</h2>
          <p>
            {record.display_name || record.name} · {captures.length}/4 captures
          </p>
        </div>
        <button
          type="button"
          className="quiet"
          aria-label={`${collapsed ? 'Expand' : 'Collapse'} Case Manager`}
          onClick={() => setCollapsed((value) => !value)}
        >
          {collapsed ? '＋' : '−'}
        </button>
      </header>
      {!collapsed && (
        <>
          <ul className="case-manager-captures">
            {captures.map((capture) => (
              <li key={capture.id} className="case-manager-capture">
                <div className="case-manager-capture-heading">
                  <strong>{capture.display_name || capture.capture_name}</strong>
                  <span>{capture.bytes === null ? 'Size unknown' : fileSize(capture.bytes)}</span>
                </div>
                <p className={`capture-status status-${capture.status}`}>
                  {capture.status.replace('_', ' ').replace(/^./, (letter) => letter.toUpperCase())}
                </p>
                <label>
                  Vantage for {capture.display_name || capture.capture_name}
                  <select
                    aria-label={`Vantage for ${capture.display_name || capture.capture_name}`}
                    value={capture.vantage_type}
                    disabled={busy}
                    onChange={(event) =>
                      onUpdate(capture.id, {
                        vantage_type: event.target.value as CaptureVantage,
                        ...(event.target.value !== 'network' ? { vantage_subtype: null } : {}),
                      })
                    }
                  >
                    {Object.entries(vantageLabels).map(([value, label]) => (
                      <option value={value} key={value}>
                        {label}
                      </option>
                    ))}
                  </select>
                </label>
                {capture.vantage_type === 'network' && (
                  <label>
                    Network device type for {capture.display_name || capture.capture_name}
                    <select
                      aria-label={`Network device type for ${capture.display_name || capture.capture_name}`}
                      value={capture.vantage_subtype ?? ''}
                      disabled={busy}
                      onChange={(event) =>
                        onUpdate(capture.id, {
                          vantage_subtype: (event.target.value ||
                            null) as CaptureNetworkSubtype | null,
                        })
                      }
                    >
                      <option value="">Choose a device type</option>
                      {subtypes.map((subtype) => (
                        <option key={subtype}>{subtype}</option>
                      ))}
                    </select>
                  </label>
                )}
                <button
                  type="button"
                  className="quiet danger"
                  disabled={busy}
                  aria-label={`Remove ${capture.display_name || capture.capture_name}`}
                  onClick={() => setRemoveTarget(capture)}
                >
                  Remove capture
                </button>
              </li>
            ))}
          </ul>
          <input
            ref={input}
            className="sr-only"
            type="file"
            multiple
            accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
            aria-label="Choose captures to add"
            disabled={busy || remaining === 0}
            onChange={(event) => {
              if (event.target.files) add(event.target.files);
              event.currentTarget.value = '';
            }}
          />
          <button
            type="button"
            className="case-manager-drop"
            aria-label="Add capture"
            disabled={busy || remaining === 0}
            onClick={() => input.current?.click()}
            onDragOver={(event) => event.preventDefault()}
            onDrop={(event) => {
              event.preventDefault();
              add(event.dataTransfer.files);
            }}
          >
            Drop captures here or choose files · {remaining} remaining
          </button>
        </>
      )}
      {removeTarget && (
        <div className="case-manager-scrim">
          <section role="alertdialog" aria-modal="true" aria-labelledby="remove-capture-title">
            <h3 id="remove-capture-title">Remove capture?</h3>
            <p>Remove {removeTarget.display_name || removeTarget.capture_name} from this case?</p>
            <div className="button-row">
              <button type="button" onClick={() => setRemoveTarget(null)}>
                Keep capture
              </button>
              <button
                type="button"
                className="danger solid"
                onClick={() => {
                  onRemove(removeTarget.id);
                  setRemoveTarget(null);
                }}
              >
                Remove capture
              </button>
            </div>
          </section>
        </div>
      )}
    </aside>
  );
}
