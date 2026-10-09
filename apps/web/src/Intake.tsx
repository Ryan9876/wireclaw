import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, errorMessage } from './api';

export const fileSize = (bytes: number) =>
  bytes >= 1024 * 1024
    ? `${(bytes / (1024 * 1024)).toLocaleString(undefined, { maximumFractionDigits: 1 })} MiB`
    : `${bytes.toLocaleString()} bytes`;

export function Intake({
  onStart,
  busy,
  fixedSymptom,
}: {
  onStart: (file: File, symptom: string) => Promise<void>;
  busy: boolean;
  fixedSymptom?: string;
}) {
  const [file, setFile] = useState<File | null>(null);
  const [symptom, setSymptom] = useState(fixedSymptom ?? '');
  const [limit, setLimit] = useState<number | null>(null);
  const [limitError, setLimitError] = useState('');
  const [fileError, setFileError] = useState('');
  const [dragging, setDragging] = useState(false);
  const [retry, setRetry] = useState(0);
  const input = useRef<HTMLInputElement>(null);
  useEffect(() => {
    const controller = new AbortController();
    api
      .limits(controller.signal)
      .then((value) => {
        if (!controller.signal.aborted) {
          setLimit(value);
          setLimitError('');
        }
      })
      .catch((error) => {
        if (!controller.signal.aborted) setLimitError(errorMessage(error));
      });
    return () => controller.abort();
  }, [retry]);
  function select(files: FileList | File[]) {
    setFile(null);
    setFileError('');
    if (files.length !== 1) {
      setFileError('Select exactly one capture file.');
      return;
    }
    const selected = files[0];
    if (selected.size === 0) {
      setFileError('The selected file is empty. Choose a PCAP or PCAPNG capture.');
      return;
    }
    if (limit && selected.size > limit) {
      setFileError(`The capture exceeds the local limit of ${fileSize(limit)}.`);
      return;
    }
    setFile(selected);
  }
  const tooLarge = !!file && !!limit && file.size > limit;
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (file && limit && !tooLarge && symptom.trim() && !busy) await onStart(file, symptom);
  }
  return (
    <section className="panel intake" aria-labelledby="intake-heading">
      <div className="section-heading">
        <h2 id="intake-heading">
          {fixedSymptom === undefined ? 'Start an investigation' : 'Resume capture intake'}
        </h2>
        <span className="eyebrow">PCAP / PCAPNG</span>
      </div>
      <p className="muted">
        Provide the capture and what the user experienced. The analyzer establishes the facts; your
        symptom provides context.
      </p>
      <form onSubmit={submit}>
        <div
          className={`drop-zone ${dragging ? 'dragging' : ''}`}
          onDragOver={(event) => {
            event.preventDefault();
            if (!busy) setDragging(true);
          }}
          onDragLeave={() => setDragging(false)}
          onDrop={(event) => {
            event.preventDefault();
            setDragging(false);
            if (!busy) select(event.dataTransfer.files);
          }}
        >
          <span className="file-icon" aria-hidden="true">
            ↥
          </span>
          <strong>Drop a packet capture here</strong>
          <span className="muted">or select a local file</span>
          <label className="file-picker" htmlFor="capture-file">
            Select capture
          </label>
          <input
            ref={input}
            className="file-input"
            id="capture-file"
            type="file"
            accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
            disabled={busy}
            aria-describedby="capture-help capture-error"
            aria-invalid={!!fileError || tooLarge}
            onChange={(event) => {
              if (event.target.files?.length) select(event.target.files);
            }}
          />
        </div>
        <p id="capture-help" className="field-help">
          {limit
            ? `Local limit: ${fileSize(limit)}. Format is verified by the backend, not the filename.`
            : 'Reading the local API capture limit…'}
        </p>
        <p
          id="capture-error"
          className="field-error"
          role={fileError || tooLarge ? 'alert' : undefined}
        >
          {fileError || (tooLarge ? 'The selected capture exceeds the local size limit.' : '')}
        </p>
        {file && (
          <div className="selected-file" role="status">
            <div>
              <strong>{file.name}</strong>
              <span>{fileSize(file.size)} · Ready for local upload</span>
            </div>
            <button
              type="button"
              className="quiet"
              disabled={busy}
              onClick={() => {
                setFile(null);
                if (input.current) input.current.value = '';
              }}
            >
              Remove selection
            </button>
          </div>
        )}
        <label htmlFor="symptom">Symptom / problem description</label>
        <textarea
          id="symptom"
          rows={4}
          value={symptom}
          readOnly={fixedSymptom !== undefined}
          disabled={busy}
          maxLength={4096}
          required
          placeholder="For example: users report slow downloads to 192.0.2.20 over port 443."
          aria-describedby="symptom-help"
          onChange={(event) => setSymptom(event.target.value)}
        />
        <div className="field-help" id="symptom-help">
          <span>
            Include affected endpoints and timing when known. Context is not packet evidence.
          </span>
          <span>{symptom.length} / 4096</span>
        </div>
        {limitError && (
          <div className="error" role="alert">
            <p>{limitError}</p>
            <button
              type="button"
              onClick={() => {
                setLimitError('');
                setRetry(retry + 1);
              }}
            >
              Retry API connection
            </button>
          </div>
        )}
        <div className="intake-footer">
          <p>Capture stays in the local Wireclaw API. No model provider is used.</p>
          <button
            className="primary"
            type="submit"
            disabled={busy || !file || !symptom.trim() || !limit || tooLarge}
          >
            {busy ? 'Submitting…' : 'Investigate capture'} <span aria-hidden="true">→</span>
          </button>
        </div>
      </form>
    </section>
  );
}
