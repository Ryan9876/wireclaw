import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, errorMessage } from './api';

export const fileSize = (bytes: number) =>
  bytes >= 1024 * 1024
    ? `${(bytes / (1024 * 1024)).toLocaleString(undefined, { maximumFractionDigits: 1 })} MiB`
    : `${bytes.toLocaleString()} bytes`;

function validateSelection(
  files: FileList | File[],
  limit: number | null,
): { file: File | null; error: string } {
  if (files.length !== 1) return { file: null, error: 'Select exactly one capture file.' };
  if (!files[0].size)
    return { file: null, error: 'The selected file is empty. Choose a PCAP or PCAPNG capture.' };
  if (limit && files[0].size > limit)
    return { file: null, error: `The capture exceeds the local limit of ${fileSize(limit)}.` };
  return { file: files[0], error: '' };
}

export function Intake({
  onStart,
  busy,
  fixedSymptom,
  initialFiles,
}: {
  onStart: (file: File, symptom: string) => Promise<void>;
  busy: boolean;
  fixedSymptom?: string;
  initialFiles?: File[];
}) {
  const [file, setFile] = useState<File | null>(() =>
    initialFiles ? validateSelection(initialFiles, null).file : null,
  );
  const [symptom, setSymptom] = useState(fixedSymptom ?? '');
  const [limit, setLimit] = useState<number | null>(null);
  const [limitError, setLimitError] = useState('');
  const [fileError, setFileError] = useState(() =>
    initialFiles ? validateSelection(initialFiles, null).error : '',
  );
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
    const selection = validateSelection(files, limit);
    setFile(selection.file);
    setFileError(selection.error);
  }
  const tooLarge = !!file && !!limit && file.size > limit;
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (file && limit && !tooLarge && symptom.trim() && !busy) await onStart(file, symptom);
  }
  return (
    <section
      className={`intake ${file ? 'has-file' : ''}`}
      aria-labelledby="intake-heading"
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
      <h1 id="intake-heading" className={file ? 'sr-only' : ''}>
        {fixedSymptom === undefined ? 'Start with a capture' : 'Resume capture intake'}
      </h1>
      <form onSubmit={submit}>
        <input
          ref={input}
          className="sr-only"
          id="capture-file"
          type="file"
          accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
          disabled={busy}
          aria-label="Select capture"
          aria-describedby="capture-help capture-error"
          aria-invalid={!!fileError || tooLarge}
          onChange={(event) => {
            if (event.target.files?.length) select(event.target.files);
          }}
        />
        {!file ? (
          <div className={`drop-zone ${dragging ? 'dragging' : ''}`}>
            <span className="file-icon" aria-hidden="true">
              ↥
            </span>
            <span>Drop PCAP or PCAPNG</span>
            <button
              type="button"
              className="primary"
              disabled={busy}
              onClick={() => input.current?.click()}
            >
              Choose file
            </button>
          </div>
        ) : (
          <div className={`selected-file ${dragging ? 'dragging' : ''}`} role="status">
            <span aria-hidden="true">▤</span>
            <div>
              <strong>{file.name}</strong>
              <span>{fileSize(file.size)}</span>
            </div>
            <button
              type="button"
              className="quiet"
              disabled={busy}
              onClick={() => input.current?.click()}
            >
              Replace
            </button>
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
        <div className="composer-wrap">
          <div className="composer">
            <button
              className="attach quiet"
              type="button"
              aria-label="Attach capture"
              disabled={busy}
              onClick={() => input.current?.click()}
            >
              ＋
            </button>
            <label className="sr-only" htmlFor="symptom">
              Symptom / problem description
            </label>
            <textarea
              id="symptom"
              rows={1}
              value={symptom}
              readOnly={fixedSymptom !== undefined}
              disabled={busy}
              maxLength={4096}
              required
              placeholder="What did users experience?"
              aria-describedby="symptom-help"
              onChange={(event) => setSymptom(event.target.value)}
            />
            <button
              className="send primary"
              type="submit"
              aria-label="Send"
              disabled={busy || !file || !symptom.trim() || !limit || tooLarge}
            >
              <span aria-hidden="true">↑</span>
            </button>
          </div>
          <p className="composer-hint" id="symptom-help">
            Attach a capture and describe the issue to begin.
          </p>
        </div>
      </form>
    </section>
  );
}
