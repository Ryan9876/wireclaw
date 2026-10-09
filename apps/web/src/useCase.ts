import { useCallback, useEffect, useRef, useState } from 'react';
import { api, errorMessage, isRunning, revision, validCaseId, type Case, type Report } from './api';

function fragmentCase() {
  const match = /^#case=([a-f0-9]{32})$/.exec(window.location.hash);
  return match?.[1] ?? null;
}

export function useCase() {
  const [id, setId] = useState<string | null>(fragmentCase);
  const [record, setRecord] = useState<Case | null>(null);
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState('');
  const [notice, setNotice] = useState('');
  const [busy, setBusy] = useState(false);
  const currentId = useRef(id);
  const operation = useRef(false);
  const generation = useRef(0);
  const publishedRevision = useRef('');
  const abort = useRef<AbortController | null>(null);
  const cancelRefresh = useCallback(() => {
    generation.current++;
    abort.current?.abort();
  }, []);

  const select = useCallback((next: string | null) => {
    generation.current++;
    abort.current?.abort();
    currentId.current = next;
    publishedRevision.current = '';
    setRecord(null);
    setReport(null);
    setError('');
    setId(next);
    window.history.replaceState(
      null,
      '',
      `${window.location.pathname}${window.location.search}${next ? `#case=${next}` : ''}`,
    );
  }, []);

  const refresh = useCallback(async (caseId = currentId.current) => {
    if (!caseId || caseId !== currentId.current) return;
    const ticket = ++generation.current;
    abort.current?.abort();
    const controller = new AbortController();
    abort.current = controller;
    const active = () => ticket === generation.current && caseId === currentId.current;
    try {
      const before = await api.get(caseId, controller.signal);
      if (!active()) return;
      setRecord(before);
      if (before.state !== 'COMPLETE' || isRunning(before)) {
        publishedRevision.current = '';
        setReport(null);
      } else if (revision(before) !== publishedRevision.current) {
        setReport(null);
        const result = await api.report(caseId, controller.signal);
        const after = await api.get(caseId, controller.signal);
        if (!active()) return;
        setRecord(after);
        if (
          revision(before) === revision(after) &&
          after.state === 'COMPLETE' &&
          !isRunning(after) &&
          result.symptom === after.symptom
        ) {
          publishedRevision.current = revision(after);
          setReport(result);
        } else {
          publishedRevision.current = '';
          setReport(null);
        }
      }
      if (active()) setError('');
    } catch (failure) {
      if (active() && !controller.signal.aborted) {
        setError(errorMessage(failure));
        setReport(null);
        publishedRevision.current = '';
      }
    }
  }, []);

  useEffect(() => {
    if (!id) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      await refresh(id);
      if (!disposed) timer = setTimeout(poll, 1200);
    }
    void poll();
    return () => {
      disposed = true;
      clearTimeout(timer);
      cancelRefresh();
    };
  }, [id, refresh, cancelRefresh]);

  useEffect(() => {
    const onHash = () => {
      if (!operation.current) select(fragmentCase());
    };
    window.addEventListener('hashchange', onHash);
    return () => window.removeEventListener('hashchange', onHash);
  }, [select]);

  async function mutate(task: () => Promise<void>) {
    if (operation.current) return;
    operation.current = true;
    setBusy(true);
    setError('');
    setNotice('');
    generation.current++;
    abort.current?.abort();
    publishedRevision.current = '';
    setReport(null);
    try {
      await task();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      operation.current = false;
      setBusy(false);
    }
  }

  async function start(file: File, symptom: string) {
    await mutate(async () => {
      const created = await api.create(symptom);
      select(created.id);
      setRecord(created);
      try {
        await api.upload(created.id, file);
        await api.investigate(created.id);
      } finally {
        await refresh(created.id);
      }
    });
  }

  async function investigate() {
    const caseId = currentId.current;
    if (!caseId) return;
    await mutate(async () => {
      try {
        await api.investigate(caseId);
      } finally {
        await refresh(caseId);
      }
    });
  }

  async function resumeUpload(file: File) {
    const caseId = currentId.current;
    if (!caseId) return;
    await mutate(async () => {
      try {
        await api.upload(caseId, file);
        await api.investigate(caseId);
      } finally {
        await refresh(caseId);
      }
    });
  }

  async function remove() {
    const caseId = currentId.current;
    if (!caseId) return;
    await mutate(async () => {
      const result = await api.delete(caseId);
      select(null);
      setNotice(
        result.cleanup_pending
          ? `Case ${caseId} removed from the case registry. Stored capture/artifact cleanup is pending; the service will retry cleanup on restart.`
          : `Case ${caseId} deleted, including its stored original capture, normalized evidence, and report. Your source file is unchanged.`,
      );
    });
  }

  function recover(value: string) {
    if (!validCaseId(value)) {
      setError('Enter a 32-character lowercase hexadecimal case ID.');
      return;
    }
    if (!operation.current) {
      setNotice('');
      select(value);
    }
  }

  const newCase = () => {
    if (!operation.current) {
      setNotice('');
      select(null);
    }
  };
  return {
    id,
    record,
    report,
    error,
    notice,
    busy,
    refresh,
    start,
    resumeUpload,
    investigate,
    remove,
    recover,
    newCase,
  };
}
