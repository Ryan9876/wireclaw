import { useEffect, useRef, useState, type FormEvent } from 'react';
import { api, errorMessage, type Followup } from './api';

type Turn = { question: string; response?: Followup; error?: string };

export function Conversation({
  caseId,
  enabled,
  onEvidence,
  onAttach,
}: {
  caseId: string;
  enabled: boolean;
  onEvidence: (ids: string[]) => void;
  onAttach: (files: File[]) => void;
}) {
  const [question, setQuestion] = useState('');
  const [turns, setTurns] = useState<Turn[]>([]);
  const [busy, setBusy] = useState(false);
  const captureInput = useRef<HTMLInputElement>(null);
  const request = useRef<AbortController | null>(null);
  useEffect(() => () => request.current?.abort(), []);
  async function submit(event: FormEvent) {
    event.preventDefault();
    if (!enabled || request.current || !question.trim()) return;
    const currentQuestion = question.trim();
    const controller = new AbortController();
    request.current = controller;
    setBusy(true);
    setQuestion('');
    setTurns((previous) => [...previous, { question: currentQuestion }]);
    try {
      // Prior turns are display-only; only the current question crosses the API boundary.
      const response = await api.followup(caseId, currentQuestion, controller.signal);
      if (!controller.signal.aborted)
        setTurns((previous) => [...previous.slice(0, -1), { question: currentQuestion, response }]);
    } catch (failure) {
      if (!controller.signal.aborted)
        setTurns((previous) => [
          ...previous.slice(0, -1),
          { question: currentQuestion, error: errorMessage(failure) },
        ]);
    } finally {
      if (!controller.signal.aborted) {
        request.current = null;
        setBusy(false);
      }
    }
  }
  return (
    <>
      <section className="followups" aria-label="Questions about this report">
        {turns.map((turn, index) => (
          <div className="turn" key={index}>
            <p className="user-question">{turn.question}</p>
            {turn.response && (
              <article className="reply" aria-label="Explanation about this report">
                <p className="answer-label">Wireclaw · About this report</p>
                <p>{turn.response.answer}</p>
                <div className="evidence-links">
                  {turn.response.evidence_ids.map((id) => (
                    <button key={id} className="evidence-id" onClick={() => onEvidence([id])}>
                      {id}
                    </button>
                  ))}
                </div>
              </article>
            )}
            {turn.error && (
              <p className="error" role="alert">
                {turn.error}
              </p>
            )}
          </div>
        ))}
      </section>
      <p className="sr-only" role="status" aria-live="polite">
        {busy ? 'Answering your question…' : turns.at(-1)?.response ? 'Explanation ready.' : ''}
      </p>
      <form className="composer-wrap" onSubmit={submit}>
        <div className="composer">
          <input
            ref={captureInput}
            className="sr-only"
            type="file"
            accept=".pcap,.pcapng,.cap,application/vnd.tcpdump.pcap"
            aria-label="Select new capture"
            onChange={(event) => {
              if (event.target.files?.length) onAttach(Array.from(event.target.files));
            }}
          />
          <button
            type="button"
            className="attach quiet"
            aria-label="Attach a new capture"
            onClick={() => captureInput.current?.click()}
          >
            ＋
          </button>
          <label className="sr-only" htmlFor="question">
            Question about this report
          </label>
          <textarea
            id="question"
            rows={1}
            value={question}
            disabled={!enabled}
            maxLength={2000}
            placeholder="Ask about this analysis…"
            aria-describedby="followup-help"
            onChange={(event) => setQuestion(event.target.value)}
          />
          <button
            className="send primary"
            type="submit"
            aria-label="Send"
            disabled={!enabled || busy || !question.trim()}
          >
            <span aria-hidden="true">↑</span>
          </button>
        </div>
        <p className="composer-hint" id="followup-help">
          {!enabled
            ? 'Follow-up is unavailable in rules-only mode or while the provider is unavailable.'
            : busy
              ? 'Answering your question…'
              : 'Answers explain this report and cited evidence. Each question is answered independently.'}
        </p>
      </form>
    </>
  );
}
