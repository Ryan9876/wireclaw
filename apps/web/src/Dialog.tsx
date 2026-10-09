import { useEffect, useRef, type ReactNode } from 'react';

export function Dialog({
  title,
  titleId,
  onClose,
  children,
  className = '',
  closeDisabled = false,
}: {
  title: string;
  titleId: string;
  onClose: () => void;
  children: ReactNode;
  className?: string;
  closeDisabled?: boolean;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const previous = document.activeElement as HTMLElement | null;
    const element = ref.current!;
    element.showModal();
    element.querySelector<HTMLElement>('[data-initial-focus]')?.focus();
    return () => {
      element.close();
      previous?.focus();
    };
  }, []);
  return (
    <dialog
      ref={ref}
      className={className}
      aria-labelledby={titleId}
      onKeyDown={(event) => {
        if (event.key !== 'Tab') return;
        const items = Array.from(
          event.currentTarget.querySelectorAll<HTMLElement>(
            'button:not(:disabled), input:not(:disabled), select:not(:disabled), textarea:not(:disabled), a[href], [tabindex="0"]',
          ),
        );
        const first = items[0];
        const last = items.at(-1);
        if (event.shiftKey && document.activeElement === first) {
          event.preventDefault();
          last?.focus();
        } else if (!event.shiftKey && document.activeElement === last) {
          event.preventDefault();
          first?.focus();
        }
      }}
      onCancel={(event) => {
        event.preventDefault();
        onClose();
      }}
    >
      <div className="dialog-heading">
        <h2 id={titleId}>{title}</h2>
        <button
          type="button"
          className="quiet"
          disabled={closeDisabled}
          onClick={onClose}
          aria-label={`Close ${title.toLowerCase()}`}
        >
          Close
        </button>
      </div>
      {children}
    </dialog>
  );
}
