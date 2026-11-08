import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { KeyRound } from 'lucide-react';
import { getTokenPrompt, resolveTokenPrompt, subscribeTokenPrompt } from '../api';

/**
 * Prompts for the operator API token (X-WTD-Token). The token is kept in sessionStorage for this
 * tab only. This is the only credential the dashboard ever asks for.
 */
export function TokenDialog() {
  const prompt = useSyncExternalStore(subscribeTokenPrompt, getTokenPrompt, () => null);
  const [value, setValue] = useState('');
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const d = dialog.current;
    if (!d) return;
    if (prompt && !d.open) {
      setValue('');
      d.showModal();
      window.setTimeout(() => input.current?.focus(), 0);
    } else if (!prompt && d.open) d.close();
  }, [prompt]);

  const finish = (token: string | null) => {
    setValue('');
    resolveTokenPrompt(token);
  };

  return (
    <dialog
      ref={dialog}
      className="dialog"
      aria-labelledby="token-title"
      onCancel={(e) => {
        e.preventDefault();
        finish(null);
      }}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          const t = value.trim();
          if (t) finish(t);
        }}
      >
        <div className="dialog-icon">
          <KeyRound size={22} aria-hidden />
        </div>
        <h2 id="token-title">Operator token</h2>
        {prompt?.reason === 'rejected' ? (
          <p className="dialog-warn" role="alert">
            The server rejected the token (401). Enter the current operator token.
          </p>
        ) : (
          <p>The analysis API needs the operator token configured on the server (WTD_API_TOKEN or data/api_token).</p>
        )}
        <label className="field">
          <span className="field-label">Token</span>
          <input
            ref={input}
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => setValue(e.target.value)}
            placeholder="Paste the operator token"
          />
        </label>
        <p className="dialog-fine">Kept in this browser tab only (sessionStorage) and sent as the X-WTD-Token header. It is cleared when the tab closes.</p>
        <div className="dialog-actions">
          <button type="button" className="btn btn-ghost" onClick={() => finish(null)}>
            Cancel
          </button>
          <button type="submit" className="btn btn-primary" disabled={!value.trim()}>
            Use token
          </button>
        </div>
      </form>
    </dialog>
  );
}
