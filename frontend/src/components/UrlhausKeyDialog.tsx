import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { Bug, LoaderCircle } from 'lucide-react';
import {
  URLHAUS_KEY_RE,
  checkUrlhausKey,
  clearUrlhausKey,
  errorMessage,
  getUrlhausKey,
  isUrlhausDialogOpen,
  onUrlhausKeyChange,
  setUrlhausDialogOpen,
  setUrlhausKey,
  subscribeUrlhausDialog,
} from '../api';

export function useUrlhausKey(): string | null {
  return useSyncExternalStore(onUrlhausKeyChange, getUrlhausKey, () => null);
}

/**
 * Lets a visitor (for example a hackathon judge) use their own abuse.ch URLhaus Auth-Key.
 * The key stays in this browser tab (sessionStorage) and is sent only with analysis requests.
 */
export function UrlhausKeyDialog() {
  const open = useSyncExternalStore(subscribeUrlhausDialog, isUrlhausDialogOpen, () => false);
  const saved = useUrlhausKey();
  const [value, setValue] = useState('');
  const [result, setResult] = useState<{ ok: boolean; text: string } | null>(null);
  const [testing, setTesting] = useState(false);
  const dialog = useRef<HTMLDialogElement>(null);
  const input = useRef<HTMLInputElement>(null);

  useEffect(() => {
    const d = dialog.current;
    if (!d) return;
    if (open && !d.open) {
      setValue('');
      setResult(null);
      d.showModal();
      window.setTimeout(() => input.current?.focus(), 0);
    } else if (!open && d.open) d.close();
  }, [open]);

  const key = value.trim();
  const shapeOk = URLHAUS_KEY_RE.test(key);
  const close = () => {
    setValue('');
    setUrlhausDialogOpen(false);
  };

  const test = async () => {
    setTesting(true);
    setResult(null);
    try {
      const r = await checkUrlhausKey(key);
      setResult({ ok: r.accepted, text: r.message });
    } catch (e) {
      setResult({ ok: false, text: errorMessage(e) });
    } finally {
      setTesting(false);
    }
  };

  return (
    <dialog
      ref={dialog}
      className="dialog"
      aria-labelledby="urlhaus-title"
      onCancel={(e) => {
        e.preventDefault();
        close();
      }}
    >
      <form
        onSubmit={(e) => {
          e.preventDefault();
          if (!shapeOk) return;
          setUrlhausKey(key);
          close();
        }}
      >
        <div className="dialog-icon">
          <Bug size={22} aria-hidden />
        </div>
        <h2 id="urlhaus-title">Your URLhaus key</h2>
        <p>
          URLhaus (abuse.ch) lists URLs that distribute malware. If this server has no key, or you prefer your own, paste your free Auth-Key from{' '}
          <a href="https://auth.abuse.ch/" target="_blank" rel="noopener noreferrer">
            auth.abuse.ch
          </a>
          .
        </p>
        {saved ? <p className="dialog-ok">A key is set for this tab. New analyses use it.</p> : null}
        <label className="field">
          <span className="field-label">Auth-Key</span>
          <input
            ref={input}
            type="password"
            autoComplete="off"
            spellCheck={false}
            value={value}
            onChange={(e) => {
              setValue(e.target.value);
              setResult(null);
            }}
            placeholder={saved ? 'Paste a different key to replace it' : 'Paste your abuse.ch Auth-Key'}
          />
        </label>
        {key && !shapeOk ? <p className="dialog-warn">An abuse.ch Auth-Key has only letters and digits (20 to 100 characters).</p> : null}
        {result ? (
          <p className={result.ok ? 'dialog-ok' : 'dialog-warn'} role="status">
            {result.text}
          </p>
        ) : null}
        <p className="dialog-fine">
          Saved in this browser tab only (sessionStorage) and cleared when the tab closes. It is sent as the X-URLhaus-Key header with each analysis, used for that analysis, and never saved on the server or written into a report.
        </p>
        <div className="dialog-actions">
          {saved ? (
            <button
              type="button"
              className="btn btn-ghost"
              onClick={() => {
                clearUrlhausKey();
                close();
              }}
            >
              Remove key
            </button>
          ) : null}
          <button type="button" className="btn btn-ghost" onClick={close}>
            Cancel
          </button>
          <button type="button" className="btn btn-secondary" disabled={!shapeOk || testing} onClick={test}>
            {testing ? <LoaderCircle size={16} className="spin" aria-hidden /> : null}
            Test key
          </button>
          <button type="submit" className="btn btn-primary" disabled={!shapeOk}>
            Save for this tab
          </button>
        </div>
      </form>
    </dialog>
  );
}
