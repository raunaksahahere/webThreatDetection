import { useEffect, useRef, useState } from 'react';
import { Check, Copy } from 'lucide-react';

async function copyText(text: string): Promise<boolean> {
  try {
    if (navigator.clipboard && window.isSecureContext) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch {
    /* fall through to legacy path */
  }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.setAttribute('readonly', '');
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch {
    return false;
  }
}

interface Props {
  value: string;
  label?: string;
  /** Visible text next to the icon; omit for an icon-only button. */
  text?: string;
  className?: string;
}

export function CopyButton({ value, label = 'Copy value', text, className = '' }: Props) {
  const [state, setState] = useState<'idle' | 'ok' | 'fail'>('idle');
  const timer = useRef<number | undefined>(undefined);
  useEffect(() => () => window.clearTimeout(timer.current), []);
  const onClick = async () => {
    const ok = await copyText(value);
    setState(ok ? 'ok' : 'fail');
    window.clearTimeout(timer.current);
    timer.current = window.setTimeout(() => setState('idle'), 1600);
  };
  return (
    <button
      type="button"
      className={`copy-btn ${state === 'ok' ? 'is-ok' : ''} ${className}`}
      onClick={onClick}
      title={label}
      aria-label={label}
    >
      {state === 'ok' ? <Check size={13} aria-hidden /> : <Copy size={13} aria-hidden />}
      {text ? <span>{state === 'ok' ? 'Copied' : state === 'fail' ? 'Copy failed' : text}</span> : null}
      <span className="sr-only" aria-live="polite">
        {state === 'ok' ? 'Copied' : state === 'fail' ? 'Copy failed' : ''}
      </span>
    </button>
  );
}
