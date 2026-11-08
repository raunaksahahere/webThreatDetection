import type { ReactNode } from 'react';
import { humanKey, isUrlLike } from '../format';
import { SafeUrl } from './SafeUrl';
import { CopyButton } from './CopyButton';

/** Renders any JSON-ish value from the API as plain text. Objects are pretty-printed, never interpreted. */
export function ValueView({ value }: { value: unknown }): ReactNode {
  if (value === null || value === undefined) return <span className="val-null">none</span>;
  if (typeof value === 'boolean') return <span className={`val-bool ${value ? 'is-true' : 'is-false'}`}>{value ? 'yes' : 'no'}</span>;
  if (typeof value === 'number') return <span className="val-num mono">{String(value)}</span>;
  if (typeof value === 'string') {
    if (isUrlLike(value)) return <SafeUrl value={value} />;
    if (/^(0x)?[0-9a-f]{40,}$/i.test(value) || /^sha256:/i.test(value))
      return (
        <span className="val-hash">
          <code className="mono">{value}</code>
          <CopyButton value={value} />
        </span>
      );
    return <span className="val-str">{value}</span>;
  }
  if (Array.isArray(value)) {
    if (value.length === 0) return <span className="val-null">empty list</span>;
    if (value.every((v) => typeof v === 'string' || typeof v === 'number')) {
      return (
        <ul className="val-list">
          {value.map((v, i) => (
            <li key={i}>
              <ValueView value={v} />
            </li>
          ))}
        </ul>
      );
    }
  }
  let text: string;
  try {
    text = JSON.stringify(value, null, 2);
  } catch {
    text = String(value);
  }
  return <pre className="val-json mono">{text}</pre>;
}

/** Generic definition list for report.tls, report.web, report.subject, evidence maps. */
export function DefinitionList({ data, className = '' }: { data: Record<string, unknown>; className?: string }) {
  const keys = Object.keys(data);
  if (keys.length === 0) return <p className="muted">No data recorded.</p>;
  return (
    <dl className={`deflist ${className}`}>
      {keys.map((k) => (
        <div className="deflist-row" key={k}>
          <dt title={k}>{humanKey(k)}</dt>
          <dd>
            <ValueView value={data[k]} />
          </dd>
        </div>
      ))}
    </dl>
  );
}
