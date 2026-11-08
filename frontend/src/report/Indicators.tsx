import type { Indicator } from '../types';
import { CopyButton } from '../components/CopyButton';
import { Empty } from '../components/Section';
import { middleTruncate } from '../format';

const LABEL: Record<string, string> = {
  url: 'URL',
  domain: 'Domain',
  ip: 'IP',
  email: 'Email',
  phone: 'Phone',
  upi: 'UPI ID',
  crypto_wallet: 'Wallet',
  brand: 'Brand',
  cert_spki: 'Cert key',
};

export function Indicators({ items }: { items: Indicator[] }) {
  if (!items.length) return <Empty>No indicators extracted.</Empty>;
  return (
    <ul className="indicators">
      {items.map((i, n) => (
        <li key={`${i.type}-${n}`} className="indicator">
          <span className={`ind-type ind-${i.type}`}>{LABEL[i.type] ?? i.type}</span>
          <code className="mono ind-value">{i.display}</code>
          {i.hashed ? (
            <span className="ind-hashed" title={`Personal identifier: matched by keyed hash only (${middleTruncate(i.match_key, 6)})`}>
              hashed
            </span>
          ) : null}
          <CopyButton value={i.display} label="Copy defanged value" />
        </li>
      ))}
    </ul>
  );
}
