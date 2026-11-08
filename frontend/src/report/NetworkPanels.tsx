import { Ban, CornerDownRight } from 'lucide-react';
import type { Hop } from '../types';
import { formatMs } from '../format';
import { SafeUrl } from '../components/SafeUrl';
import { DefinitionList } from '../components/ValueView';
import { Empty } from '../components/Section';

export function RedirectChain({ hops }: { hops: Hop[] }) {
  if (!hops.length) return <Empty>No HTTP requests were made for this report.</Empty>;
  const sorted = hops.slice().sort((a, b) => a.index - b.index);
  return (
    <ol className="hops">
      {sorted.map((h) => {
        const blocked = Boolean(h.blocked_reason);
        const st = h.status ?? null;
        const stClass = st === null ? 'none' : st >= 500 ? '5xx' : st >= 400 ? '4xx' : st >= 300 ? '3xx' : '2xx';
        return (
          <li key={h.index} className={`hop ${blocked ? 'is-blocked' : ''}`}>
            <div className="hop-rail" aria-hidden>
              <span className="hop-dot">{h.index}</span>
            </div>
            <div className="hop-card">
              <div className="hop-top">
                <span className={`http-status st-${stClass}`}>{st ?? (blocked ? 'blocked' : 'no response')}</span>
                <span className="hop-host mono">{h.host}</span>
                {h.ip ? <span className="hop-ip mono">{h.ip}</span> : null}
                {h.tls_version ? <span className="hop-tls mono">{h.tls_version}</span> : null}
                {h.duration_ms ? <span className="hop-time mono">{formatMs(h.duration_ms)}</span> : null}
              </div>
              <SafeUrl value={h.url} />
              {h.location ? (
                <div className="hop-location">
                  <CornerDownRight size={14} aria-hidden />
                  <span className="mini-label">Location</span>
                  <SafeUrl value={h.location} />
                </div>
              ) : null}
              {blocked ? (
                <div className="hop-blocked" role="note">
                  <Ban size={14} aria-hidden />
                  <span>
                    <strong>Blocked:</strong> {h.blocked_reason}
                  </span>
                </div>
              ) : null}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

export function KeyValuePanel({ data, empty }: { data: Record<string, unknown> | null | undefined; empty: string }) {
  if (!data || !Object.keys(data).length) return <Empty>{empty}</Empty>;
  return <DefinitionList data={data} className="deflist-wide" />;
}
