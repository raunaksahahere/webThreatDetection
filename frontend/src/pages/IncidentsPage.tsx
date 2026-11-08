import { useCallback, useEffect, useState } from 'react';
import { LoaderCircle, Network, RefreshCw } from 'lucide-react';
import type { Incident } from '../types';
import { errorMessage, listIncidents } from '../api';
import { formatDate, shortId } from '../format';
import { href, reportPath } from '../router';
import { Empty, Notice } from '../components/Section';
import { ClassificationBadge } from '../components/Badges';

export function IncidentsPage() {
  const [items, setItems] = useState<Incident[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setItems(await listIncidents());
      setError(null);
    } catch (e) {
      setError(errorMessage(e));
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  return (
    <div className="page">
      <div className="page-head">
        <div>
          <p className="eyebrow">Campaign board</p>
          <h1 className="page-title">Incidents</h1>
          <p className="page-lede">Reports grouped because they share indicators, infrastructure or message patterns.</p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => void load()} disabled={loading}>
          {loading ? <LoaderCircle size={15} className="spin" aria-hidden /> : <RefreshCw size={15} aria-hidden />} Refresh
        </button>
      </div>
      {error ? (
        <Notice tone="bad" title="Could not load incidents">
          {error}
        </Notice>
      ) : null}
      {items === null && !error ? <div className="skeleton-table" aria-busy="true" aria-label="Loading" /> : null}
      {items && items.length === 0 ? <Empty>No incident clusters yet. Clusters appear when two or more reports share evidence.</Empty> : null}
      {items && items.length > 0 ? (
        <ul className="incidents">
          {items.map((c) => (
            <li key={c.cluster_id} className="incident">
              <div className="incident-head">
                <Network size={18} aria-hidden />
                <code className="mono incident-id">{c.cluster_id}</code>
                <span className="count-tag">
                  {c.report_ids.length} {c.report_ids.length === 1 ? 'report' : 'reports'}
                </span>
              </div>
              {c.classifications?.length ? (
                <div className="incident-cls">
                  {c.classifications.map((k) => (
                    <ClassificationBadge key={k} value={k} size="sm" />
                  ))}
                </div>
              ) : null}
              <div className="incident-span">
                <span>
                  <span className="mini-label">First seen</span> {formatDate(c.first_seen)}
                </span>
                <span>
                  <span className="mini-label">Last seen</span> {formatDate(c.last_seen)}
                </span>
              </div>
              <div>
                <span className="mini-label">Shared evidence</span>
                <ul className="shared-list">
                  {c.shared.map((s, i) => (
                    <li key={i} className="mono">
                      {s}
                    </li>
                  ))}
                </ul>
              </div>
              <div className="incident-reports">
                {c.report_ids.map((rid) => (
                  <a key={rid} className="report-pill mono" href={href(reportPath(rid))}>
                    {shortId(rid)}
                  </a>
                ))}
              </div>
            </li>
          ))}
        </ul>
      ) : null}
    </div>
  );
}
