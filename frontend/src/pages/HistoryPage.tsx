import { useCallback, useEffect, useState } from 'react';
import { Globe, LoaderCircle, Mail, RefreshCw } from 'lucide-react';
import type { AnalysisSummary } from '../types';
import { errorMessage, listAnalyses } from '../api';
import { formatDate, formatRelative, shortId } from '../format';
import { href, navigate, reportPath } from '../router';
import { ClassificationBadge } from '../components/Badges';
import { Empty, Notice } from '../components/Section';

export function HistoryPage() {
  const [items, setItems] = useState<AnalysisSummary[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setItems(await listAnalyses(50));
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
          <p className="eyebrow">Case log</p>
          <h1 className="page-title">History</h1>
          <p className="page-lede">The 50 most recent analyses, newest first.</p>
        </div>
        <button type="button" className="btn btn-secondary" onClick={() => void load()} disabled={loading}>
          {loading ? <LoaderCircle size={15} className="spin" aria-hidden /> : <RefreshCw size={15} aria-hidden />} Refresh
        </button>
      </div>
      {error ? (
        <Notice tone="bad" title="Could not load history">
          {error}
        </Notice>
      ) : null}
      {items === null && !error ? <div className="skeleton-table" aria-busy="true" aria-label="Loading" /> : null}
      {items && items.length === 0 ? (
        <Empty>
          No analyses yet. <a href={href('/')}>Start an investigation</a>.
        </Empty>
      ) : null}
      {items && items.length > 0 ? (
        <div className="table-wrap">
          <table className="table history-table">
            <thead>
              <tr>
                <th scope="col">Verdict</th>
                <th scope="col">Input</th>
                <th scope="col">Kind</th>
                <th scope="col">Status</th>
                <th scope="col">Submitted</th>
                <th scope="col">Report</th>
              </tr>
            </thead>
            <tbody>
              {items.map((it) => (
                <tr key={it.id} className="row-link" onClick={() => navigate(reportPath(it.id))}>
                  <td>{it.classification ? <ClassificationBadge value={it.classification} size="sm" /> : <span className="status-chip">{it.status}</span>}</td>
                  <td className="input-cell">
                    <code className="mono">{it.input_display}</code>
                  </td>
                  <td>
                    <span className="kind-chip">
                      {it.kind === 'url' ? <Globe size={13} aria-hidden /> : <Mail size={13} aria-hidden />}
                      {it.kind === 'url' ? 'URL' : 'Message'}
                    </span>
                  </td>
                  <td>
                    <span className={`status-chip st-${it.status}`}>{it.status}</span>
                  </td>
                  <td title={formatDate(it.created_at)}>{formatRelative(it.created_at) || formatDate(it.created_at)}</td>
                  <td>
                    <a className="mono" href={href(reportPath(it.id))} onClick={(e) => e.stopPropagation()}>
                      {shortId(it.id)}
                    </a>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      ) : null}
    </div>
  );
}
