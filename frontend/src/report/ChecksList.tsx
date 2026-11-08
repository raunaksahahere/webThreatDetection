import { useMemo } from 'react';
import type { CheckResult, CheckStatus } from '../types';
import { CHECK_STATUS_LABEL, CHECK_STATUS_ORDER, formatMs } from '../format';
import { CheckStatusBadge } from '../components/Badges';
import { Empty } from '../components/Section';

export function ChecksList({ checks }: { checks: CheckResult[] }) {
  const sorted = useMemo(
    () =>
      checks
        .slice()
        .sort(
          (a, b) =>
            CHECK_STATUS_ORDER.indexOf(a.status) - CHECK_STATUS_ORDER.indexOf(b.status) ||
            Number(b.essential) - Number(a.essential) ||
            a.name.localeCompare(b.name),
        ),
    [checks],
  );
  const counts = useMemo(() => {
    const c: Partial<Record<CheckStatus, number>> = {};
    for (const k of checks) c[k.status] = (c[k.status] ?? 0) + 1;
    return c;
  }, [checks]);

  if (!checks.length) return <Empty>No checks have been recorded yet.</Empty>;

  return (
    <div className="checks">
      <div className="check-summary">
        {CHECK_STATUS_ORDER.slice()
          .reverse()
          .map((s) => (
            <span key={s} className={`check-count chk-${s} ${counts[s] ? '' : 'is-zero'}`}>
              <b>{counts[s] ?? 0}</b> {CHECK_STATUS_LABEL[s].toLowerCase()}
            </span>
          ))}
      </div>
      <div className="table-wrap">
        <table className="table checks-table">
          <thead>
            <tr>
              <th scope="col">Check</th>
              <th scope="col">Status</th>
              <th scope="col">Detail</th>
              <th scope="col" className="num">
                Time
              </th>
            </tr>
          </thead>
          <tbody>
            {sorted.map((c) => (
              <tr key={c.name} className={`chk-row-${c.status}`}>
                <td>
                  <code className="mono check-name">{c.name}</code>
                  {c.essential ? (
                    <span className="essential-tag" title="Essential checks gate a Low Risk verdict; if one is missing the verdict is Inconclusive">
                      essential
                    </span>
                  ) : null}
                </td>
                <td>
                  <CheckStatusBadge value={c.status} />
                </td>
                <td className="check-detail">{c.detail || <span className="muted">—</span>}</td>
                <td className="num mono">{c.duration_ms ? formatMs(c.duration_ms) : ''}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
