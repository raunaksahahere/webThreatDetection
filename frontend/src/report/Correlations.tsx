import { ArrowRight } from 'lucide-react';
import type { CorrelationLink } from '../types';
import { ClassificationBadge } from '../components/Badges';
import { Empty } from '../components/Section';
import { formatDate, shortId } from '../format';
import { href, reportPath } from '../router';

const METHOD: Record<string, string> = {
  exact_indicator: 'Same indicator',
  message_similarity: 'Similar message text',
  brand_pattern: 'Same brand pattern',
  infrastructure: 'Shared infrastructure',
};

export function Correlations({ items }: { items: CorrelationLink[] }) {
  if (!items.length) return <Empty>No related reports found in the local report store.</Empty>;
  return (
    <ul className="correlations">
      {items.map((c) => (
        <li key={c.other_report_id + c.method} className="corr">
          <div className="corr-head">
            <span className="corr-method">{METHOD[c.method] ?? c.method}</span>
            {c.method === 'message_similarity' && typeof c.score === 'number' ? <span className="corr-score mono">{c.score}% similar text</span> : null}
          </div>
          <ul className="corr-shared">
            {c.shared.map((s, i) => (
              <li key={i} className="mono">
                {s}
              </li>
            ))}
          </ul>
          <a className="corr-link" href={href(reportPath(c.other_report_id))}>
            <ClassificationBadge value={c.other_classification} size="sm" />
            <span className="mono">Report {shortId(c.other_report_id)}</span>
            <span className="muted">{formatDate(c.other_created_at)}</span>
            <ArrowRight size={14} aria-hidden />
          </a>
        </li>
      ))}
    </ul>
  );
}
