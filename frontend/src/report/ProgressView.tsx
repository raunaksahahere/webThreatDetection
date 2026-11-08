import { useEffect, useState } from 'react';
import { LoaderCircle } from 'lucide-react';
import type { Report } from '../types';
import { FlowSteps } from '../components/FlowSteps';
import { CheckStatusBadge } from '../components/Badges';
import { SafeUrl } from '../components/SafeUrl';

const ANALYSE_MODULES = new Set(['intel', 'content', 'message', 'correlation', 'ai']);

/** Infers the active flow step from what the report contains so far (the API has no explicit stage field). */
export function stageOf(r: Report): number {
  if (r.status === 'complete') return 5;
  if (r.status === 'queued') return 1;
  if (r.assessment) return 3;
  const checks = r.checks ?? [];
  if (checks.some((c) => ANALYSE_MODULES.has(c.module))) return 2;
  return 1;
}

const STAGE_TEXT = ['Submitted', 'Investigating: URL structure, DNS, TLS, redirects and page fetch', 'Analysing: threat intelligence, content, correlations and AI explanation', 'Assessing risk with fixed rules', 'Writing the report'];

function useElapsed(since: string): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const t = window.setInterval(() => setNow(Date.now()), 1000);
    return () => window.clearInterval(t);
  }, []);
  const t0 = new Date(since).getTime();
  return Number.isNaN(t0) ? 0 : Math.max(0, Math.round((now - t0) / 1000));
}

export function ProgressView({ report }: { report: Report }) {
  const stage = stageOf(report);
  const elapsed = useElapsed(report.created_at);
  const checks = report.checks ?? [];
  return (
    <section className="progress panel" aria-live="polite" aria-busy="true">
      <div className="progress-head">
        <LoaderCircle size={22} className="spin" aria-hidden />
        <div>
          <p className="eyebrow">{report.status === 'queued' ? 'Queued' : 'Running'} · {elapsed}s elapsed</p>
          <h1 className="progress-title">{report.status === 'queued' ? 'Waiting for an inspector to pick this up' : STAGE_TEXT[stage] ?? 'Working'}</h1>
        </div>
      </div>
      <div className="progress-subject">
        {report.kind === 'url' ? <SafeUrl value={report.input_display} alreadyDefanged /> : <blockquote className="verdict-excerpt">{report.input_display}</blockquote>}
      </div>
      <FlowSteps active={stage} detailed live />
      {checks.length ? (
        <ul className="progress-checks">
          {checks.map((c) => (
            <li key={c.name}>
              <code className="mono">{c.name}</code>
              <CheckStatusBadge value={c.status} />
            </li>
          ))}
        </ul>
      ) : null}
      <p className="fine">This page refreshes every 1.5 seconds until the report is ready.</p>
    </section>
  );
}
