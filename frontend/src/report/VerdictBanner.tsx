import { CircleQuestionMark, OctagonX, Shield, ShieldAlert, ShieldX, TriangleAlert } from 'lucide-react';
import type { Assessment, CheckResult, Report } from '../types';
import { classificationTone, coverageText, CHECK_STATUS_LABEL, formatDate } from '../format';
import { SafeUrl } from '../components/SafeUrl';
import { FindingChip } from './FindingChip';

export const CAVEAT = 'No automated check can prove a site or message is safe.';

const ICONS = {
  low: Shield,
  suspicious: ShieldAlert,
  high: ShieldX,
  malicious: OctagonX,
  neutral: CircleQuestionMark,
} as const;

const PLAIN: Record<string, string> = {
  'Low Risk': 'No significant warning signs were found in the checks that completed.',
  Suspicious: 'Several warning signs were found. Treat it with caution.',
  'High Risk': 'Strong warning signs were found. Do not interact with it.',
  'Confirmed Malicious': 'An authoritative threat-intelligence source lists it as malicious.',
  Inconclusive: 'There was not enough completed evidence to reach a verdict.',
};

function Tally({ checks }: { checks: CheckResult[] }) {
  if (!checks.length) return null;
  return (
    <div className="tally" aria-hidden>
      {checks.map((c) => (
        <span key={c.name} className={`tally-cell chk-${c.status} ${c.essential ? 'is-essential' : ''}`} title={`${c.name}: ${CHECK_STATUS_LABEL[c.status] ?? c.status}${c.essential ? ' (essential)' : ''}`} />
      ))}
    </div>
  );
}

interface Props {
  report: Report;
  assessment: Assessment | null | undefined;
  onFocusFinding: (id: string) => void;
  knownFindingIds: Set<string>;
}

export function VerdictBanner({ report, assessment, onFocusFinding, knownFindingIds }: Props) {
  const cls = assessment?.classification ?? null;
  const tone = classificationTone(cls);
  const Icon = ICONS[tone];
  const cov = assessment?.coverage;
  return (
    <section className={`verdict tone-${tone}`} aria-labelledby="verdict-h" id="verdict">
      <div className="verdict-band" aria-hidden />
      <div className="verdict-main">
        <div className="verdict-subject">
          <span className="verdict-kind">{report.kind === 'url' ? 'Website' : 'Message'}</span>
          {report.kind === 'url' ? (
            <SafeUrl value={report.input_display} alreadyDefanged />
          ) : (
            <blockquote className="verdict-excerpt">{report.input_display}</blockquote>
          )}
        </div>
        <div className="verdict-row">
          <Icon className="verdict-icon" size={44} strokeWidth={1.75} aria-hidden />
          <div>
            <p className="verdict-label">Verdict</p>
            <h1 id="verdict-h" className="verdict-cls">
              {cls ?? 'No verdict'}
            </h1>
            <p className="verdict-plain">{cls ? PLAIN[cls] : report.status === 'complete' ? 'The analysis finished without an assessment.' : 'The analysis did not produce an assessment.'}</p>
          </div>
        </div>
        {assessment ? (
          <div className="verdict-rule">
            <code className="rule-id mono">{assessment.rule_id}</code>
            <span className="rule-text">{assessment.rule_text}</span>
          </div>
        ) : null}
        {assessment?.basis_finding_ids?.length ? (
          <div className="verdict-basis">
            <span className="mini-label">Based on</span>
            {assessment.basis_finding_ids.map((id) => (
              <FindingChip key={id} id={id} known={knownFindingIds.has(id)} onFocus={onFocusFinding} />
            ))}
          </div>
        ) : null}
      </div>
      <aside className="verdict-side">
        {cov ? (
          <div className="coverage">
            <p className="mini-label">Coverage</p>
            <p className="coverage-text">{coverageText(cov)}</p>
            <Tally checks={report.checks ?? []} />
            {cov.essential_missing.length ? (
              <p className="coverage-missing">
                <TriangleAlert size={14} aria-hidden /> Essential checks not completed:{' '}
                {cov.essential_missing.map((n, i) => (
                  <span key={n}>
                    {i ? ', ' : ''}
                    <code className="mono">{n}</code>
                  </span>
                ))}
              </p>
            ) : null}
          </div>
        ) : null}
        <dl className="verdict-meta">
          <div>
            <dt>Submitted</dt>
            <dd>{formatDate(report.created_at)}</dd>
          </div>
          <div>
            <dt>Completed</dt>
            <dd>{formatDate(report.completed_at)}</dd>
          </div>
          <div>
            <dt>Report ID</dt>
            <dd>
              <code className="mono">{report.id}</code>
            </dd>
          </div>
        </dl>
        <p className="caveat">{CAVEAT}</p>
      </aside>
    </section>
  );
}
