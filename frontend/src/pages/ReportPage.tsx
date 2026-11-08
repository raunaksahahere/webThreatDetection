import { useCallback, useEffect, useMemo, useState } from 'react';
import { ArrowLeft, FlaskConical, KeyRound, ListChecks, RefreshCw, TriangleAlert } from 'lucide-react';
import type { Report } from '../types';
import { ApiError, MOCK_MODE, errorMessage, getAnalysis } from '../api';
import { href } from '../router';
import { VerdictBanner } from '../report/VerdictBanner';
import { AIPanel } from '../report/AIPanel';
import { FindingsTable, type FocusRequest } from '../report/FindingsTable';
import { ChecksList } from '../report/ChecksList';
import { KeyValuePanel, RedirectChain } from '../report/NetworkPanels';
import { Indicators } from '../report/Indicators';
import { Correlations } from '../report/Correlations';
import { RegistryPanel } from '../report/RegistryPanel';
import { ProgressView, stageOf } from '../report/ProgressView';
import { FlowSteps } from '../components/FlowSteps';
import { Empty, Notice, Section } from '../components/Section';
import { DefinitionList } from '../components/ValueView';

interface LoadError {
  message: string;
  status: number;
  tokenRequired: boolean;
}

function useReport(id: string) {
  const [report, setReport] = useState<Report | null>(null);
  const [error, setError] = useState<LoadError | null>(null);
  const [nonce, setNonce] = useState(0);

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    let failures = 0;
    setReport((prev) => (prev && prev.id === id ? prev : null));
    const tick = async () => {
      try {
        const r = await getAnalysis(id);
        if (!alive) return;
        failures = 0;
        setReport(r);
        setError(null);
        if (r.status === 'queued' || r.status === 'running') timer = window.setTimeout(tick, 1500);
      } catch (e) {
        if (!alive) return;
        const status = (e as { status?: number }).status ?? 0;
        const tokenRequired = e instanceof ApiError && e.code === 'token_required';
        setError({ message: errorMessage(e), status, tokenRequired });
        const retriable = !tokenRequired && (status === 0 || status === 429 || status >= 500);
        if (retriable && failures < 20) {
          failures += 1;
          timer = window.setTimeout(tick, Math.min(10000, 1500 * 2 ** Math.min(failures, 3)));
        }
      }
    };
    void tick();
    return () => {
      alive = false;
      window.clearTimeout(timer);
    };
  }, [id, nonce]);

  const reload = useCallback(() => setNonce((n) => n + 1), []);
  return { report, error, reload };
}

const JUMPS = [
  ['verdict', 'Verdict'],
  ['ai', 'AI'],
  ['findings', 'Findings'],
  ['checks', 'Checks'],
  ['network', 'Network'],
  ['registry', 'Registry'],
] as const;

function jump(id: string) {
  document.getElementById(id)?.scrollIntoView({ behavior: 'smooth', block: 'start' });
}

export function ReportPage({ id }: { id: string }) {
  const { report, error, reload } = useReport(id);
  const [focus, setFocus] = useState<FocusRequest | null>(null);
  const onFocusFinding = useCallback((fid: string) => setFocus((prev) => ({ id: fid, n: (prev?.n ?? 0) + 1 })), []);

  useEffect(() => setFocus(null), [id]);

  const findings = report?.findings ?? [];
  const knownIds = useMemo(() => new Set(findings.map((f) => f.id)), [findings]);
  const basisIds = useMemo(() => new Set(report?.assessment?.basis_finding_ids ?? []), [report?.assessment]);
  const syntheticCount = findings.filter((f) => f.provenance === 'synthetic').length;

  const back = (
    <a className="back-link" href={href('/history')}>
      <ArrowLeft size={15} aria-hidden /> History
    </a>
  );

  if (!report) {
    if (error) {
      return (
        <div className="page">
          {back}
          <Notice
            tone={error.status === 404 ? 'neutral' : 'bad'}
            icon={error.tokenRequired ? <KeyRound size={18} aria-hidden /> : <TriangleAlert size={18} aria-hidden />}
            title={error.tokenRequired ? 'Operator token required' : error.status === 404 ? 'Report not found' : 'Could not load the report'}
          >
            <p>{error.message}</p>
            <button type="button" className="btn btn-secondary btn-sm" onClick={reload}>
              <RefreshCw size={14} aria-hidden /> {error.tokenRequired ? 'Enter token' : 'Try again'}
            </button>
          </Notice>
        </div>
      );
    }
    return (
      <div className="page">
        {back}
        <div className="skeleton-verdict" aria-busy="true" aria-label="Loading report" />
      </div>
    );
  }

  if (report.status === 'queued' || report.status === 'running') {
    return (
      <div className="page">
        {back}
        {error ? (
          <Notice tone="warn" title="Connection problem — retrying">
            {error.message}
          </Notice>
        ) : null}
        <ProgressView report={report} />
      </div>
    );
  }

  const failed = report.status === 'failed' || report.status === 'interrupted';
  const a = report.assessment;

  return (
    <div className="page report">
      <div className="report-top">
        {back}
        {MOCK_MODE ? <span className="mock-tag">Mock data</span> : null}
        <FlowSteps active={failed ? stageOf(report) : 5} failedAt={failed ? Math.min(stageOf(report), 4) : null} />
      </div>

      {syntheticCount ? (
        <div className="synthetic-banner" role="note">
          <FlaskConical size={18} aria-hidden />
          <span>
            <strong>Contains synthetic evidence.</strong> {syntheticCount} {syntheticCount === 1 ? 'finding comes' : 'findings come'} from a demo/test fixture, not real observations. Look for the striped “Synthetic fixture” badge.
          </span>
        </div>
      ) : null}

      {failed ? (
        <Notice tone="bad" icon={<TriangleAlert size={18} aria-hidden />} title={report.status === 'failed' ? 'The analysis failed' : 'The analysis was interrupted'}>
          {report.error ? <p className="mono-text">{report.error}</p> : <p>No error detail was recorded.</p>}
          <p>Anything shown below is partial. Missing checks are not evidence of safety.</p>
        </Notice>
      ) : null}

      <VerdictBanner report={report} assessment={a} onFocusFinding={onFocusFinding} knownFindingIds={knownIds} />

      <nav className="jumpbar" aria-label="Report sections">
        {JUMPS.map(([k, label]) => (
          <button key={k} type="button" onClick={() => jump(k)}>
            {label}
          </button>
        ))}
      </nav>

      <div className="report-grid">
        <div className="report-main">
          {a || report.recommended_actions?.length ? (
            <Section id="why" num="01" title="Why this verdict" className="why">
              <div className="why-grid">
                <div>
                  {a?.rationale?.length ? (
                    <ul className="rationale">
                      {a.rationale.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ul>
                  ) : (
                    <Empty>No rationale recorded.</Empty>
                  )}
                  {a?.contradictions?.length ? (
                    <div className="contradictions">
                      <h3 className="mini-label">Evidence pointing the other way</h3>
                      <ul>
                        {a.contradictions.map((c, i) => (
                          <li key={i}>{c}</li>
                        ))}
                      </ul>
                    </div>
                  ) : null}
                </div>
                <div className="todo">
                  <h3 className="todo-title">
                    <ListChecks size={16} aria-hidden /> What to do
                  </h3>
                  {report.recommended_actions?.length ? (
                    <ol className="todo-list">
                      {report.recommended_actions.map((r, i) => (
                        <li key={i}>{r}</li>
                      ))}
                    </ol>
                  ) : (
                    <Empty>No recommended actions recorded.</Empty>
                  )}
                </div>
              </div>
            </Section>
          ) : null}

          <AIPanel ai={report.ai} knownFindingIds={knownIds} onFocusFinding={onFocusFinding} num="02" />

          <Section id="findings" num="03" title="Findings" aside={<span className="count-tag">{findings.length}</span>}>
            <FindingsTable findings={findings} focus={focus} basisIds={basisIds} />
          </Section>

          <Section id="checks" num="04" title="Checks" aside={<span className="count-tag">{report.checks?.length ?? 0}</span>}>
            <ChecksList checks={report.checks ?? []} />
          </Section>

          <Section id="network" num="05" title="Redirect chain">
            <RedirectChain hops={report.redirects ?? []} />
          </Section>

          <div className="two-up">
            <Section id="tls" num="06" title="TLS">
              <KeyValuePanel data={report.tls} empty="No TLS data recorded (plain HTTP, skipped, or not applicable)." />
            </Section>
            <Section id="web" num="07" title="Web page">
              <KeyValuePanel data={report.web} empty="No page data recorded." />
            </Section>
          </div>
        </div>

        <aside className="report-side">
          <Section id="registry" num="08" title="Registry & integrity" className="registry-panel">
            <RegistryPanel report={report} onChanged={reload} />
          </Section>

          <Section id="indicators" num="09" title="Indicators" aside={<span className="count-tag">{report.indicators?.length ?? 0}</span>}>
            <Indicators items={report.indicators ?? []} />
          </Section>

          <Section id="correlations" num="10" title="Related reports">
            <Correlations items={report.correlations ?? []} />
          </Section>

          <Section id="limitations" num="11" title="Limitations" className="limits">
            {report.limitations?.length ? (
              <ul className="limit-list">
                {report.limitations.map((l, i) => (
                  <li key={i}>{l}</li>
                ))}
              </ul>
            ) : (
              <Empty>No limitations recorded.</Empty>
            )}
          </Section>

          <Section id="subject" num="12" title="Subject & input">
            {report.subject && Object.keys(report.subject).length ? <DefinitionList data={report.subject} /> : null}
            <dl className="deflist">
              <div className="deflist-row">
                <dt>input sha256</dt>
                <dd>
                  <code className="mono hash-wrap">{report.input_sha256}</code>
                </dd>
              </div>
              <div className="deflist-row">
                <dt>schema</dt>
                <dd className="mono">{report.schema_version ?? 'wtd.report.v1'}</dd>
              </div>
            </dl>
          </Section>
        </aside>
      </div>
    </div>
  );
}
