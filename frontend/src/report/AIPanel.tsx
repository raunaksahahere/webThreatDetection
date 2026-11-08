import { Bot, BotOff, CircleCheck, CircleSlash, CircleX, Quote, ShieldBan, TriangleAlert } from 'lucide-react';
import type { AIResult, AIStatus } from '../types';
import { formatMs } from '../format';
import { FindingChip } from './FindingChip';
import { Section } from '../components/Section';

const STATE: Record<AIStatus, { label: string; text: string }> = {
  ok: { label: 'Explanation available', text: '' },
  unavailable: {
    label: 'AI unavailable',
    text: 'The AI provider could not be reached, so there is no AI explanation for this report. The verdict comes from fixed rules and is not affected.',
  },
  failed: {
    label: 'AI failed',
    text: 'The AI provider returned an error, so there is no AI explanation for this report. The verdict comes from fixed rules and is not affected.',
  },
  disabled: {
    label: 'AI disabled',
    text: 'AI explanations are turned off on this server. The verdict comes from fixed rules and is not affected.',
  },
  rejected: {
    label: 'AI output rejected',
    text: 'The AI produced an explanation, but it failed validation against the evidence and has been discarded. Nothing from it is shown. The verdict comes from fixed rules and is not affected.',
  },
};

const ICON: Record<AIStatus, typeof Bot> = { ok: Bot, unavailable: CircleSlash, failed: CircleX, disabled: BotOff, rejected: ShieldBan };

interface Props {
  ai: AIResult | null | undefined;
  knownFindingIds: Set<string>;
  onFocusFinding: (id: string) => void;
  num: string;
}

export function AIPanel({ ai, knownFindingIds, onFocusFinding, num }: Props) {
  const status: AIStatus | 'none' = ai?.status ?? 'none';
  const Icon = status === 'none' ? BotOff : ICON[status];
  const badge = (
    <span className={`ai-badge ai-${status}`}>
      <Icon size={14} aria-hidden />
      <span>{status === 'none' ? 'No AI result' : STATE[status].label}</span>
      {ai?.provider || ai?.model ? (
        <span className="ai-model mono">
          {[ai.provider, ai.model].filter(Boolean).join(' / ')}
          {ai.latency_ms ? ` · ${formatMs(ai.latency_ms)}` : ''}
        </span>
      ) : null}
    </span>
  );

  return (
    <Section id="ai" num={num} title="AI explanation" aside={badge} className={`ai-panel ai-state-${status}`}>
      {!ai ? (
        <p className="ai-off-text">No AI result was recorded for this report. The verdict comes from fixed rules.</p>
      ) : ai.status !== 'ok' ? (
        <div className={`ai-off ai-${ai.status}`}>
          <p className="ai-off-text">{STATE[ai.status].text}</p>
          {ai.error ? (
            <p className="ai-error">
              <span className="mini-label">Reported error</span> <code className="mono">{ai.error}</code>
            </p>
          ) : null}
        </div>
      ) : (
        <div className="ai-body">
          <p className="ai-disclaimer">Written by a language model from the findings below. Each point links to the evidence it relies on; check the evidence, not just the wording.</p>
          {ai.summary ? <p className="ai-summary">{ai.summary}</p> : <p className="muted">The model returned no summary.</p>}
          {ai.points?.length ? (
            <ol className="ai-points">
              {ai.points.map((p, i) => (
                <li key={i}>
                  <p>{p.explanation}</p>
                  {p.finding_ids.length ? (
                    <div className="chip-row">
                      {p.finding_ids.map((id) => (
                        <FindingChip key={id} id={id} known={knownFindingIds.has(id)} onFocus={onFocusFinding} />
                      ))}
                    </div>
                  ) : null}
                </li>
              ))}
            </ol>
          ) : null}
          {ai.recommended_actions?.length ? (
            <div className="ai-block">
              <h3 className="mini-label">AI-recommended actions</h3>
              <ul className="ai-actions">
                {ai.recommended_actions.map((a, i) => (
                  <li key={i}>{a}</li>
                ))}
              </ul>
            </div>
          ) : null}
          {ai.uncertainty ? (
            <div className="ai-block ai-uncertainty">
              <h3 className="mini-label">Uncertainty</h3>
              <p>{ai.uncertainty}</p>
            </div>
          ) : null}
        </div>
      )}

      {ai?.observations?.length && ai.status === 'ok' ? (
        <div className="ai-block ai-observations">
          <h3 className="ai-obs-title">AI-identified patterns (unverified language signals)</h3>
          <ul>
            {ai.observations.map((o, i) => (
              <li key={i} className="ai-obs">
                <div className="ai-obs-head">
                  <span className="ai-obs-tech">{o.technique}</span>
                  {o.quote_verified ? (
                    <span className="qv qv-yes" title="The quote was found verbatim in the submitted content">
                      <CircleCheck size={12} aria-hidden /> Quote verified
                    </span>
                  ) : (
                    <span className="qv qv-no" title="The quote was NOT found verbatim in the submitted content">
                      <TriangleAlert size={12} aria-hidden /> Quote not verified
                    </span>
                  )}
                </div>
                <blockquote className="ai-quote">
                  <Quote size={14} aria-hidden />
                  <span>{o.quote}</span>
                </blockquote>
                <p className="ai-obs-why">{o.rationale}</p>
              </li>
            ))}
          </ul>
        </div>
      ) : null}

      {ai?.injection_attempt_observed ? (
        <div className="notice notice-warn ai-inject" role="note">
          <TriangleAlert size={16} aria-hidden />
          <div>
            <strong>Possible prompt-injection attempt.</strong> The analysed content appears to contain instructions aimed at an AI system. Treat any AI output with extra care.
          </div>
        </div>
      ) : null}

      {ai?.validation_notes?.length ? (
        <details className="ai-validation">
          <summary>Validation notes ({ai.validation_notes.length})</summary>
          <ul>
            {ai.validation_notes.map((n, i) => (
              <li key={i}>{n}</li>
            ))}
          </ul>
        </details>
      ) : null}
    </Section>
  );
}
