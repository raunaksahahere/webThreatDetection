import { Check } from 'lucide-react';

export const FLOW = [
  { key: 'submit', label: 'Submit', hint: 'Paste a link or a message' },
  { key: 'investigate', label: 'Investigate', hint: 'Fetch safely in an isolated inspector: URL, DNS, TLS, redirects, page' },
  { key: 'analyse', label: 'Analyse', hint: 'Threat intelligence, content signals, correlations, AI explanation' },
  { key: 'assess', label: 'Assess risk', hint: 'Fixed rules decide the verdict; missing checks are counted, never assumed clean' },
  { key: 'report', label: 'Report & verify', hint: 'Evidence report, on-chain commitment, independent verification' },
] as const;

interface Props {
  /** Index of the active step (0-4). Steps before it are complete. Use 5 for all complete. */
  active: number;
  /** Shows the hint text under each step. */
  detailed?: boolean;
  /** Pulsing indicator on the active step. */
  live?: boolean;
  failedAt?: number | null;
}

export function FlowSteps({ active, detailed = false, live = false, failedAt = null }: Props) {
  return (
    <ol className={`flow ${detailed ? 'flow-detailed' : ''}`} aria-label="Analysis flow">
      {FLOW.map((s, i) => {
        const state = failedAt === i ? 'failed' : i < active ? 'done' : i === active ? 'active' : 'todo';
        return (
          <li key={s.key} className={`flow-step is-${state} ${live && state === 'active' ? 'is-live' : ''}`} aria-current={state === 'active' ? 'step' : undefined}>
            <span className="flow-num" aria-hidden>
              {state === 'done' ? <Check size={14} strokeWidth={3} /> : i + 1}
            </span>
            <span className="flow-text">
              <span className="flow-label">{s.label}</span>
              {detailed ? <span className="flow-hint">{s.hint}</span> : null}
            </span>
          </li>
        );
      })}
    </ol>
  );
}
