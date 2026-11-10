import type { ReactNode } from 'react';
import {
  Ban,
  CircleCheck,
  CircleDashed,
  CircleHelp,
  CircleSlash,
  CircleX,
  Database,
  FlaskConical,
  Radar,
  RefreshCw,
  Sparkles,
  Wrench,
} from 'lucide-react';
import type { CheckStatus, Provenance, Severity, Strength } from '../types';
import { CHECK_STATUS_LABEL, PROVENANCE_HINT, PROVENANCE_LABEL, classificationTone } from '../format';

export function ClassificationBadge({ value, size = 'md' }: { value: string | null | undefined; size?: 'sm' | 'md' }) {
  const tone = classificationTone(value);
  return (
    <span className={`cls-badge tone-${tone} size-${size}`}>
      <span className="cls-dot" aria-hidden />
      {value ?? 'No verdict'}
    </span>
  );
}

export function SeverityBadge({ value }: { value: Severity }) {
  return <span className={`sev-badge sev-${value}`}>{value}</span>;
}

export function StrengthBadge({ value }: { value: Strength }) {
  const bars = { weak: 1, moderate: 2, strong: 3, authoritative: 4 }[value] ?? 0;
  return (
    <span className="str-badge" title={`Evidence strength: ${value}`}>
      <span className="str-bars" aria-hidden>
        {[1, 2, 3, 4].map((i) => (
          <i key={i} className={i <= bars ? 'on' : ''} />
        ))}
      </span>
      {value}
    </span>
  );
}

const PROV_ICON: Record<Provenance, ReactNode> = {
  live: <Radar size={12} aria-hidden />,
  cached: <RefreshCw size={12} aria-hidden />,
  dataset: <Database size={12} aria-hidden />,
  synthetic: <FlaskConical size={12} aria-hidden />,
  ai: <Sparkles size={12} aria-hidden />,
};

export function ProvenanceBadge({ value = 'live' }: { value?: Provenance }) {
  const v = (PROVENANCE_LABEL[value] ? value : 'live') as Provenance;
  return (
    <span className={`prov-badge prov-${v}`} title={PROVENANCE_HINT[v]}>
      {PROV_ICON[v]}
      {v === 'synthetic' ? 'Synthetic fixture' : PROVENANCE_LABEL[v]}
    </span>
  );
}

const CHECK_ICON: Record<CheckStatus, ReactNode> = {
  succeeded: <CircleCheck size={14} aria-hidden />,
  failed: <CircleX size={14} aria-hidden />,
  unavailable: <CircleSlash size={14} aria-hidden />,
  inconclusive: <CircleHelp size={14} aria-hidden />,
  skipped: <CircleDashed size={14} aria-hidden />,
  not_implemented: <Wrench size={14} aria-hidden />,
};

export function CheckStatusBadge({ value }: { value: CheckStatus }) {
  return (
    <span className={`chk-badge chk-${value}`}>
      {CHECK_ICON[value] ?? <Ban size={14} aria-hidden />}
      {CHECK_STATUS_LABEL[value] ?? value}
    </span>
  );
}

export function Pill({ tone = 'muted', children, title }: { tone?: 'good' | 'warn' | 'bad' | 'muted'; children: ReactNode; title?: string }) {
  return (
    <span className={`pill pill-${tone}`} title={title}>
      <span className="pill-led" aria-hidden />
      {children}
    </span>
  );
}
