import type { CheckStatus, Classification, Coverage, Module, Provenance, Severity, Strength } from './types';

export const SEVERITY_ORDER: Severity[] = ['critical', 'high', 'medium', 'low', 'info'];
export const STRENGTH_ORDER: Strength[] = ['authoritative', 'strong', 'moderate', 'weak'];
export const MODULE_ORDER: Module[] = ['url', 'dns', 'intel', 'tls', 'web', 'content', 'message', 'correlation', 'ai'];
export const CHECK_STATUS_ORDER: CheckStatus[] = ['failed', 'unavailable', 'inconclusive', 'skipped', 'not_implemented', 'succeeded'];

export const MODULE_LABEL: Record<Module, string> = {
  url: 'URL structure',
  dns: 'DNS & registration',
  intel: 'Threat intelligence',
  tls: 'TLS certificate',
  web: 'Web fetch',
  content: 'Page content',
  message: 'Message language',
  correlation: 'Correlation',
  ai: 'AI language signals',
};

export const CHECK_STATUS_LABEL: Record<CheckStatus, string> = {
  succeeded: 'Succeeded',
  failed: 'Failed',
  unavailable: 'Unavailable',
  inconclusive: 'Inconclusive',
  skipped: 'Skipped',
  not_implemented: 'Not implemented',
};

export const PROVENANCE_LABEL: Record<Provenance, string> = {
  live: 'Live',
  cached: 'Cached',
  dataset: 'Dataset',
  synthetic: 'Synthetic',
  ai: 'AI',
};

export const PROVENANCE_HINT: Record<Provenance, string> = {
  live: 'Observed during this analysis',
  cached: 'Reused from an earlier lookup',
  dataset: 'Matched against a documented local dataset snapshot',
  synthetic: 'Deliberately constructed demo/test fixture. Not real evidence.',
  ai: 'Produced by a language model and validated against the input',
};

export type Tone = 'low' | 'suspicious' | 'high' | 'malicious' | 'neutral';

export function classificationTone(c: string | null | undefined): Tone {
  switch (c as Classification) {
    case 'Low Risk':
      return 'low';
    case 'Suspicious':
      return 'suspicious';
    case 'High Risk':
      return 'high';
    case 'Confirmed Malicious':
      return 'malicious';
    default:
      return 'neutral';
  }
}

export function severityRank(s: string): number {
  const i = SEVERITY_ORDER.indexOf(s as Severity);
  return i === -1 ? SEVERITY_ORDER.length : i;
}

export function strengthRank(s: string): number {
  const i = STRENGTH_ORDER.indexOf(s as Strength);
  return i === -1 ? STRENGTH_ORDER.length : i;
}

/** "11 of 13 checks completed; 1 failed; 1 unavailable" — counts only, never a percentage. */
export function coverageText(c: Coverage, inconclusive = 0): string {
  const parts = [`${c.succeeded} of ${c.applicable} ${c.applicable === 1 ? 'check' : 'checks'} completed`];
  if (c.failed) parts.push(`${c.failed} failed`);
  if (c.unavailable) parts.push(`${c.unavailable} unavailable`);
  if (inconclusive) parts.push(`${inconclusive} inconclusive`);
  if (c.skipped) parts.push(`${c.skipped} skipped`);
  return parts.join('; ');
}

const dtf = new Intl.DateTimeFormat(undefined, { dateStyle: 'medium', timeStyle: 'medium' });

export function formatDate(iso: string | null | undefined): string {
  if (!iso) return '—';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return dtf.format(d);
}

export function formatRelative(iso: string | null | undefined): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return '';
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 0) return 'just now';
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.floor(s / 60)} min ago`;
  if (s < 86400) return `${Math.floor(s / 3600)} h ago`;
  return `${Math.floor(s / 86400)} d ago`;
}

export function formatMs(ms: number | null | undefined): string {
  if (ms === null || ms === undefined) return '';
  if (ms < 1000) return `${ms} ms`;
  return `${(ms / 1000).toFixed(1)} s`;
}

export function shortId(id: string): string {
  return id.length > 12 ? id.slice(0, 8) : id;
}

export function middleTruncate(s: string, keep = 10): string {
  if (s.length <= keep * 2 + 1) return s;
  return `${s.slice(0, keep)}…${s.slice(-keep)}`;
}

const URLISH = /^[a-z][a-z0-9+.-]{1,15}:\/\//i;

export function isUrlLike(s: string): boolean {
  return URLISH.test(s.trim()) || /^www\./i.test(s.trim());
}

/**
 * Defang a URL for display: "https://a.b/c" -> "hxxps://a[.]b/c". Already-defanged strings are left alone.
 * Display only; the original value is still available through the copy button.
 */
export function defang(s: string): string {
  if (/hxxp|\[\.\]|\[:\]/i.test(s)) return s;
  const m = /^([a-z][a-z0-9+.-]*):\/\/([^/?#]*)(.*)$/is.exec(s.trim());
  if (!m) return s.replace(/\./g, '[.]');
  const scheme = m[1].replace(/^http/i, (x) => (x[0] === 'H' ? 'HXXP' : 'hxxp'));
  const host = m[2].replace(/\./g, '[.]');
  return `${scheme}://${host}${m[3]}`;
}

export function humanKey(k: string): string {
  return k.replace(/_/g, ' ');
}
