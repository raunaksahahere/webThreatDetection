import { useEffect, useState } from 'react';
import { Clock, Monitor, Moon, Network, ScanSearch, Sun } from 'lucide-react';
import { MOCK_MODE, getHealth, errorMessage, setUrlhausDialogOpen } from '../api';
import { useUrlhausKey } from './UrlhausKeyDialog';
import type { Health } from '../types';
import { href, usePath } from '../router';
import { Pill } from './Badges';

type Theme = 'system' | 'light' | 'dark';
const THEME_KEY = 'wtd.theme';

function readTheme(): Theme {
  try {
    const t = window.localStorage.getItem(THEME_KEY);
    return t === 'light' || t === 'dark' ? t : 'system';
  } catch {
    return 'system';
  }
}

export function applyStoredTheme(): void {
  const t = readTheme();
  if (t === 'system') delete document.documentElement.dataset.theme;
  else document.documentElement.dataset.theme = t;
}

function ThemeToggle() {
  const [theme, setTheme] = useState<Theme>(readTheme);
  useEffect(() => {
    if (theme === 'system') delete document.documentElement.dataset.theme;
    else document.documentElement.dataset.theme = theme;
    try {
      window.localStorage.setItem(THEME_KEY, theme);
    } catch {
      /* ignore */
    }
  }, [theme]);
  const next: Record<Theme, Theme> = { system: 'light', light: 'dark', dark: 'system' };
  const Icon = theme === 'light' ? Sun : theme === 'dark' ? Moon : Monitor;
  return (
    <button type="button" className="icon-btn" onClick={() => setTheme(next[theme])} title={`Theme: ${theme} (click to change)`} aria-label={`Theme: ${theme}. Change theme`}>
      <Icon size={16} aria-hidden />
    </button>
  );
}

const OFF = /\b(not|no|none|disabled|unavailable|missing|off|error|failed|false|unconfigured)\b|^0\b/i;
const ON = /^(ok|on|true|configured|enabled|live|ready|available|connected)$/i;

/** Interprets a health value (boolean, word, or text such as "125053 domains") as on/off. */
function healthState(v: unknown): { on: boolean; text: string } {
  if (typeof v === 'boolean') return { on: v, text: v ? 'configured' : 'not configured' };
  if (typeof v === 'number') return { on: v > 0, text: String(v) };
  if (typeof v === 'string') {
    const t = v.trim();
    return { on: t !== '' && (ON.test(t) || !OFF.test(t)), text: t.replace(/_/g, ' ') || 'unknown' };
  }
  if (v && typeof v === 'object') {
    const o = v as Record<string, unknown>;
    const flag = o.configured ?? o.enabled ?? o.ok ?? o.status;
    return healthState(typeof flag === 'undefined' ? true : flag);
  }
  return { on: false, text: 'unknown' };
}

function StatusPills() {
  const ownUrlhaus = useUrlhausKey();
  const [health, setHealth] = useState<Health | null>(null);
  const [err, setErr] = useState<string | null>(null);
  useEffect(() => {
    let alive = true;
    const load = () =>
      getHealth()
        .then((h) => {
          if (!alive) return;
          setHealth(h);
          setErr(null);
        })
        .catch((e) => alive && setErr(errorMessage(e)));
    load();
    const t = window.setInterval(load, 30000);
    return () => {
      alive = false;
      window.clearInterval(t);
    };
  }, []);

  if (err && !health)
    return (
      <div className="status-pills" aria-label="Service status">
        <Pill tone="bad" title={err}>
          API unreachable
        </Pill>
      </div>
    );
  if (!health)
    return (
      <div className="status-pills" aria-label="Service status">
        <Pill tone="muted">Checking…</Pill>
      </div>
    );

  const chain = health.chain ?? {};
  const ai = health.ai ?? {};
  const aiStatus = (ai.status ?? 'unknown').toString();
  const aiOn = healthState(aiStatus).on;
  const aiTone = aiOn ? 'good' : /disabled/i.test(aiStatus) ? 'muted' : 'warn';
  const aiShort = (ai.model ?? '').split('/').pop()?.split(':')[0] || ai.provider || aiStatus;
  const intel = Object.entries(health.intel ?? {});
  return (
    <div className="status-pills" aria-label="Service status">
      <Pill
        tone={health.ok ? 'good' : 'bad'}
        title={`API ${health.ok ? 'healthy' : 'degraded'}${health.version ? ` · version ${health.version}` : ''}${err ? ` · last refresh failed: ${err}` : ''}`}
      >
        API{health.version ? ` ${health.version}` : ''}
      </Pill>
      <Pill tone={chain.connected ? 'good' : 'bad'} title={chain.connected ? `Chain ${chain.chain_id ?? '?'} · contract ${chain.contract ?? 'unknown'}` : 'Blockchain not reachable: registration and verification are unavailable'}>
        {chain.connected ? `Chain ${chain.chain_id ?? ''}`.trim() : 'Chain offline'}
      </Pill>
      <Pill tone={aiTone} title={`AI provider: ${ai.provider ?? 'none'} · model: ${ai.model ?? 'none'} · status: ${aiStatus}`}>
        AI {aiOn ? aiShort : aiStatus}
      </Pill>
      {intel.map(([name, v]) => {
        const s = healthState(v);
        if (name === 'urlhaus' && !MOCK_MODE) {
          const title = ownUrlhaus
            ? 'URLhaus: using your own key for new analyses (this tab only). Click to change or remove it.'
            : s.on
              ? 'URLhaus: configured on the server. Click to use your own key instead.'
              : 'URLhaus: not configured on this server. Click to add your own free abuse.ch key.';
          return (
            <button key={name} type="button" className="pill-btn" onClick={() => setUrlhausDialogOpen(true)} title={title} aria-label={title}>
              <Pill tone={ownUrlhaus || s.on ? 'good' : 'muted'}>{ownUrlhaus ? 'urlhaus · your key' : s.on ? 'urlhaus' : 'urlhaus · add key'}</Pill>
            </button>
          );
        }
        return (
          <Pill key={name} tone={s.on ? 'good' : 'muted'} title={`Threat intel source ${name}: ${s.text}`}>
            {name}
          </Pill>
        );
      })}
    </div>
  );
}

const NAV = [
  { path: '/', label: 'Investigate', icon: ScanSearch },
  { path: '/history', label: 'History', icon: Clock },
  { path: '/incidents', label: 'Incidents', icon: Network },
];

export function Header() {
  const path = usePath();
  const section = path.startsWith('/r/') ? '' : path;
  return (
    <header className="topbar">
      <div className="topbar-inner">
        <a className="brand" href={href('/')} aria-label="WTD home">
          <span className="brand-mark" aria-hidden>
            <svg viewBox="0 0 32 32" width="30" height="30">
              <path d="M16 3.5l10 3.9v7.6c0 6.3-4.2 11.2-10 13-5.8-1.8-10-6.7-10-13V7.4L16 3.5z" fill="none" stroke="currentColor" strokeWidth="2.2" strokeLinejoin="round" />
              <circle cx="15" cy="14.6" r="4" fill="none" stroke="var(--signal)" strokeWidth="2.2" />
              <path d="M18 17.6l3.2 3.2" stroke="var(--signal)" strokeWidth="2.4" strokeLinecap="round" />
            </svg>
          </span>
          <span className="brand-text">
            <span className="brand-name">WTD</span>
            <span className="brand-sub">Web Threat Detection · Digital Trust</span>
          </span>
        </a>
        <nav className="nav" aria-label="Main">
          {NAV.map(({ path: p, label, icon: Icon }) => (
            <a key={p} href={href(p)} className={`nav-link ${section === p ? 'is-active' : ''}`} aria-current={section === p ? 'page' : undefined}>
              <Icon size={15} aria-hidden />
              <span>{label}</span>
            </a>
          ))}
        </nav>
        <div className="topbar-right">
          <StatusPills />
          <ThemeToggle />
        </div>
      </div>
    </header>
  );
}

export function MockBanner() {
  if (!MOCK_MODE) return null;
  return (
    <div className="mock-banner" role="status">
      <strong>MOCK MODE</strong>
      <span>Sample data from src/mock. No backend is contacted and nothing is analysed or registered.</span>
    </div>
  );
}
