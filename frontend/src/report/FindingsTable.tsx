import { useEffect, useMemo, useRef, useState } from 'react';
import { ChevronRight, FlaskConical } from 'lucide-react';
import type { Finding, Module } from '../types';
import { MODULE_LABEL, MODULE_ORDER, SEVERITY_ORDER, formatDate, severityRank, strengthRank } from '../format';
import { ProvenanceBadge, SeverityBadge, StrengthBadge } from '../components/Badges';
import { DefinitionList } from '../components/ValueView';
import { Empty } from '../components/Section';

// Required by the Safe Browsing usage terms on every warning derived from Google data, and only on those.
const GSB_ADVISORY_URL = 'https://developers.google.com/safe-browsing/v4/advisory';

export interface FocusRequest {
  id: string;
  n: number;
}

function FindingRow({ f, open, highlighted, onToggle, rowRef, basis }: { f: Finding; open: boolean; highlighted: boolean; onToggle: () => void; rowRef: (el: HTMLLIElement | null) => void; basis: boolean }) {
  const prov = f.provenance ?? 'live';
  const bodyId = `finding-body-${f.id.replace(/[^A-Za-z0-9_-]/g, '_')}`;
  return (
    <li ref={rowRef} className={`finding sev-row-${f.severity} ${open ? 'is-open' : ''} ${highlighted ? 'is-highlighted' : ''} ${prov === 'synthetic' ? 'is-synthetic' : ''}`}>
      <button type="button" className="finding-head" aria-expanded={open} aria-controls={bodyId} onClick={onToggle}>
        <ChevronRight size={16} className="finding-caret" aria-hidden />
        <SeverityBadge value={f.severity} />
        <span className="finding-title">{f.title}</span>
        <span className="finding-tags">
          {basis ? <span className="basis-tag" title="This finding is part of the basis for the verdict">basis</span> : null}
          <StrengthBadge value={f.strength} />
          <ProvenanceBadge value={prov} />
        </span>
        <code className="finding-id mono">{f.id}</code>
      </button>
      {open ? (
        <div className="finding-body" id={bodyId}>
          {prov === 'synthetic' ? (
            <div className="synthetic-warn">
              <FlaskConical size={16} aria-hidden />
              <span>
                <strong>Synthetic evidence.</strong> This finding comes from a deliberately constructed demo/test fixture. It is not real threat intelligence.
              </span>
            </div>
          ) : null}
          <div className="finding-observed">
            <span className="mini-label">Observed</span>
            <p>{f.observed}</p>
          </div>
          {f.code === 'intel.gsb_listed' ? (
            <p className="advisory-note">
              <a href={GSB_ADVISORY_URL} target="_blank" rel="noopener noreferrer">
                Advisory provided by Google
              </a>
              . Safe Browsing protection is not perfect: it can miss unsafe sites and can list safe ones in error.
            </p>
          ) : null}
          <div className="finding-grid">
            <div>
              <span className="mini-label">Impact</span>
              <p>{f.impact}</p>
            </div>
            <div>
              <span className="mini-label">Recommendation</span>
              <p>{f.recommendation}</p>
            </div>
            <div className="finding-limit">
              <span className="mini-label">Limitation</span>
              <p>{f.limitation}</p>
            </div>
          </div>
          {f.evidence && Object.keys(f.evidence).length ? (
            <div className="finding-evidence">
              <span className="mini-label">Evidence</span>
              <DefinitionList data={f.evidence} />
            </div>
          ) : null}
          <dl className="finding-meta">
            <div>
              <dt>Source</dt>
              <dd>{f.source}</dd>
            </div>
            <div>
              <dt>Provenance</dt>
              <dd>
                <ProvenanceBadge value={prov} />
              </dd>
            </div>
            <div>
              <dt>Observed at</dt>
              <dd title={f.observed_at}>{formatDate(f.observed_at)}</dd>
            </div>
            <div>
              <dt>Rule code</dt>
              <dd>
                <code className="mono">{f.code}</code>
              </dd>
            </div>
          </dl>
        </div>
      ) : null}
    </li>
  );
}

interface Props {
  findings: Finding[];
  focus: FocusRequest | null;
  basisIds: Set<string>;
}

export function FindingsTable({ findings, focus, basisIds }: Props) {
  const [open, setOpen] = useState<Set<string>>(() => new Set());
  const [highlight, setHighlight] = useState<string | null>(null);
  const rows = useRef(new Map<string, HTMLLIElement>());

  const groups = useMemo(() => {
    const by = new Map<string, Finding[]>();
    for (const f of findings) {
      const list = by.get(f.module) ?? [];
      list.push(f);
      by.set(f.module, list);
    }
    const order = [...MODULE_ORDER, ...[...by.keys()].filter((m) => !MODULE_ORDER.includes(m as Module))];
    return order
      .filter((m) => by.has(m))
      .map((m) => ({
        module: m,
        items: by.get(m)!.slice().sort((a, b) => severityRank(a.severity) - severityRank(b.severity) || strengthRank(a.strength) - strengthRank(b.strength) || a.id.localeCompare(b.id)),
      }));
  }, [findings]);

  const counts = useMemo(() => {
    const c: Record<string, number> = {};
    for (const f of findings) c[f.severity] = (c[f.severity] ?? 0) + 1;
    return c;
  }, [findings]);

  useEffect(() => {
    if (!focus) return;
    setOpen((prev) => new Set(prev).add(focus.id));
    setHighlight(focus.id);
    const raf = requestAnimationFrame(() => {
      rows.current.get(focus.id)?.scrollIntoView({ behavior: 'smooth', block: 'center' });
    });
    const t = window.setTimeout(() => setHighlight(null), 2200);
    return () => {
      cancelAnimationFrame(raf);
      window.clearTimeout(t);
    };
  }, [focus]);

  if (!findings.length) return <Empty>No findings were produced. That is not evidence of safety: check the coverage and limitations.</Empty>;

  const toggle = (id: string) =>
    setOpen((prev) => {
      const n = new Set(prev);
      if (n.has(id)) n.delete(id);
      else n.add(id);
      return n;
    });

  return (
    <div className="findings">
      <div className="findings-toolbar">
        <div className="sev-summary" aria-label="Findings by severity">
          {SEVERITY_ORDER.filter((s) => counts[s]).map((s) => (
            <span key={s} className={`sev-count sev-${s}`}>
              <b>{counts[s]}</b> {s}
            </span>
          ))}
        </div>
        <div className="toolbar-actions">
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(new Set(findings.map((f) => f.id)))}>
            Expand all
          </button>
          <button type="button" className="btn btn-ghost btn-sm" onClick={() => setOpen(new Set())}>
            Collapse all
          </button>
        </div>
      </div>
      {groups.map((g) => (
        <div className="finding-group" key={g.module}>
          <h3 className="group-head">
            <span className="group-module mono">{g.module}</span>
            <span className="group-label">{MODULE_LABEL[g.module as Module] ?? g.module}</span>
            <span className="group-count">{g.items.length}</span>
          </h3>
          <ul className="finding-list">
            {g.items.map((f) => (
              <FindingRow
                key={f.id}
                f={f}
                open={open.has(f.id)}
                highlighted={highlight === f.id}
                onToggle={() => toggle(f.id)}
                basis={basisIds.has(f.id)}
                rowRef={(el) => {
                  if (el) rows.current.set(f.id, el);
                  else rows.current.delete(f.id);
                }}
              />
            ))}
          </ul>
        </div>
      ))}
    </div>
  );
}
