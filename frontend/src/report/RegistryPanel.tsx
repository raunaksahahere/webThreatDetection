import { useCallback, useEffect, useState } from 'react';
import { Blocks, CircleCheck, CircleX, Download, FileCheck, GitBranch, Gavel, LoaderCircle, Terminal, TriangleAlert } from 'lucide-react';
import type { RegistryRecord, Report, ReviewRecord, ThreatReportState, VerifyResult } from '../types';
import { downloadEnvelope, errorMessage, getThreatReport, registerThreatReport, reviewThreatReport, reviseThreatReport, saveBlob, verifyIntegrity } from '../api';
import { formatDate } from '../format';
import { CopyButton } from '../components/CopyButton';
import { ValueView } from '../components/ValueView';
import { Notice } from '../components/Section';

export const CHAIN_CAVEAT = 'The chain proves this report has not changed since it was registered — not that its conclusions are true.';

type Busy = 'register' | 'revise' | 'verify' | 'download' | 'review' | null;

function Hex({ value }: { value: string }) {
  return (
    <span className="hex">
      <code className="mono">{value}</code>
      <CopyButton value={value} />
    </span>
  );
}

function RecordCard({ r, latest }: { r: RegistryRecord; latest: boolean }) {
  return (
    <li className={`rec ${latest ? 'is-latest' : 'is-superseded'}`}>
      <div className="rec-head">
        <GitBranch size={15} aria-hidden />
        <strong>Revision {r.revision}</strong>
        {latest ? <span className="rec-tag latest">latest</span> : <span className="rec-tag">superseded</span>}
        <span className="rec-time" title={r.registered_at}>
          {formatDate(r.registered_at)}
        </span>
      </div>
      <dl className="rec-grid">
        <div>
          <dt>Chain ID</dt>
          <dd className="mono">{r.chain_id}</dd>
        </div>
        <div>
          <dt>Block</dt>
          <dd className="mono">{r.block_number}</dd>
        </div>
        <div className="span-2">
          <dt>Contract</dt>
          <dd>
            <Hex value={r.contract} />
          </dd>
        </div>
        <div className="span-2">
          <dt>Report ID (on chain)</dt>
          <dd>
            <Hex value={r.report_id_hex} />
          </dd>
        </div>
        <div className="span-2">
          <dt>Commitment</dt>
          <dd>
            <Hex value={r.commitment} />
          </dd>
        </div>
        <div className="span-2">
          <dt>Transaction</dt>
          <dd>
            <Hex value={r.tx_hash} />
          </dd>
        </div>
        <div className="span-2">
          <dt>Canonicalization</dt>
          <dd className="mono">{r.canonicalization}</dd>
        </div>
      </dl>
    </li>
  );
}

function VerifyView({ v }: { v: VerifyResult }) {
  // The API sets match=true only for the latest revision; a match on an older revision means superseded.
  const matchedSome = v.matched_revision !== null && v.matched_revision !== undefined;
  const superseded = matchedSome && v.latest_revision !== null && v.matched_revision !== v.latest_revision;
  const ok = v.match && !superseded;
  const tone = ok ? 'good' : superseded ? 'warn' : 'bad';
  const Icon = ok ? CircleCheck : superseded ? TriangleAlert : CircleX;
  const title = ok
    ? `Match: the stored report reproduces the commitment of revision ${v.matched_revision ?? '?'} (latest)`
    : superseded
      ? `Matches revision ${v.matched_revision}, which has been superseded by revision ${v.latest_revision}`
      : 'Mismatch: the stored report does not reproduce any on-chain commitment';
  return (
    <div className={`verify-result verify-${tone}`} role="status">
      <div className="verify-title">
        <Icon size={20} aria-hidden />
        <strong>{title}</strong>
      </div>
      {tone === 'bad' ? <p>The report may have been altered after registration, or the chain state differs. Run the independent verifier below to confirm.</p> : null}
      <dl className="verify-grid">
        <div>
          <dt>Recomputed by the app</dt>
          <dd>
            <Hex value={v.recomputed} />
          </dd>
        </div>
        <div>
          <dt>Latest on chain</dt>
          <dd>{v.onchain_latest ? <Hex value={v.onchain_latest} /> : <span className="muted">none</span>}</dd>
        </div>
        <div>
          <dt>On-chain review status</dt>
          <dd>{v.status ?? <span className="muted">unknown</span>}</dd>
        </div>
      </dl>
      <p className="fine">
        {v.checked_at ? `Checked ${formatDate(v.checked_at)}. ` : ''}This check runs inside the WTD server. For a check that does not trust this server, use the independent verifier.
      </p>
    </div>
  );
}

function StatusHistory({ items }: { items: unknown[] }) {
  if (!items.length) return null;
  return (
    <div className="status-history">
      <h3 className="mini-label">On-chain review status history</h3>
      <ol>
        {items.map((it, i) => {
          if (it && typeof it === 'object') {
            const o = it as Record<string, unknown>;
            const status = o.status ?? o.name;
            return (
              <li key={i}>
                <span className="sh-status">{typeof status === 'string' || typeof status === 'number' ? String(status) : 'entry'}</span>
                {typeof o.timestamp === 'string' || typeof o.timestamp === 'number' ? (
                  <span className="muted">{formatDate(typeof o.timestamp === 'string' ? o.timestamp : new Date(o.timestamp * 1000).toISOString())}</span>
                ) : null}
                {typeof o.by === 'string' ? <code className="mono sh-by">{o.by}</code> : null}
              </li>
            );
          }
          return (
            <li key={i}>
              <ValueView value={it} />
            </li>
          );
        })}
      </ol>
    </div>
  );
}

function ReviewBox({ current, reviews, busy, onReview }: { current: string | null | undefined; reviews: ReviewRecord[]; busy: Busy; onReview: (s: ReviewRecord['status'], note: string) => Promise<void> }) {
  const [status, setStatus] = useState<ReviewRecord['status']>('Validated');
  const [note, setNote] = useState('');
  const needNote = status !== 'Validated';
  return (
    <div className="review-box">
      <h3 className="mini-label">
        <Gavel size={14} aria-hidden /> Independent review{current ? <span className={`review-current review-${current.toLowerCase()}`}>{current}</span> : null}
      </h3>
      <p className="fine">
        A reviewer account (separate from the reporter that registered this report; the contract rejects self-review) records Validated, Disputed or Retracted on chain. Only the SHA-256 of the note is written on chain; the note text stays here.
      </p>
      {reviews.length ? (
        <ul className="review-list">
          {reviews.map((r) => (
            <li key={r.tx_hash}>
              <strong className={`review-current review-${r.status.toLowerCase()}`}>{r.status}</strong> {r.note || <span className="muted">(no note)</span>}
              <div className="fine mono">
                by {r.reviewer.slice(0, 10)}… · note sha256 {r.note_hash.slice(0, 14)}… · tx {r.tx_hash.slice(0, 14)}…
              </div>
            </li>
          ))}
        </ul>
      ) : null}
      <form
        className="review-form"
        onSubmit={(e) => {
          e.preventDefault();
          if (needNote && !note.trim()) return;
          void onReview(status, note).then(() => setNote(''));
        }}
      >
        <div className="review-choices" role="radiogroup" aria-label="Review decision">
          {(['Validated', 'Disputed', 'Retracted'] as const).map((s) => (
            <label key={s} className={`review-choice ${status === s ? 'is-active' : ''}`}>
              <input type="radio" name="review-status" value={s} checked={status === s} onChange={() => setStatus(s)} /> {s}
            </label>
          ))}
        </div>
        <label className="field">
          <span className="field-label">Reviewer note {needNote ? '(required)' : '(optional)'}</span>
          <textarea rows={2} maxLength={500} value={note} onChange={(e) => setNote(e.target.value)} placeholder="e.g. Confirmed independently: the domain was registered 3 days ago and asks for the OTP" />
        </label>
        <button type="submit" className="btn btn-secondary" disabled={busy !== null || (needNote && !note.trim())}>
          {busy === 'review' ? <LoaderCircle size={15} className="spin" aria-hidden /> : <Gavel size={15} aria-hidden />} Record review on-chain
        </button>
      </form>
    </div>
  );
}

interface Props {
  report: Report;
  onChanged: () => void;
}

export function RegistryPanel({ report, onChanged }: Props) {
  const [state, setState] = useState<ThreatReportState | null | undefined>(undefined);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [busy, setBusy] = useState<Busy>(null);
  const [actionError, setActionError] = useState<string | null>(null);
  const [verify, setVerify] = useState<VerifyResult | null>(null);
  const [filename, setFilename] = useState<string | null>(null);
  const [submitter, setSubmitter] = useState('');
  const [reviseOpen, setReviseOpen] = useState(false);
  const [reason, setReason] = useState('');

  const complete = report.status === 'complete';

  const load = useCallback(async () => {
    try {
      setLoadError(null);
      setState(await getThreatReport(report.id));
    } catch (e) {
      setLoadError(errorMessage(e));
      setState(null);
    }
  }, [report.id]);

  useEffect(() => {
    if (complete) void load();
  }, [complete, load]);

  const records = (state?.records?.length ? state.records : report.registry ?? []).slice().sort((a, b) => b.revision - a.revision);
  const registered = records.length > 0;
  const latest = records[0]?.revision;

  const run = async (kind: Exclude<Busy, null>, fn: () => Promise<void>) => {
    setBusy(kind);
    setActionError(null);
    try {
      await fn();
    } catch (e) {
      setActionError(errorMessage(e));
    } finally {
      setBusy(null);
    }
  };

  const doRegister = () =>
    run('register', async () => {
      await registerThreatReport(report.id, submitter.trim() || undefined);
      setVerify(null);
      await load();
      onChanged();
    });

  const doRevise = () =>
    run('revise', async () => {
      await reviseThreatReport(report.id, reason.trim());
      setReason('');
      setReviseOpen(false);
      setVerify(null);
      await load();
      onChanged();
    });

  const doVerify = () => run('verify', async () => setVerify(await verifyIntegrity(report.id)));

  const doReview = (status: ReviewRecord['status'], note: string) =>
    run('review', async () => {
      await reviewThreatReport(report.id, status, note);
      setVerify(null);
      await load();
    });

  const doDownload = () =>
    run('download', async () => {
      const { blob, filename: name } = await downloadEnvelope(report.id);
      saveBlob(blob, name);
      setFilename(name);
    });

  const cli = `node verifier/verify.mjs --envelope ${filename ?? '<file>'} --deployment deployments/local.json`;

  return (
    <div className="registry">
      <p className="chain-caveat">
        <Blocks size={16} aria-hidden />
        <span>{CHAIN_CAVEAT}</span>
      </p>
      <p className="fine">Only a salted SHA-256 commitment and the classification code are written on chain. No URLs, message text, indicators or personal data.</p>

      {!complete ? (
        <Notice tone="neutral">Registration becomes available once the analysis is complete.</Notice>
      ) : state === undefined ? (
        <p className="muted loading-line">
          <LoaderCircle size={14} className="spin" aria-hidden /> Loading registry state…
        </p>
      ) : (
        <>
          {loadError ? (
            <Notice tone="warn" title="Could not load registry state">
              {loadError}
            </Notice>
          ) : null}

          {!registered ? (
            <div className="reg-start">
              <label className="field">
                <span className="field-label">Submitter label (optional)</span>
                <input type="text" value={submitter} maxLength={60} placeholder="e.g. SOC analyst on duty" onChange={(e) => setSubmitter(e.target.value)} />
              </label>
              <button type="button" className="btn btn-primary" onClick={doRegister} disabled={busy !== null}>
                {busy === 'register' ? <LoaderCircle size={16} className="spin" aria-hidden /> : <Blocks size={16} aria-hidden />}
                {busy === 'register' ? 'Registering…' : 'Register commitment on-chain'}
              </button>
            </div>
          ) : (
            <>
              <ul className="records">
                {records.map((r) => (
                  <RecordCard key={`${r.revision}-${r.tx_hash}`} r={r} latest={r.revision === latest} />
                ))}
              </ul>
              {state?.onchain && typeof (state.onchain as { error?: unknown }).error === 'string' ? (
                <Notice tone="warn" title="Blockchain not reachable">
                  {String((state.onchain as { error?: unknown }).error)}
                </Notice>
              ) : null}
              {state?.onchain?.status_history?.length ? <StatusHistory items={state.onchain.status_history} /> : null}

              <div className="reg-actions">
                <button type="button" className="btn btn-secondary" onClick={doVerify} disabled={busy !== null}>
                  {busy === 'verify' ? <LoaderCircle size={16} className="spin" aria-hidden /> : <FileCheck size={16} aria-hidden />}
                  Verify integrity (app)
                </button>
                <button type="button" className="btn btn-secondary" onClick={doDownload} disabled={busy !== null}>
                  {busy === 'download' ? <LoaderCircle size={16} className="spin" aria-hidden /> : <Download size={16} aria-hidden />}
                  Download report for independent verification
                </button>
                <button type="button" className="btn btn-ghost" onClick={() => setReviseOpen((o) => !o)} disabled={busy !== null} aria-expanded={reviseOpen}>
                  <GitBranch size={16} aria-hidden />
                  Publish revision
                </button>
              </div>

              {reviseOpen ? (
                <form
                  className="revise-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    if (reason.trim()) void doRevise();
                  }}
                >
                  <label className="field">
                    <span className="field-label">Reason for the revision</span>
                    <textarea rows={3} maxLength={300} value={reason} onChange={(e) => setReason(e.target.value)} placeholder="e.g. Re-analysed after the CERT Polska feed became available" />
                  </label>
                  <p className="fine">A revision registers a new commitment (revision {(latest ?? 0) + 1}). Earlier revisions stay on chain and are marked superseded. The review status resets to Pending.</p>
                  <div className="dialog-actions">
                    <button type="button" className="btn btn-ghost" onClick={() => setReviseOpen(false)}>
                      Cancel
                    </button>
                    <button type="submit" className="btn btn-primary" disabled={!reason.trim() || busy !== null}>
                      {busy === 'revise' ? <LoaderCircle size={16} className="spin" aria-hidden /> : null}
                      Publish revision
                    </button>
                  </div>
                </form>
              ) : null}

              {verify ? <VerifyView v={verify} /> : null}

              <ReviewBox current={state?.onchain?.current_status} reviews={state?.reviews ?? []} busy={busy} onReview={doReview} />

              <div className="cli">
                <div className="cli-head">
                  <Terminal size={15} aria-hidden />
                  <span>Independent verification (does not trust this server)</span>
                </div>
                <div className="cli-cmd">
                  <code className="mono">{cli}</code>
                  <CopyButton value={cli} label="Copy command" />
                </div>
                <p className="fine">
                  {filename ? `Saved as ${filename}. ` : 'Download the report first, then run this from the project root. '}
                  The verifier recomputes the commitment and reads the contract directly. Exit code 0 = matches latest revision, 2 = matches a superseded revision, 1 = no match (tampered), 3 = chain or input error.
                </p>
              </div>
            </>
          )}
        </>
      )}

      {actionError ? (
        <Notice tone="bad" title="Registry action failed">
          {actionError}
        </Notice>
      ) : null}
    </div>
  );
}
