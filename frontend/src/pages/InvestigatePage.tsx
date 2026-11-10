import { useState, type FormEvent } from 'react';
import { ArrowRight, Globe, Info, LoaderCircle, Mail, QrCode, ShieldAlert } from 'lucide-react';
import jsQR from 'jsqr';
import { MOCK_MODE, createAnalysis, errorMessage } from '../api';
import { QuotaLine } from '../components/PublicDemo';
import { NoWalletLine } from '../components/ChainNotice';
import { navigate, reportPath, href } from '../router';
import { FlowSteps } from '../components/FlowSteps';
import { Notice } from '../components/Section';

type Tab = 'url' | 'message' | 'qr';
const MAX_MESSAGE = 150000;
const MESSAGE_NOTICE = 'Paste the message text only. Remove passwords, OTPs, card numbers and personal details you do not want analysed.';

/** Decode a QR code locally in the browser (the image never leaves this page; the server only sees the decoded text). */
async function decodeQr(file: File): Promise<string | null> {
  const bmp = await createImageBitmap(file);
  const scale = Math.min(1, 1600 / Math.max(bmp.width, bmp.height));
  const w = Math.max(1, Math.round(bmp.width * scale));
  const h = Math.max(1, Math.round(bmp.height * scale));
  const canvas = document.createElement('canvas');
  canvas.width = w;
  canvas.height = h;
  const ctx = canvas.getContext('2d');
  if (!ctx) return null;
  ctx.drawImage(bmp, 0, 0, w, h);
  const img = ctx.getImageData(0, 0, w, h);
  return jsQR(img.data, w, h, { inversionAttempts: 'attemptBoth' })?.data ?? null;
}

function qrKind(payload: string): 'url' | 'upi' | 'text' {
  if (/^https?:\/\//i.test(payload.trim())) return 'url';
  if (/^upi:\/\/pay\?/i.test(payload.trim())) return 'upi';
  return 'text';
}

export function InvestigatePage() {
  const [tab, setTab] = useState<Tab>('url');
  const [url, setUrl] = useState('');
  const [text, setText] = useState('');
  const [investigateLinks, setInvestigateLinks] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [qr, setQr] = useState<string | null>(null);
  const [qrBusy, setQrBusy] = useState(false);

  const canSubmit = !busy && (tab === 'url' ? url.trim().length > 0 : tab === 'qr' ? !!qr : text.trim().length > 0);

  const submit = async (e: FormEvent) => {
    e.preventDefault();
    if (!canSubmit) return;
    setBusy(true);
    setError(null);
    try {
      const res =
        tab === 'url'
          ? await createAnalysis({ kind: 'url', url: url.trim() })
          : tab === 'qr' && qr
            ? qrKind(qr) === 'url'
              ? await createAnalysis({ kind: 'url', url: qr.trim(), via: 'qr' })
              : await createAnalysis({ kind: 'message', text: qr, investigate_links: true, via: 'qr' })
            : await createAnalysis({ kind: 'message', text, investigate_links: investigateLinks });
      navigate(reportPath(res.id));
    } catch (err) {
      setError(errorMessage(err));
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="page investigate">
      <div className="hero">
        <p className="eyebrow">Case intake</p>
        <h1 className="hero-title">
          Is this link or message <em>a trap?</em>
        </h1>
        <p className="hero-lede">
          Submit a suspicious website address or the text of a message. WTD investigates it in an isolated inspector, explains every piece of evidence, and can register a tamper-evident commitment of the report on a blockchain.
        </p>
      </div>

      <form className="intake" onSubmit={submit} noValidate>
        <div className="tabs" role="tablist" aria-label="What do you want to check?">
          <button type="button" role="tab" id="tab-url" aria-selected={tab === 'url'} aria-controls="panel-url" className={`tab ${tab === 'url' ? 'is-active' : ''}`} onClick={() => setTab('url')}>
            <Globe size={16} aria-hidden /> Website / URL
          </button>
          <button type="button" role="tab" id="tab-msg" aria-selected={tab === 'message'} aria-controls="panel-msg" className={`tab ${tab === 'message' ? 'is-active' : ''}`} onClick={() => setTab('message')}>
            <Mail size={16} aria-hidden /> Message / Email
          </button>
          <button type="button" role="tab" id="tab-qr" aria-selected={tab === 'qr'} aria-controls="panel-qr" className={`tab ${tab === 'qr' ? 'is-active' : ''}`} onClick={() => setTab('qr')}>
            <QrCode size={16} aria-hidden /> QR code
          </button>
        </div>

        {tab === 'qr' ? (
          <div className="intake-panel" role="tabpanel" id="panel-qr" aria-labelledby="tab-qr">
            <label className="field">
              <span className="field-label">Photo or screenshot of a QR code</span>
              <input
                type="file"
                accept="image/png,image/jpeg,image/webp,image/gif"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  setQr(null);
                  setError(null);
                  if (!f) return;
                  if (f.size > 10_000_000) {
                    setError('Image is larger than 10 MB.');
                    return;
                  }
                  setQrBusy(true);
                  try {
                    const data = await decodeQr(f);
                    if (!data) setError('No QR code found in that image. Try a sharper, straight-on photo.');
                    else setQr(data.slice(0, 4000));
                  } catch {
                    setError('Could not read that image.');
                  } finally {
                    setQrBusy(false);
                  }
                }}
              />
            </label>
            <p className="field-help">
              <Info size={14} aria-hidden /> The image is decoded here in your browser and is never uploaded. Only the decoded text is investigated: a web address gets the full website investigation; a UPI payment code is checked for "scan to receive money" tricks.
            </p>
            {qrBusy ? (
              <p className="muted">
                <LoaderCircle size={14} className="spin" aria-hidden /> Decoding…
              </p>
            ) : null}
            {qr ? (
              <div className="qr-decoded">
                <span className="mini-label">Decoded ({qrKind(qr) === 'url' ? 'web address' : qrKind(qr) === 'upi' ? 'UPI payment request' : 'text'})</span>
                <code className="mono">{qr}</code>
              </div>
            ) : null}
          </div>
        ) : tab === 'url' ? (
          <div className="intake-panel" role="tabpanel" id="panel-url" aria-labelledby="tab-url">
            <label className="field">
              <span className="field-label">Website address</span>
              <input
                type="text"
                inputMode="url"
                autoComplete="off"
                autoCapitalize="off"
                spellCheck={false}
                className="input-xl mono"
                placeholder="https://example.com/login"
                value={url}
                maxLength={2048}
                onChange={(e) => setUrl(e.target.value)}
              />
            </label>
            <p className="field-help">
              <Info size={14} aria-hidden /> Paste the link without opening it. WTD fetches it from the server inside a sandboxed process; your browser never loads the page.
            </p>
          </div>
        ) : (
          <div className="intake-panel" role="tabpanel" id="panel-msg" aria-labelledby="tab-msg">
            <Notice tone="warn" icon={<ShieldAlert size={18} aria-hidden />}>
              {MESSAGE_NOTICE}
            </Notice>
            <label className="field">
              <span className="field-label">Message text, or a raw e-mail (paste &ldquo;Show original&rdquo; / .eml source to check SPF, DKIM, DMARC, spoofing and attachments)</span>
              <textarea
                rows={8}
                spellCheck={false}
                placeholder="Dear customer, your account will be blocked today. Update your KYC at…"
                value={text}
                maxLength={MAX_MESSAGE}
                onChange={(e) => setText(e.target.value)}
              />
            </label>
            <label className="eml-load">
              <input
                type="file"
                accept=".eml,message/rfc822,text/plain"
                onChange={async (e) => {
                  const f = e.target.files?.[0];
                  if (!f) return;
                  if (f.size > MAX_MESSAGE) {
                    setError(`That file is ${Math.round(f.size / 1024)} KB; the limit is ${Math.round(MAX_MESSAGE / 1024)} KB.`);
                    return;
                  }
                  setText(await f.text()); // read locally as text; attachments inside are never opened
                  e.target.value = '';
                }}
              />
              <span>Load an .eml file</span>
            </label>
            <div className="field-row">
              <label className="check">
                <input type="checkbox" checked={investigateLinks} onChange={(e) => setInvestigateLinks(e.target.checked)} />
                <span>Also investigate links found in the message</span>
              </label>
              <span className="counter mono">
                {text.length.toLocaleString()} / {MAX_MESSAGE.toLocaleString()}
              </span>
            </div>
          </div>
        )}

        {error ? (
          <Notice tone="bad" title="Could not start the analysis">
            {error}
          </Notice>
        ) : null}

        <div className="intake-actions">
          <button type="submit" className="btn btn-primary btn-lg" disabled={!canSubmit}>
            {busy ? <LoaderCircle size={18} className="spin" aria-hidden /> : null}
            {busy ? 'Submitting…' : 'Start investigation'}
            {!busy ? <ArrowRight size={18} aria-hidden /> : null}
          </button>
          {MOCK_MODE ? (
            <a className="btn btn-ghost" href={href(reportPath('3f6c2a9e-8b1d-4c57-9e2a-71d0b5f4c8a1'))}>
              Open sample report
            </a>
          ) : null}
        </div>
        <QuotaLine />
        <NoWalletLine />
      </form>

      <section className="how" aria-labelledby="how-h">
        <h2 id="how-h" className="kicker">
          How it works
        </h2>
        <FlowSteps active={-1} detailed />
        <p className="how-foot">No automated check can prove a site or message is safe. WTD reports what it observed, what it could not check, and why it reached its verdict.</p>
      </section>
    </div>
  );
}
