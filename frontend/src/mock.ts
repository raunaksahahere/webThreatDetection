// Offline mock backend for ?mock=1. Serves src/mock/sampleReport.json plus a few derived variants
// so every UI state can be exercised and screenshotted without the API. Never used in normal mode.
import sample from './mock/sampleReport.json';
import type {
  AnalysisCreated,
  AnalysisRequest,
  AnalysisSummary,
  Health,
  Incident,
  RegistrationResult,
  RegistryRecord,
  Report,
  ThreatReportState,
  VerifyResult,
} from './types';
import { defang } from './format';

const SAMPLE = sample as unknown as Report;
const clone = <T,>(v: T): T => JSON.parse(JSON.stringify(v)) as T;
const delay = (ms: number) => new Promise((r) => setTimeout(r, ms));

const OTHER_ID = 'b7e19d42-5a3c-4f8e-a1d6-2c9f0e8b3a57';
const INCONCLUSIVE_ID = 'e2a4c6d8-1f3b-4a5c-8d7e-9f0a1b2c3d4e';
const MESSAGE_ID = 'c91f7e20-6b4d-4e1a-9c3f-5d8a2b7e6f10';

function hex(seed: string): string {
  // Deterministic fake 64-hex string (display only; not a real hash).
  let h1 = 0x811c9dc5;
  let out = '';
  for (let round = 0; out.length < 64; round++) {
    for (let i = 0; i < seed.length; i++) h1 = Math.imul(h1 ^ seed.charCodeAt(i) ^ round, 16777619) >>> 0;
    out += h1.toString(16).padStart(8, '0');
  }
  return out.slice(0, 64);
}

function variantHighRisk(): Report {
  const r = clone(SAMPLE);
  r.id = OTHER_ID;
  r.created_at = '2026-11-07T18:03:55Z';
  r.completed_at = '2026-11-07T18:04:04Z';
  r.input_display = 'hxxps://yono-sbi-rewards[.]top/claim';
  r.input_sha256 = hex('other-input');
  r.subject = { ...r.subject, host: 'yono-sbi-rewards.top', defanged: r.input_display };
  r.assessment = {
    ...r.assessment!,
    classification: 'High Risk',
    rule_id: 'R-HIGH-1',
    rule_text: 'At least one strong signal corroborated by a moderate signal.',
  };
  r.correlations = [
    {
      other_report_id: SAMPLE.id,
      other_created_at: SAMPLE.created_at,
      other_classification: 'Suspicious',
      shared: ['ip: 203.0.113[.]45', 'brand: State Bank of India'],
      method: 'infrastructure',
      score: null,
    },
  ];
  r.registry = [];
  return r;
}

function variantInconclusive(): Report {
  const r = clone(SAMPLE);
  r.id = INCONCLUSIVE_ID;
  r.created_at = '2026-11-08T05:10:40Z';
  r.completed_at = '2026-11-08T05:10:52Z';
  r.input_display = 'hxxp://parcel-redelivery[.]example/track';
  r.input_sha256 = hex('inconclusive-input');
  r.subject = { host: 'parcel-redelivery.example', scheme: 'http', defanged: r.input_display };
  r.redirects = [
    { index: 0, url: 'http://parcel-redelivery.example/track', host: 'parcel-redelivery.example', ip: '198.51.100.7', status: 302, location: 'http://10.0.0.5/admin', blocked_reason: null, duration_ms: 210 },
    { index: 1, url: 'http://10.0.0.5/admin', host: '10.0.0.5', ip: '10.0.0.5', status: null, location: null, blocked_reason: 'Private address (10.0.0.0/8) blocked by SSRF guard', duration_ms: 0 },
  ];
  r.tls = null;
  r.web = null;
  r.findings = (r.findings ?? []).filter((f) => f.module === 'url' && f.id !== 'url.brand_in_domain');
  r.findings.push({
    id: 'web.redirect_to_private',
    code: 'web.redirect_to_private',
    module: 'web',
    title: 'Redirect points to a private network address',
    observed: 'The first response redirected to 10.0.0.5, a private address. The fetch was stopped.',
    evidence: { location: 'http://10.0.0.5/admin', policy: 'netguard.private_ranges' },
    source: 'wtd.netguard v1',
    provenance: 'live',
    observed_at: '2026-11-08T05:10:41Z',
    severity: 'medium',
    strength: 'moderate',
    impact: 'Redirecting to internal addresses is unusual for public sites and can indicate probing.',
    recommendation: 'Do not open the link on a work network.',
    limitation: 'The destination page was not inspected, so its content is unknown.',
  });
  r.checks = (r.checks ?? []).map((c) => {
    if (c.name === 'web.fetch') return { ...c, status: 'skipped', detail: 'Stopped by SSRF guard at hop 1 (private address)' };
    if (c.name === 'tls.handshake') return { ...c, status: 'skipped', detail: 'Not applicable: plain HTTP URL' };
    if (c.name === 'content.html_features') return { ...c, status: 'skipped', detail: 'No page content fetched' };
    if (c.name === 'intel.urlhaus') return { ...c, status: 'unavailable', detail: 'URLhaus API did not respond within 8000 ms' };
    if (c.name === 'ai.explain') return { ...c, status: 'unavailable', detail: 'AI provider not reachable' };
    return c;
  });
  r.assessment = {
    classification: 'Inconclusive',
    rule_id: 'R-INC-1',
    rule_text: 'One or more essential checks did not complete; the evidence is insufficient for any other classification.',
    basis_finding_ids: ['web.redirect_to_private'],
    rationale: ['Essential checks web.fetch and intel.urlhaus did not complete.', 'Remaining signals are weak or moderate.'],
    contradictions: [],
    coverage: { applicable: 13, succeeded: 7, failed: 1, unavailable: 2, skipped: 3, essential_missing: ['intel.urlhaus', 'web.fetch'] },
  };
  r.recommended_actions = [
    'Do not open the link, especially on a work or home network with internal devices.',
    'If the message claimed to be a parcel company, check delivery status in the official app or website instead.',
  ];
  r.indicators = [
    { type: 'url', display: r.input_display, match_key: 'http://parcel-redelivery.example/track', hashed: false },
    { type: 'domain', display: 'parcel-redelivery[.]example', match_key: 'parcel-redelivery.example', hashed: false },
    { type: 'ip', display: '198.51.100[.]7', match_key: '198.51.100.7', hashed: false },
  ];
  r.limitations = ['The destination page was not fetched because the redirect pointed to a private address.', 'URLhaus did not respond, so threat-intelligence coverage is incomplete.', 'No automated check can prove a site or message is safe.'];
  r.ai = { status: 'unavailable', provider: 'ollama', model: 'llama3.1:8b-instruct', error: 'Connection refused (127.0.0.1:11434)', points: [], observations: [], recommended_actions: [], validation_notes: [] };
  r.correlations = [];
  r.registry = [];
  return r;
}

function variantMessage(): Report {
  const r = clone(SAMPLE);
  r.id = MESSAGE_ID;
  r.kind = 'message';
  r.created_at = '2026-11-08T04:21:09Z';
  r.completed_at = '2026-11-08T04:21:20Z';
  r.input_display =
    'Dear Customer, your SBI YONO account will be BLOCKED today. Update PAN immediately: hxxps://sbi-kyc-update[.]top/verify … Call [phone redacted] for help.';
  r.input_sha256 = hex('message-input');
  r.redirects = [];
  r.tls = null;
  r.web = null;
  r.findings = [
    {
      id: 'message.urgency',
      code: 'message.urgency',
      module: 'message',
      title: 'Message threatens account blocking with a same-day deadline',
      observed: "The text says the account 'will be BLOCKED today'.",
      evidence: { phrases: ['BLOCKED today', 'immediately'] },
      source: 'wtd.message v1',
      provenance: 'live',
      observed_at: '2026-11-08T04:21:10Z',
      severity: 'medium',
      strength: 'weak',
      impact: 'Deadlines push people to act before checking.',
      recommendation: 'Banks do not block accounts by SMS deadline; check in the official app.',
      limitation: 'Urgent wording also appears in genuine reminders.',
    },
    {
      id: 'message.link_brand_mismatch',
      code: 'message.link_brand_mismatch',
      module: 'message',
      title: 'Message claims to be from SBI but links to a non-official domain',
      observed: 'The message names SBI and links to sbi-kyc-update.top, which is not an official SBI domain.',
      evidence: { brand: 'State Bank of India', link_domain: 'sbi-kyc-update.top' },
      source: 'wtd.message v1',
      provenance: 'live',
      observed_at: '2026-11-08T04:21:10Z',
      severity: 'high',
      strength: 'strong',
      impact: 'The link leads away from the bank while claiming to be the bank.',
      recommendation: 'Do not open the link.',
      limitation: 'Official domain list is curated and may be incomplete.',
    },
  ];
  r.checks = [
    { name: 'message.parse', module: 'message', status: 'succeeded', essential: true, detail: 'Text normalised; 1 link, 1 phone number extracted', duration_ms: 3 },
    { name: 'message.language', module: 'message', status: 'succeeded', essential: true, detail: '7 language rules evaluated', duration_ms: 5 },
    { name: 'url.static_rules', module: 'url', status: 'succeeded', essential: true, detail: 'Linked URL analysed statically', duration_ms: 4 },
    { name: 'web.fetch', module: 'web', status: 'skipped', essential: false, detail: 'Link investigation disabled for this submission', duration_ms: 0 },
    { name: 'ai.explain', module: 'ai', status: 'succeeded', essential: false, detail: 'Output rejected by validation', duration_ms: 3104 },
  ];
  r.assessment = {
    classification: 'High Risk',
    rule_id: 'R-HIGH-1',
    rule_text: 'At least one strong signal corroborated by a moderate signal.',
    basis_finding_ids: ['message.link_brand_mismatch', 'message.urgency'],
    rationale: ['Strong signal: brand claim with a non-official link.', 'Corroborated by urgency language.'],
    contradictions: [],
    coverage: { applicable: 4, succeeded: 4, failed: 0, unavailable: 0, skipped: 0, essential_missing: [] },
  };
  r.ai = {
    status: 'rejected',
    provider: 'ollama',
    model: 'llama3.1:8b-instruct',
    latency_ms: 3104,
    injection_attempt_observed: true,
    validation_notes: [
      'Output cited finding ids that do not exist in this report.',
      'Output contained instructions copied from the message ("ignore previous instructions").',
    ],
    points: [],
    observations: [],
    recommended_actions: [],
    error: 'Validation failed: 2 problems',
  };
  r.indicators = [
    { type: 'url', display: 'hxxps://sbi-kyc-update[.]top/verify', match_key: 'https://sbi-kyc-update.top/verify', hashed: false },
    { type: 'phone', display: '+91 ••••• •3210', match_key: hex('phone'), hashed: true },
    { type: 'brand', display: 'State Bank of India', match_key: 'state-bank-of-india', hashed: false },
  ];
  r.correlations = [
    { other_report_id: SAMPLE.id, other_created_at: SAMPLE.created_at, other_classification: 'Suspicious', shared: ['domain: sbi-kyc-update[.]top'], method: 'exact_indicator', score: null },
  ];
  r.registry = [];
  return r;
}

const store = new Map<string, Report>([
  [SAMPLE.id, clone(SAMPLE)],
  [OTHER_ID, variantHighRisk()],
  [INCONCLUSIVE_ID, variantInconclusive()],
  [MESSAGE_ID, variantMessage()],
]);

const registry = new Map<string, RegistryRecord[]>([[SAMPLE.id, clone(SAMPLE.registry ?? [])]]);
const pending = new Map<string, { started: number; base: Report }>();
let counter = 0;

export async function getHealth(): Promise<Health> {
  await delay(120);
  return {
    ok: true,
    version: '0.1.0-mock',
    chain: { connected: true, chain_id: 31337, contract: '0x5FbDB2315678afecb367f032d93F642f64180aa3' },
    ai: { provider: 'ollama', model: 'llama3.1:8b-instruct', status: 'configured' },
    intel: { urlhaus: 'configured', certpl: 'not loaded' },
  };
}

export async function createAnalysis(body: AnalysisRequest): Promise<AnalysisCreated> {
  await delay(250);
  counter += 1;
  const id = `mock-run-${Date.now().toString(36)}-${counter}`;
  const base = clone(body.kind === 'url' ? SAMPLE : store.get(MESSAGE_ID)!);
  base.id = id;
  base.created_at = new Date().toISOString().replace(/\.\d+Z$/, 'Z');
  base.input_display = body.kind === 'url' ? defang(body.url.trim()).slice(0, 300) : body.text.trim().slice(0, 200);
  base.registry = [];
  base.correlations = (base.correlations ?? []).map((c) => ({ ...c }));
  pending.set(id, { started: Date.now(), base });
  return { id, status: 'queued' };
}

export async function getAnalysis(id: string): Promise<Report> {
  await delay(150);
  const p = pending.get(id);
  if (p) {
    const t = Date.now() - p.started;
    const all = p.base.checks ?? [];
    if (t < 1500) return { ...p.base, status: 'queued', checks: [], findings: [], assessment: null, ai: null, completed_at: null };
    if (t < 7000) {
      const n = Math.max(1, Math.floor(((t - 1500) / 5500) * all.length));
      return { ...p.base, status: 'running', checks: all.slice(0, n), findings: [], assessment: null, ai: null, completed_at: null };
    }
    pending.delete(id);
    const done: Report = { ...p.base, status: 'complete', completed_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z') };
    store.set(id, done);
    return clone(done);
  }
  const r = store.get(id);
  if (!r) throw Object.assign(new Error('Report not found (mock mode has 4 sample reports).'), { status: 404 });
  return clone({ ...r, registry: registry.get(id) ?? [] });
}

export async function listAnalyses(): Promise<AnalysisSummary[]> {
  await delay(150);
  const items: AnalysisSummary[] = [];
  for (const [id, p] of pending) {
    items.push({ id, kind: p.base.kind, status: 'running', created_at: p.base.created_at, input_display: p.base.input_display, classification: null });
  }
  for (const r of store.values()) {
    items.push({ id: r.id, kind: r.kind, status: r.status, created_at: r.created_at, input_display: r.input_display, classification: r.assessment?.classification ?? null });
  }
  return items.sort((a, b) => b.created_at.localeCompare(a.created_at));
}

function makeRecord(id: string, revision: number): RegistryRecord {
  const existing = registry.get(id)?.[0];
  return {
    chain_id: 31337,
    contract: '0x5FbDB2315678afecb367f032d93F642f64180aa3',
    report_id_hex: existing?.report_id_hex ?? '0x' + hex('rid:' + id),
    commitment: '0x' + hex(`commitment:${id}:${revision}:${Date.now()}`),
    revision,
    tx_hash: '0x' + hex(`tx:${id}:${revision}:${Date.now()}`),
    block_number: 7 + revision * 3 + counter,
    registered_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
    canonicalization: 'RFC8785-JCS',
  };
}

function threatReportDoc(id: string) {
  const r = store.get(id);
  return {
    schema: 'wtd.threat-report.v1',
    report_id: id,
    created_at: r?.created_at ?? '',
    kind: r?.kind ?? 'url',
    classification: r?.assessment?.classification ?? 'Inconclusive',
    rule_id: r?.assessment?.rule_id ?? '',
    indicators: (r?.indicators ?? []).filter((i) => !i.hashed).map((i) => ({ type: i.type, value: i.display })),
    findings: (r?.findings ?? []).map((f) => ({ id: f.id, code: f.code, severity: f.severity, strength: f.strength, title: f.title })),
    evidence_digest: 'sha256:' + hex('digest:' + id),
    summary: r?.ai?.summary ?? '',
    submitter: 'mock operator',
  };
}

export async function getEnvelope(id: string) {
  await delay(100);
  if (!(registry.get(id) ?? []).length) throw Object.assign(new Error('Not registered yet.'), { status: 404 });
  return { schema: 'wtd.commitment.v1', salt: hex('salt:' + id), threat_report: threatReportDoc(id) };
}

export async function registerThreatReport(id: string, _submitter?: string): Promise<RegistrationResult> {
  await delay(900);
  if ((registry.get(id) ?? []).length) throw Object.assign(new Error('Already registered; publish a revision instead.'), { status: 409 });
  const rec = makeRecord(id, 0);
  registry.set(id, [rec]);
  return { threat_report: threatReportDoc(id), envelope: await getEnvelope(id), commitment: rec.commitment, record: rec };
}

export async function reviseThreatReport(id: string, reason: string): Promise<RegistrationResult> {
  await delay(900);
  const recs = registry.get(id) ?? [];
  if (!recs.length) throw Object.assign(new Error('Register the report first.'), { status: 409 });
  if (!reason.trim()) throw Object.assign(new Error('A reason is required.'), { status: 422 });
  const rec = makeRecord(id, recs.length);
  registry.set(id, [...recs, rec]);
  return { threat_report: threatReportDoc(id), envelope: await getEnvelope(id), commitment: rec.commitment, record: rec };
}

export async function getThreatReport(id: string): Promise<ThreatReportState | null> {
  await delay(150);
  const recs = registry.get(id) ?? [];
  if (!recs.length) return null;
  return {
    envelope: await getEnvelope(id),
    commitment: recs[recs.length - 1].commitment,
    records: clone(recs),
    onchain: {
      revisions: recs.map((r) => ({ index: r.revision, commitment: r.commitment, classification: 2, timestamp: Math.floor(new Date(r.registered_at).getTime() / 1000), author: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' })),
      status_history: [{ index: 0, status: 'Pending', timestamp: Math.floor(new Date(recs[recs.length - 1].registered_at).getTime() / 1000), by: '0x70997970C51812dc3A010C7d01b50e0d17dc79C8' }],
    },
  };
}

export async function verifyIntegrity(id: string): Promise<VerifyResult> {
  await delay(600);
  const recs = registry.get(id) ?? [];
  if (!recs.length) throw Object.assign(new Error('Not registered yet.'), { status: 404 });
  const latest = recs[recs.length - 1];
  return {
    match: true,
    matched_revision: latest.revision,
    latest_revision: latest.revision,
    recomputed: latest.commitment,
    onchain_latest: latest.commitment,
    status: 'Pending',
    checked_at: new Date().toISOString().replace(/\.\d+Z$/, 'Z'),
  };
}

export async function listIncidents(): Promise<Incident[]> {
  await delay(150);
  return [
    {
      cluster_id: 'cl-' + hex('cluster-1').slice(0, 10),
      report_ids: [SAMPLE.id, OTHER_ID, MESSAGE_ID],
      shared: ['ip: 203.0.113[.]45', 'brand: State Bank of India', 'domain: sbi-kyc-update[.]top'],
      classifications: ['High Risk', 'Suspicious'],
      first_seen: '2026-11-07T18:03:55Z',
      last_seen: SAMPLE.created_at,
    },
  ];
}
