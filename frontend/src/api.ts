// HTTP client for the WTD API (docs/INTERFACES.md §2).
// - The operator token lives in sessionStorage only (this tab), is sent as X-WTD-Token,
//   and is never placed in URLs or logged.
// - A 401 clears the token and asks the operator again, then retries.
// - In mock mode (?mock=1) every call is answered locally from src/mock and no request is made.
import type {
  AccessInfo,
  QuotaInfo,
  AnalysisCreated,
  AnalysisRequest,
  AnalysisSummary,
  Health,
  Incident,
  CampaignBrief,
  ReviewRecord,
  RegistrationResult,
  Report,
  ThreatReportState,
  VerifyResult,
} from './types';
import * as mock from './mock';

export const MOCK_MODE: boolean = (() => {
  try {
    const q = new URLSearchParams(window.location.search);
    return q.get('mock') === '1';
  } catch {
    return false;
  }
})();

export class ApiError extends Error {
  readonly status: number;
  readonly code: 'network' | 'token_required' | 'http';
  constructor(status: number, message: string, code: ApiError['code'] = 'http') {
    super(message);
    this.status = status;
    this.code = code;
  }
}

// ---------------- token handling ----------------

const TOKEN_KEY = 'wtd.operatorToken';
let memoryToken: string | null = null;
const tokenListeners = new Set<() => void>();

export function getToken(): string | null {
  try {
    return window.sessionStorage.getItem(TOKEN_KEY) ?? memoryToken;
  } catch {
    return memoryToken;
  }
}

export function setToken(token: string): void {
  memoryToken = token;
  try {
    window.sessionStorage.setItem(TOKEN_KEY, token);
  } catch {
    /* storage blocked: keep in memory for this page only */
  }
  tokenListeners.forEach((l) => l());
}

export function clearToken(): void {
  memoryToken = null;
  try {
    window.sessionStorage.removeItem(TOKEN_KEY);
  } catch {
    /* ignore */
  }
  tokenListeners.forEach((l) => l());
}

export function onTokenChange(l: () => void): () => void {
  tokenListeners.add(l);
  return () => tokenListeners.delete(l);
}

export type TokenReason = 'missing' | 'rejected';

// The prompt is a tiny external store so it works no matter which component mounts first.
let prompt: { reason: TokenReason } | null = null;
let promptResolve: ((t: string | null) => void) | null = null;
const promptListeners = new Set<() => void>();
const emitPrompt = () => promptListeners.forEach((l) => l());

export function subscribeTokenPrompt(l: () => void): () => void {
  promptListeners.add(l);
  return () => promptListeners.delete(l);
}

export function getTokenPrompt(): { reason: TokenReason } | null {
  return prompt;
}

/** Called by <TokenDialog/> with the entered token, or null when the operator cancels. */
export function resolveTokenPrompt(token: string | null): void {
  const r = promptResolve;
  promptResolve = null;
  prompt = null;
  emitPrompt();
  r?.(token);
}

function askForToken(reason: TokenReason): Promise<string | null> {
  return new Promise((resolve) => {
    promptResolve?.(null);
    promptResolve = resolve;
    prompt = { reason };
    emitPrompt();
  });
}

let pendingToken: Promise<string> | null = null;

function obtainToken(reason: TokenReason): Promise<string> {
  if (!pendingToken) {
    pendingToken = (async () => {
      const t = await askForToken(reason);
      if (!t) throw new ApiError(401, 'An operator token is required to use the analysis API.', 'token_required');
      setToken(t);
      return t;
    })().finally(() => {
      pendingToken = null;
    });
  }
  return pendingToken;
}


// ---------------- investigator's own URLhaus key ----------------
// Optional abuse.ch Auth-Key a visitor (e.g. a judge) supplies when the server has none or they prefer their own.
// Kept in sessionStorage for this tab only, sent as X-URLhaus-Key with each analysis, never stored by the server.

const URLHAUS_KEY = 'wtd.urlhausKey';
export const URLHAUS_KEY_RE = /^[A-Za-z0-9]{20,100}$/;
let memoryUrlhaus: string | null = null;
const urlhausListeners = new Set<() => void>();

export function getUrlhausKey(): string | null {
  try {
    return window.sessionStorage.getItem(URLHAUS_KEY) ?? memoryUrlhaus;
  } catch {
    return memoryUrlhaus;
  }
}

export function setUrlhausKey(key: string): void {
  memoryUrlhaus = key;
  try {
    window.sessionStorage.setItem(URLHAUS_KEY, key);
  } catch {
    /* storage blocked: keep in memory for this page only */
  }
  urlhausListeners.forEach((l) => l());
}

export function clearUrlhausKey(): void {
  memoryUrlhaus = null;
  try {
    window.sessionStorage.removeItem(URLHAUS_KEY);
  } catch {
    /* ignore */
  }
  urlhausListeners.forEach((l) => l());
}

export function onUrlhausKeyChange(l: () => void): () => void {
  urlhausListeners.add(l);
  return () => urlhausListeners.delete(l);
}

// Open/close state for <UrlhausKeyDialog/>, so the header pill and the Investigate page can both open it.
let urlhausDialogOpen = false;
const urlhausDialogListeners = new Set<() => void>();
export function isUrlhausDialogOpen(): boolean {
  return urlhausDialogOpen;
}
export function setUrlhausDialogOpen(open: boolean): void {
  urlhausDialogOpen = open;
  urlhausDialogListeners.forEach((l) => l());
}
export function subscribeUrlhausDialog(l: () => void): () => void {
  urlhausDialogListeners.add(l);
  return () => urlhausDialogListeners.delete(l);
}

// ---------------- public demo: access mode and browser session ----------------

let accessPromise: Promise<AccessInfo> | null = null;

/** Access mode from /api/health, fetched once per page load. */
export function accessInfo(): Promise<AccessInfo> {
  if (MOCK_MODE) return Promise.resolve({ mode: 'operator_token' });
  if (!accessPromise)
    accessPromise = getHealth()
      .then((h) => h.access ?? { mode: 'operator_token' as const })
      .catch((e: unknown) => {
        accessPromise = null;
        throw e;
      });
  return accessPromise;
}

async function isPublicDemo(): Promise<boolean> {
  try {
    return (await accessInfo()).mode === 'public_demo';
  } catch {
    return false;
  }
}

const SESSION_KEY = 'wtd.session';
let memorySession: string | null = null;

function randomId(): string {
  if (typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  const b = crypto.getRandomValues(new Uint8Array(16));
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('');
}

/** Random id for this browser tab's session (sessionStorage), used by the public demo's per-session limit. */
export function getSessionId(): string {
  try {
    let id = window.sessionStorage.getItem(SESSION_KEY);
    if (!id) {
      id = randomId();
      window.sessionStorage.setItem(SESSION_KEY, id);
    }
    return id;
  } catch {
    memorySession ??= randomId();
    return memorySession;
  }
}

// ---------------- core request ----------------

interface RequestOpts {
  method?: 'GET' | 'POST';
  body?: unknown;
  auth?: boolean;
  headers?: Record<string, string>;
}

async function errorFromResponse(res: Response): Promise<ApiError> {
  let detail = '';
  try {
    const data: unknown = await res.json();
    if (data && typeof data === 'object' && 'detail' in data) {
      const d = (data as { detail: unknown }).detail;
      if (typeof d === 'string') detail = d;
      else if (Array.isArray(d))
        detail = d
          .map((e) => (e && typeof e === 'object' && 'msg' in e ? String((e as { msg: unknown }).msg) : String(e)))
          .join('; ');
      else detail = JSON.stringify(d);
    }
  } catch {
    /* non-JSON error body */
  }
  if (res.status === 429) return new ApiError(429, detail || 'Too many requests. Wait a moment and try again.');
  if (res.status === 404) return new ApiError(404, detail || 'Not found.');
  return new ApiError(res.status, detail || `Request failed (HTTP ${res.status}).`);
}

/** Backend origin. Empty = same origin (the API serves the dashboard). Set VITE_API_BASE at build time for a
 *  separately hosted dashboard, e.g. Vercel → https://wtd-api.onrender.com (the API must list this origin in WTD_CORS_ORIGINS). */
export const API_BASE: string = ((import.meta.env.VITE_API_BASE as string | undefined) ?? '').trim().replace(/\/+$/, '');

async function request(path: string, opts: RequestOpts = {}, attempt = 0): Promise<Response> {
  const { method = 'GET', body, auth = true } = opts;
  const headers = new Headers({ Accept: 'application/json', ...(opts.headers ?? {}) });
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  let sent: string | null = null;
  if (auth) {
    // In the public demo the token is optional; the operator can still set one to lift the limits.
    sent = getToken() ?? ((await isPublicDemo()) ? null : await obtainToken('missing'));
    if (sent) headers.set('X-WTD-Token', sent);
  }
  let res: Response;
  try {
    res = await fetch(API_BASE + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
      credentials: 'same-origin',
      cache: 'no-store',
      referrerPolicy: 'no-referrer',
      redirect: 'error',
    });
  } catch {
    throw new ApiError(0, 'Cannot reach the WTD service. Check that the backend is running.', 'network');
  }
  if (res.status === 401 && auth && attempt < 3) {
    // Only discard the token we actually sent; another request may already have replaced it.
    if (getToken() === sent) {
      clearToken();
      await obtainToken(sent ? 'rejected' : 'missing');
    }
    return request(path, opts, attempt + 1);
  }
  if (!res.ok) throw await errorFromResponse(res);
  return res;
}

async function json<T>(path: string, opts?: RequestOpts): Promise<T> {
  const res = await request(path, opts);
  return (await res.json()) as T;
}

const enc = encodeURIComponent;

// ---------------- endpoints ----------------

export function getHealth(): Promise<Health> {
  if (MOCK_MODE) return mock.getHealth();
  return json<Health>('/api/health', { auth: false });
}

export function createAnalysis(body: AnalysisRequest): Promise<AnalysisCreated> {
  if (MOCK_MODE) return mock.createAnalysis(body);
  // Custom headers only where needed: the session id is what the public demo's per-session limit counts.
  const own = getUrlhausKey();
  const headers: Record<string, string> = { 'X-WTD-Session': getSessionId() };
  if (own) headers['X-URLhaus-Key'] = own;
  return json<AnalysisCreated>('/api/analyses', { method: 'POST', body, headers });
}

/** Analyses left for this browser session in the public demo. */
export function getQuota(): Promise<QuotaInfo> {
  if (MOCK_MODE) return Promise.resolve({ public_demo: false });
  return json<QuotaInfo>('/api/quota', { auth: false, headers: { 'X-WTD-Session': getSessionId() } });
}

/** Asks the server to test a URLhaus key with one harmless lookup. The key is not saved anywhere by the server. */
export function checkUrlhausKey(key: string): Promise<{ accepted: boolean; message: string }> {
  if (MOCK_MODE) return Promise.reject(new ApiError(0, 'Not available in mock mode', 'network'));
  return json<{ accepted: boolean; message: string }>('/api/intel/urlhaus/check', { method: 'POST', headers: { 'X-URLhaus-Key': key } });
}

export function listAnalyses(limit = 50): Promise<AnalysisSummary[]> {
  if (MOCK_MODE) return mock.listAnalyses();
  return json<AnalysisSummary[]>(`/api/analyses?limit=${limit}`);
}

export function getAnalysis(id: string): Promise<Report> {
  if (MOCK_MODE) return mock.getAnalysis(id);
  return json<Report>(`/api/analyses/${enc(id)}`);
}

export function registerThreatReport(id: string, submitter?: string): Promise<RegistrationResult> {
  if (MOCK_MODE) return mock.registerThreatReport(id, submitter);
  const body = submitter ? { submitter } : {};
  return json<RegistrationResult>(`/api/analyses/${enc(id)}/threat-report`, { method: 'POST', body });
}

export function reviseThreatReport(id: string, reason: string): Promise<RegistrationResult> {
  if (MOCK_MODE) return mock.reviseThreatReport(id, reason);
  return json<RegistrationResult>(`/api/analyses/${enc(id)}/threat-report/revise`, { method: 'POST', body: { reason } });
}

export function reviewThreatReport(id: string, status: 'Validated' | 'Disputed' | 'Retracted', note: string): Promise<ReviewRecord> {
  if (MOCK_MODE) return Promise.reject(new ApiError(0, 'Not available in mock mode', 'network'));
  return json<ReviewRecord>(`/api/analyses/${enc(id)}/threat-report/review`, { method: 'POST', body: { status, note } });
}

/** Returns null when the report has not been registered (404). */
export async function getThreatReport(id: string): Promise<ThreatReportState | null> {
  if (MOCK_MODE) return mock.getThreatReport(id);
  try {
    return await json<ThreatReportState>(`/api/analyses/${enc(id)}/threat-report`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

export function verifyIntegrity(id: string): Promise<VerifyResult> {
  if (MOCK_MODE) return mock.verifyIntegrity(id);
  return json<VerifyResult>(`/api/analyses/${enc(id)}/verify`);
}

export async function downloadEnvelope(id: string): Promise<{ blob: Blob; filename: string }> {
  const fallback = `wtd-threat-report-${id.replace(/[^A-Za-z0-9_-]/g, '').slice(0, 8) || 'report'}.json`;
  if (MOCK_MODE) {
    const env = await mock.getEnvelope(id);
    return { blob: new Blob([JSON.stringify(env, null, 2)], { type: 'application/json' }), filename: fallback };
  }
  const res = await request(`/api/analyses/${enc(id)}/threat-report/download`);
  const blob = await res.blob();
  // Accept a server-suggested filename only if it is a plain, safe file name.
  const cd = res.headers.get('Content-Disposition') ?? '';
  const m = /filename="?([A-Za-z0-9._-]{1,100})"?/.exec(cd);
  const filename = m && !m[1].startsWith('.') ? m[1] : fallback;
  return { blob: new Blob([blob], { type: 'application/json' }), filename };
}

export function listIncidents(): Promise<Incident[]> {
  if (MOCK_MODE) return mock.listIncidents();
  return json<Incident[]>('/api/incidents');
}

/** Returns null when no brief has been generated for this cluster (404). */
export async function getCampaignBrief(clusterId: string): Promise<CampaignBrief | null> {
  if (MOCK_MODE) return null;
  try {
    return await json<CampaignBrief>(`/api/incidents/${enc(clusterId)}/brief`);
  } catch (e) {
    if (e instanceof ApiError && e.status === 404) return null;
    throw e;
  }
}

export function createCampaignBrief(clusterId: string): Promise<CampaignBrief> {
  if (MOCK_MODE) return Promise.reject(new ApiError(0, 'Not available in mock mode', 'network'));
  return json<CampaignBrief>(`/api/incidents/${enc(clusterId)}/brief`, { method: 'POST', body: {} });
}

/** Save a Blob we generated ourselves as a file. */
export function saveBlob(blob: Blob, filename: string): void {
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  a.rel = 'noopener';
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 2000);
}

export function errorMessage(e: unknown): string {
  if (e instanceof ApiError) return e.message;
  if (e instanceof Error) return e.message;
  return 'Unexpected error.';
}
