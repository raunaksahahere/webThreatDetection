// HTTP client for the WTD API (docs/INTERFACES.md §2).
// - The operator token lives in sessionStorage only (this tab), is sent as X-WTD-Token,
//   and is never placed in URLs or logged.
// - A 401 clears the token and asks the operator again, then retries.
// - In mock mode (?mock=1) every call is answered locally from src/mock and no request is made.
import type {
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

export type TokenReason = 'missing' | 'rejected' | 'manual';

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

export function requestTokenManually(): Promise<string> {
  return obtainToken('manual');
}

// ---------------- core request ----------------

interface RequestOpts {
  method?: 'GET' | 'POST';
  body?: unknown;
  auth?: boolean;
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

async function request(path: string, opts: RequestOpts = {}, attempt = 0): Promise<Response> {
  const { method = 'GET', body, auth = true } = opts;
  const headers = new Headers({ Accept: 'application/json' });
  if (body !== undefined) headers.set('Content-Type', 'application/json');
  let sent: string | null = null;
  if (auth) {
    sent = getToken() ?? (await obtainToken('missing'));
    headers.set('X-WTD-Token', sent);
  }
  let res: Response;
  try {
    res = await fetch(path, {
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
      await obtainToken('rejected');
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
  return json<AnalysisCreated>('/api/analyses', { method: 'POST', body });
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
