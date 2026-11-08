// Hand-written mirror of docs/report.schema.json (wtd.report.v1) and the HTTP API in docs/INTERFACES.md §2.
// Every string here is untrusted data from analysed content: render as plain text only.

export type Classification = 'Low Risk' | 'Suspicious' | 'High Risk' | 'Confirmed Malicious' | 'Inconclusive';
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical';
export type Strength = 'weak' | 'moderate' | 'strong' | 'authoritative';
export type CheckStatus = 'succeeded' | 'failed' | 'unavailable' | 'skipped' | 'not_implemented';
export type Provenance = 'live' | 'cached' | 'dataset' | 'synthetic' | 'ai';
export type AIStatus = 'ok' | 'unavailable' | 'failed' | 'disabled' | 'rejected';
export type Module = 'url' | 'dns' | 'intel' | 'tls' | 'web' | 'content' | 'message' | 'correlation' | 'ai';
export type ReportStatus = 'queued' | 'running' | 'complete' | 'failed' | 'interrupted';
export type ReportKind = 'url' | 'message';

export type EvidenceValue = string | number | boolean | null | string[] | number[] | { [k: string]: unknown };
export type EvidenceMap = { [key: string]: EvidenceValue };

export interface Finding {
  id: string;
  code: string;
  module: Module;
  title: string;
  observed: string;
  evidence?: EvidenceMap;
  source: string;
  provenance?: Provenance;
  observed_at: string;
  severity: Severity;
  strength: Strength;
  impact: string;
  recommendation: string;
  limitation: string;
}

export interface CheckResult {
  name: string;
  module: Module;
  status: CheckStatus;
  essential: boolean;
  detail?: string;
  duration_ms?: number;
}

export interface Hop {
  index: number;
  url: string;
  host: string;
  ip?: string | null;
  status?: number | null;
  location?: string | null;
  blocked_reason?: string | null;
  tls_version?: string | null;
  duration_ms?: number;
}

export type IndicatorType = 'url' | 'domain' | 'ip' | 'email' | 'phone' | 'upi' | 'crypto_wallet' | 'brand' | 'cert_spki';

export interface Indicator {
  type: IndicatorType;
  display: string;
  match_key: string;
  hashed?: boolean;
}

export interface Coverage {
  applicable: number;
  succeeded: number;
  failed: number;
  unavailable: number;
  skipped: number;
  essential_missing: string[];
}

export interface Assessment {
  classification: Classification;
  rule_id: string;
  rule_text: string;
  basis_finding_ids: string[];
  rationale: string[];
  contradictions: string[];
  coverage: Coverage;
}

export interface AIPoint {
  finding_ids: string[];
  explanation: string;
}

export interface AIObservation {
  technique: string;
  quote: string;
  rationale: string;
  quote_verified: boolean;
}

export interface AIResult {
  status: AIStatus;
  provider?: string | null;
  model?: string | null;
  latency_ms?: number | null;
  summary?: string | null;
  points?: AIPoint[];
  observations?: AIObservation[];
  recommended_actions?: string[];
  uncertainty?: string | null;
  injection_attempt_observed?: boolean | null;
  validation_notes?: string[];
  error?: string | null;
}

export type CorrelationMethod = 'exact_indicator' | 'message_similarity' | 'brand_pattern' | 'infrastructure';

export interface CorrelationLink {
  other_report_id: string;
  other_created_at: string;
  other_classification: string;
  shared: string[];
  method: CorrelationMethod;
  score?: number | null;
}

export interface RegistryRecord {
  chain_id: number;
  contract: string;
  report_id_hex: string;
  commitment: string;
  revision: number;
  tx_hash: string;
  block_number: number;
  registered_at: string;
  canonicalization: string;
}

export interface Report {
  schema_version?: 'wtd.report.v1';
  id: string;
  kind: ReportKind;
  status: ReportStatus;
  created_at: string;
  completed_at?: string | null;
  input_display: string;
  input_sha256: string;
  subject?: EvidenceMap;
  redirects?: Hop[];
  tls?: EvidenceMap | null;
  web?: EvidenceMap | null;
  indicators?: Indicator[];
  findings?: Finding[];
  checks?: CheckResult[];
  assessment?: Assessment | null;
  ai?: AIResult | null;
  correlations?: CorrelationLink[];
  recommended_actions?: string[];
  limitations?: string[];
  registry?: RegistryRecord[];
  error?: string | null;
}

// ---- HTTP API shapes (INTERFACES.md §2) ----

export interface Health {
  ok: boolean;
  version?: string;
  chain?: { connected?: boolean; chain_id?: number | null; contract?: string | null };
  ai?: { provider?: string | null; model?: string | null; status?: string | null };
  intel?: { [source: string]: unknown };
}

export type AnalysisRequest =
  | { kind: 'url'; url: string; via?: 'qr' }
  | { kind: 'message'; text: string; investigate_links: boolean; via?: 'qr' };

export interface AnalysisCreated {
  id: string;
  status: ReportStatus;
}

export interface AnalysisSummary {
  id: string;
  kind: ReportKind;
  status: ReportStatus;
  created_at: string;
  input_display: string;
  classification: Classification | null;
}

export interface RegistrationResult {
  threat_report: { [k: string]: unknown };
  envelope: { [k: string]: unknown };
  commitment: string;
  record: RegistryRecord;
}

export interface ThreatReportState {
  envelope: { [k: string]: unknown };
  commitment: string;
  records: RegistryRecord[];
  onchain?: { revisions?: unknown[]; status_history?: unknown[]; current_status?: string | null; error?: string } | null;
  reviews?: ReviewRecord[];
}

export interface ReviewRecord {
  tx_hash: string;
  status: 'Validated' | 'Disputed' | 'Retracted';
  note: string;
  note_hash: string;
  reviewer: string;
  created_at?: string;
}

export interface VerifyResult {
  match: boolean;
  matched_revision: number | null;
  latest_revision: number | null;
  recomputed: string;
  onchain_latest: string | null;
  status: string | null;
  checked_at?: string;
  note?: string;
}

export type IncidentKind = 'campaign' | 'shared_infrastructure' | 'repeat_checks';

export interface IncidentReportRef {
  id: string;
  kind: 'url' | 'message';
  target: string;
  created_at: string;
  classification: string | null;
  rule: string | null;
}

export interface IncidentLink {
  a: string;
  b: string;
  shared: string[];
  different_targets: boolean;
}

export interface Incident {
  cluster_id: string;
  kind?: IncidentKind;
  report_ids: string[];
  distinct_targets?: number;
  shared: string[];
  links?: IncidentLink[];
  reports?: IncidentReportRef[];
  classifications?: string[];
  first_seen: string;
  last_seen: string;
  has_brief?: boolean;
}

export interface CampaignBrief {
  cluster_id: string;
  link_type: IncidentKind;
  report_ids: string[];
  generated_at: string;
  status: 'ok' | 'rejected' | 'failed' | 'unavailable' | 'disabled';
  error?: string;
  summary?: string;
  assessment?: 'likely_same_campaign' | 'possibly_related' | 'not_enough_evidence' | 'repeat_checks_only';
  link_explanations?: { indicator: string; report_ids: string[]; explanation: string }[];
  common_tactics?: { technique: string; report_ids: string[]; finding_ids: string[] }[];
  next_steps?: string[];
  uncertainty?: string;
  injection_attempt_observed?: boolean;
  validation_notes?: string[];
  provider?: string;
  model?: string;
  latency_ms?: number;
}
