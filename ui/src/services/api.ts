const API_BASE = "/api";
const DEFAULT_TIMEOUT_MS = 15_000;

export class ApiError extends Error {
  status: number;
  detail?: string;

  constructor(message: string, status: number, detail?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.detail = detail;
  }
}

interface RequestOptions extends RequestInit {
  timeoutMs?: number;
}

async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
  const { timeoutMs = DEFAULT_TIMEOUT_MS, ...init } = options;
  const controller = new AbortController();
  const timer = window.setTimeout(() => controller.abort(), timeoutMs);

  try {
    const res = await fetch(`${API_BASE}${path}`, { ...init, signal: controller.signal });
    if (!res.ok) {
      let detail: string | undefined;
      try {
        const body = await res.json();
        detail = typeof body.detail === "string" ? body.detail : undefined;
      } catch {
        // ignore body parse failure
      }
      throw new ApiError(`Request failed: ${res.status}`, res.status, detail);
    }
    if (res.status === 204) return undefined as T;
    return (await res.json()) as T;
  } catch (err) {
    if (err instanceof DOMException && err.name === "AbortError") {
      throw new ApiError(`Request timed out after ${timeoutMs}ms`, 0, "timeout");
    }
    throw err;
  } finally {
    window.clearTimeout(timer);
  }
}

export interface StageInfo {
  name: string;
  status: string;
  message: string;
  progress: number;
}

export interface TaskResponse {
  task_id: string;
  status: string;
  progress?: number;
  stages?: StageInfo[];
  ioc_value: string;
  error?: string;
}

export interface NormalizedResult {
  ioc: string;
  ioc_type: string;
  source: string;
  verdict: string;
  status: string;
  raw_score: number | null;
  confidence: string;
  tags: string[];
  categories: string[];
  malware_family?: string;
  mitre_attck?: string[];
  first_seen?: string | null;
  last_seen?: string | null;
  related_iocs?: [string, string][];
  source_link?: string;
  reports_count?: number;
  reports?: Record<string, unknown>[];
  raw_data?: Record<string, unknown>;
  samples?: string[];
  dropped_files?: string[];
  registry_keys?: string[];
  network_iocs?: [string, string][];
  process_tree?: string;
  ssdeep?: string;
  tlsh?: string;
}

export interface GeoIPInfo {
  country?: string;
  country_code?: string;
  city?: string;
  asn?: string;
  asn_name?: string;
  isp?: string;
  org?: string;
  latitude?: number;
  longitude?: number;
}

export interface WhoisInfo {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  abuse_email?: string;
  org?: string;
}

export interface DNSInfo {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
  txt: string[];
  cname: string[];
}

export interface SSLInfo {
  subject?: string;
  issuer?: string;
  serial?: string;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
  subject_alt_names: string[];
  is_self_signed: boolean;
  is_expired: boolean;
  is_wildcard: boolean;
  days_remaining?: number;
}

export interface ReverseDNSInfo {
  hostnames: string[];
}

export interface SubdomainInfo {
  subdomains: string[];
}

export interface PassiveDNSInfo {
  records: Record<string, unknown>[];
}

export interface CVEInfo {
  is_in_kev: boolean;
  kev_date_added: string;
  epss_score?: number;
  epss_percentile?: number;
  cvss_vector: string;
  cvss_attack_vector: string;
  cvss_complexity: string;
  cvss_privileges_required: string;
  cvss_user_interaction: string;
  cwe: string[];
  references: string[];
  public_exploits_exist: boolean;
  exploit_sources: string[];
  poc_available: boolean;
  affected_products: string[];
}

export interface BreachInfo {
  breach_count?: number;
  breach_names: string[];
  most_recent_breach: string;
  exposed_data_types: string[];
  source: string;
}

export interface FaviconInfo {
  favicon_hash: number;
  favicon_url: string;
}

export interface EmailSecurityInfo {
  spf: string;
  dkim: string;
  dmarc: string;
}

export interface EnrichmentData {
  geoip?: GeoIPInfo;
  open_ports: number[];
  whois?: WhoisInfo;
  dns?: DNSInfo;
  ssl?: SSLInfo;
  reverse_dns?: ReverseDNSInfo;
  subdomains?: SubdomainInfo;
  cve?: CVEInfo;
  breach?: BreachInfo;
  favicon?: FaviconInfo;
  email_security?: EmailSecurityInfo;
  passive_dns?: PassiveDNSInfo;
  redirect_chain: Record<string, unknown>[];
  url_preview: Record<string, unknown>;
  extra: Record<string, unknown>;
  relationships: Relationship[];
  completeness: Record<string, string>;
  analysis_notes?: string[];
}

export interface SourceWeight {
  name: string;
  weight: number;
  verdict: string;
  score: number | null;
  confidence: string | null;
}

export interface CompositeScore {
  score: number;
  verdict: string;
  confidence: string;
  sources_contributing: number;
  source_breakdown: SourceWeight[];
}

export interface Relationship {
  source_ioc?: string;
  target_ioc?: string;
  relationship?: string;
  via_source?: string;
  [key: string]: unknown;
}

export interface LookupResponse {
  input: string;
  normalized: string;
  ioc_type: string;
  composite: CompositeScore;
  enrichment: EnrichmentData;
  results: NormalizedResult[];
  relationships: Relationship[];
  executive_summary: string;
}

export interface SourceInventoryItem {
  name: string;
  supported_types: string[];
  public_without_key: boolean;
  requires_key: boolean;
  configured: boolean;
  available: boolean;
  enabled_by_policy: boolean;
  credential_env?: string;
  credential_source: string;
  rate_limit_per_minute: number;
}

export interface SourceInventory {
  sources: SourceInventoryItem[];
  count: number;
  available_count: number;
  credential_configured_count: number;
}

export async function lookupIOC(value: string, iocType?: string): Promise<TaskResponse> {
  return request<TaskResponse>("/lookup", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc: value, ioc_type: iocType }),
  });
}

export async function getSourceInventory(): Promise<SourceInventory> {
  return request<SourceInventory>("/sources");
}

export async function getTaskStatus(taskId: string): Promise<TaskResponse> {
  return request<TaskResponse>(`/tasks/${taskId}`);
}

export async function getTaskResult(taskId: string): Promise<LookupResponse> {
  try {
    return await request<LookupResponse>(`/tasks/${taskId}/result`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 425) throw new ApiError("not_ready", 425);
    throw err;
  }
}

// --- Batch ---

export interface BatchSubtask {
  task_id: string;
  ioc_value: string;
  status: string;
  progress: number;
  error?: string;
}

export interface BatchStatus {
  batch_id: string;
  status: string;
  progress: number;
  total: number;
  completed: number;
  subtasks: BatchSubtask[];
  error?: string;
}

export interface BatchResultSummary {
  malicious: number;
  suspicious: number;
  clean: number;
  unknown: number;
  error: number;
}

export interface BatchResultItem extends NormalizedResult {
  _ioc: string;
}

export interface BatchResult {
  batch_id: string;
  total: number;
  completed: number;
  summary: BatchResultSummary;
  results: BatchResultItem[];
  relationships: Relationship[];
}

export async function startBatch(iocs: string[]): Promise<{ batch_id: string; total: number; status: string }> {
  return request("/batch", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ iocs }),
  });
}

export async function getBatchStatus(batchId: string): Promise<BatchStatus> {
  return request<BatchStatus>(`/batch/${batchId}`);
}

export async function getBatchResult(batchId: string): Promise<BatchResult> {
  try {
    return await request<BatchResult>(`/batch/${batchId}/result`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 425) throw new ApiError("not_ready", 425);
    throw err;
  }
}

export async function uploadBatchFile(file: File): Promise<{ batch_id: string; total: number; status: string }> {
  const form = new FormData();
  form.append("file", file);
  return request("/batch/upload", { method: "POST", body: form });
}

export type BatchSSEEventName = "batch_started" | "progress" | "batch_done" | "heartbeat" | string;

export interface BatchSSEEvent {
  event: BatchSSEEventName;
  data: Record<string, unknown>;
}

export async function streamBatchProgress(
  batchId: string,
  onEvent: (event: BatchSSEEvent) => void,
  signal?: AbortSignal,
): Promise<void> {
  const res = await fetch(`${API_BASE}/batch/${batchId}/stream`, { signal });
  if (!res.ok || !res.body) throw new ApiError(`Stream failed: ${res.status}`, res.status);
  const reader = res.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  try {
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      const events = buffer.split("\n\n");
      buffer = events.pop() ?? "";
      for (const block of events) {
        const event = parseSSE(block);
        if (event) onEvent(event);
      }
    }
  } finally {
    reader.releaseLock();
  }
}

function parseSSE(block: string): BatchSSEEvent | null {
  let event = "message";
  let dataRaw = "";
  for (const line of block.split("\n")) {
    if (line.startsWith("event:")) event = line.slice(6).trim();
    else if (line.startsWith("data:")) dataRaw += line.slice(5).trim();
  }
  if (!dataRaw) return null;
  let data: Record<string, unknown> = {};
  try {
    data = JSON.parse(dataRaw);
  } catch {
    return null;
  }
  return { event, data };
}

// --- Investigations ---

export interface InvestigationSummary {
  id: number;
  name: string;
  description: string;
  ioc_count: number;
  created_at: string;
  updated_at: string;
}

export interface InvestigationIOCEntry {
  id: number;
  ioc_id: number;
  value: string;
  ioc_type: string;
  notes: string;
  score: number | null;
  verdict: string | null;
  looked_up_at: string | null;
}

export interface InvestigationDetail {
  id: number;
  name: string;
  description: string;
  iocs: InvestigationIOCEntry[];
  created_at: string;
  updated_at: string;
}

export async function listInvestigations(): Promise<InvestigationSummary[]> {
  return request<InvestigationSummary[]>("/investigations");
}

export async function createInvestigation(name: string, description = ""): Promise<{ id: number; name: string }> {
  return request("/investigations", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, description }),
  });
}

export async function getInvestigation(id: number): Promise<InvestigationDetail> {
  return request<InvestigationDetail>(`/investigations/${id}`);
}

export async function updateInvestigation(id: number, data: { name?: string; description?: string }): Promise<void> {
  await request<void>(`/investigations/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
}

export async function deleteInvestigation(id: number): Promise<void> {
  await request<void>(`/investigations/${id}`, { method: "DELETE" });
}

export async function addIOCToInvestigation(invId: number, ioc: string): Promise<void> {
  await request<void>(`/investigations/${invId}/iocs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc }),
  });
}

export async function updateIOCNotes(invId: number, iiId: number, notes: string): Promise<void> {
  await request<void>(`/investigations/${invId}/iocs/${iiId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes }),
  });
}

export async function removeIOCFromInvestigation(invId: number, iiId: number): Promise<void> {
  await request<void>(`/investigations/${invId}/iocs/${iiId}`, { method: "DELETE" });
}

// --- Recent ---

export interface RecentIOC {
  id: number;
  value: string;
  ioc_type: string;
  verdict: string | null;
  score: number | null;
  confidence: string | null;
  created_at: string | null;
}

export async function getRecentIOCs(): Promise<RecentIOC[]> {
  return request<RecentIOC[]>("/recent");
}

export async function deleteRecentIOC(id: number): Promise<void> {
  await request<void>(`/recent/${id}`, { method: "DELETE" });
}

// --- Feedback ---

export type FeedbackValue = "false_positive" | "confirmed";

export interface FeedbackInfo {
  ioc_value: string;
  feedback: FeedbackValue;
  note: string | null;
  created_at: string | null;
}

export async function submitFeedback(ioc: string, feedback: FeedbackValue, note?: string): Promise<FeedbackInfo> {
  return request<FeedbackInfo>("/feedback", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc, feedback, note: note || null }),
  });
}

export async function getFeedback(ioc: string): Promise<FeedbackInfo | null> {
  try {
    return await request<FeedbackInfo>(`/feedback/${encodeURIComponent(ioc)}`);
  } catch (err) {
    if (err instanceof ApiError && err.status === 404) return null;
    throw err;
  }
}
