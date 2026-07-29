const API_BASE = "/api";

export interface StageInfo {
  name: string;
  status: string;
  message: string;
  progress: number;
}

export interface TaskResponse {
  task_id: string;
  status: string;
  progress: number;
  stages: StageInfo[];
  ioc_value: string;
  error?: string;
}

export interface NormalizedResult {
  ioc: string;
  ioc_type: string;
  source: string;
  verdict: string;
  raw_score: number | null;
  confidence: string;
  tags: string[];
  categories: string[];
  malware_family?: string;
  source_link?: string;
  reports_count?: number;
}

export interface GeoIPInfo {
  country?: string;
  city?: string;
  asn?: string;
  isp?: string;
  org?: string;
}

export interface WhoisInfo {
  registrar?: string;
  creation_date?: string;
  expiration_date?: string;
  org?: string;
}

export interface DNSInfo {
  a: string[];
  aaaa: string[];
  mx: string[];
  ns: string[];
}

export interface EnrichmentData {
  geoip?: GeoIPInfo;
  whois?: WhoisInfo;
  dns?: DNSInfo;
  reverse_dns?: { hostnames: string[] };
  ssl?: { subject?: string; issuer?: string };
  cve?: { is_in_kev: boolean; epss_score?: number; cvss_vector?: string };
  email_security?: { spf: string; dkim: string; dmarc: string };
  subdomains?: { subdomains: string[] };
  relationships?: any[];
}

export interface CompositeScore {
  score: number;
  verdict: string;
  confidence: string;
  sources_contributing: number;
}

export interface LookupResponse {
  input: string;
  normalized: string;
  ioc_type: string;
  composite: CompositeScore;
  enrichment: EnrichmentData;
  results: NormalizedResult[];
  relationships: any[];
  executive_summary: string;
}

export async function lookupIOC(value: string): Promise<TaskResponse> {
  const res = await fetch(`${API_BASE}/lookup`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ input: value }),
  });
  if (!res.ok) throw new Error(`Lookup failed: ${res.status}`);
  return res.json();
}

export async function getTaskStatus(taskId: string): Promise<TaskResponse> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}`);
  if (!res.ok) throw new Error(`Task fetch failed: ${res.status}`);
  return res.json();
}

export async function getTaskResult(taskId: string): Promise<LookupResponse> {
  const res = await fetch(`${API_BASE}/tasks/${taskId}/result`);
  if (res.status === 425) throw new Error("not_ready");
  if (!res.ok) throw new Error(`Result fetch failed: ${res.status}`);
  return res.json();
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

export interface BatchResult {
  batch_id: string;
  total: number;
  completed: number;
  summary: BatchResultSummary;
  results: any[];
  relationships: any[];
}

export async function startBatch(iocs: string[]): Promise<{ batch_id: string; total: number; status: string }> {
  const res = await fetch(`${API_BASE}/batch`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ iocs }),
  });
  if (!res.ok) throw new Error(`Batch start failed: ${res.status}`);
  return res.json();
}

export async function getBatchStatus(batchId: string): Promise<BatchStatus> {
  const res = await fetch(`${API_BASE}/batch/${batchId}`);
  if (!res.ok) throw new Error(`Batch status fetch failed: ${res.status}`);
  return res.json();
}

export async function getBatchResult(batchId: string): Promise<BatchResult> {
  const res = await fetch(`${API_BASE}/batch/${batchId}/result`);
  if (res.status === 425) throw new Error("not_ready");
  if (!res.ok) throw new Error(`Batch result fetch failed: ${res.status}`);
  return res.json();
}

export async function uploadBatchFile(file: File): Promise<{ batch_id: string; total: number; status: string }> {
  const form = new FormData();
  form.append("file", file);
  const res = await fetch(`${API_BASE}/batch/upload`, { method: "POST", body: form });
  if (!res.ok) throw new Error(`Batch upload failed: ${res.status}`);
  return res.json();
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
  const res = await fetch(`${API_BASE}/investigations`);
  if (!res.ok) throw new Error(`List investigations failed: ${res.status}`);
  return res.json();
}

export async function createInvestigation(name: string, description = ""): Promise<{ id: number; name: string }> {
  const res = await fetch(`${API_BASE}/investigations`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ name, description }),
  });
  if (!res.ok) throw new Error(`Create investigation failed: ${res.status}`);
  return res.json();
}

export async function getInvestigation(id: number): Promise<InvestigationDetail> {
  const res = await fetch(`${API_BASE}/investigations/${id}`);
  if (!res.ok) throw new Error(`Get investigation failed: ${res.status}`);
  return res.json();
}

export async function updateInvestigation(id: number, data: { name?: string; description?: string }): Promise<void> {
  const res = await fetch(`${API_BASE}/investigations/${id}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(data),
  });
  if (!res.ok) throw new Error(`Update investigation failed: ${res.status}`);
}

export async function deleteInvestigation(id: number): Promise<void> {
  const res = await fetch(`${API_BASE}/investigations/${id}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Delete investigation failed: ${res.status}`);
}

export async function addIOCToInvestigation(invId: number, ioc: string): Promise<void> {
  const res = await fetch(`${API_BASE}/investigations/${invId}/iocs`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ ioc }),
  });
  if (!res.ok) throw new Error(`Add IOC failed: ${res.status}`);
}

export async function updateIOCNotes(invId: number, iiId: number, notes: string): Promise<void> {
  const res = await fetch(`${API_BASE}/investigations/${invId}/iocs/${iiId}`, {
    method: "PUT",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ notes }),
  });
  if (!res.ok) throw new Error(`Update notes failed: ${res.status}`);
}

export async function removeIOCFromInvestigation(invId: number, iiId: number): Promise<void> {
  const res = await fetch(`${API_BASE}/investigations/${invId}/iocs/${iiId}`, { method: "DELETE" });
  if (!res.ok) throw new Error(`Remove IOC failed: ${res.status}`);
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
  const res = await fetch(`${API_BASE}/recent`);
  if (!res.ok) throw new Error(`Recent IOCs fetch failed: ${res.status}`);
  return res.json();
}

export async function deleteRecentIOC(id: number): Promise<void> {
  await fetch(`${API_BASE}/recent/${id}`, { method: "DELETE" });
}
