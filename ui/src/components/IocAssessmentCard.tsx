import { useEffect, useMemo, useState } from "react";
import type {
  CVEInfo,
  EvidenceObservation,
  IOCAssessment,
  NormalizedResult,
  ProviderHealth,
} from "../services/api";
import Tag from "./Tag";
import VerdictBadge from "./VerdictBadge";

type Tone = "malicious" | "suspicious" | "clean" | "unknown" | "health";

const LABELS: Record<string, string> = {
  malicious: "Malicious",
  malicious_test_artifact: "Security Test Artifact",
  suspicious: "Suspicious",
  benign: "Benign",
  clean: "Clean",
  unknown: "Unknown",
  not_found: "Not Found",
  undetected: "Undetected",
  harmless: "Harmless",
  whitelisted: "Whitelisted",
  rate_limited: "Rate Limited",
  unavailable: "Unavailable",
  timeout: "Timeout",
  error: "Error",
  invalid_request: "Invalid Request",
  not_applicable: "Not Applicable",
  aborted_due_to_ioc_deadline: "IOC Deadline",
  batch_deadline_exceeded: "Batch Deadline",
  context_only: "Context Only",
  technique_metadata: "Technique Metadata",
  technique_metadata_unavailable: "Technique Metadata Unavailable",
  critical: "Critical",
  high: "High",
  medium: "Medium",
  low: "Low",
  informational: "Informational",
};

function label(value: string | null | undefined): string {
  if (!value) return "—";
  return LABELS[value] ?? value.replace(/_/g, " ").replace(/\b\w/g, (char) => char.toUpperCase());
}

function toneForVerdict(verdict: string): Tone {
  if (verdict === "malicious_test_artifact") return "unknown";
  if (verdict.includes("malicious")) return "malicious";
  if (verdict === "suspicious") return "suspicious";
  if (verdict === "benign" || verdict === "clean") return "clean";
  return "unknown";
}

function toneClass(tone: Tone): string {
  return tone === "malicious"
    ? "text-red-300 border-red-500/40 bg-red-500/10"
    : tone === "suspicious"
      ? "text-amber-300 border-amber-500/40 bg-amber-500/10"
      : tone === "clean"
        ? "text-green-300 border-green-500/40 bg-green-500/10"
        : tone === "health"
          ? "text-rose-300 border-rose-500/40 bg-rose-500/10"
          : "text-gray-300 border-gray-500/40 bg-gray-500/10";
}

function stateClass(state: string): string {
  if (state === "success" || state === "not_found") return toneClass(state === "success" ? "clean" : "unknown");
  if (state === "not_applicable") return "text-cyan-300 border-cyan-500/40 bg-cyan-500/10";
  return toneClass("health");
}

function lookupStatus(assessment: IOCAssessment): { value: string; detail: string; tone: Tone } {
  if (assessment.assessment_status === "not_applicable") {
    return { value: "NOT APPLICABLE", detail: "No provider is applicable to this IOC domain", tone: "unknown" };
  }
  if (assessment.assessment_status === "unavailable") {
    return { value: "UNAVAILABLE", detail: "No usable provider result was available", tone: "health" };
  }
  if (assessment.assessment_status === "batch_deadline_exceeded") {
    return { value: "BATCH DEADLINE", detail: "IOC was not started before the batch deadline", tone: "health" };
  }
  if (assessment.assessment_status === "aborted_due_to_ioc_deadline") {
    return { value: "IOC DEADLINE", detail: "Some provider work was aborted at the IOC deadline", tone: "health" };
  }
  const limited = assessment.rate_limited_sources.length;
  const healthFailureSources = new Set([
    ...assessment.unavailable_sources,
    ...assessment.error_sources.filter((source) => !assessment.rate_limited_sources.includes(source)),
  ]);
  const healthFailures = healthFailureSources.size;
  const expected = Number(assessment.evidence_summary.expected_providers ?? 0);
  const evaluated = Number(assessment.evidence_summary.evaluated_providers ?? 0);

  if (assessment.final_verdict === "unknown" && limited > 0 && evaluated === 0) {
    return { value: "RATE LIMITED", detail: `${limited} provider${limited === 1 ? "" : "s"} could not be queried`, tone: "health" };
  }
  if (limited > 0 || healthFailures > 0 || (expected > 0 && evaluated < expected)) {
    const details = [
      limited ? `${limited} rate limited` : "",
      healthFailures ? `${healthFailures} provider issue${healthFailures === 1 ? "" : "s"}` : "",
    ].filter(Boolean).join(" · ");
    return { value: "PARTIAL", detail: details || "Some providers were not evaluated", tone: "suspicious" };
  }
  return { value: "COMPLETE", detail: `${evaluated || expected || assessment.provider_breakdown.length} providers evaluated`, tone: "clean" };
}

function confidencePercent(value: string): number {
  return value === "high" ? 100 : value === "medium" ? 65 : 30;
}

function formatAge(seconds: number | null | undefined): string {
  if (seconds == null || !Number.isFinite(seconds)) return "age unavailable";
  if (seconds < 60) return `${Math.max(0, Math.round(seconds))}s old`;
  if (seconds < 3600) return `${Math.round(seconds / 60)}m old`;
  if (seconds < 86400) return `${Math.round(seconds / 3600)}h old`;
  return `${Math.round(seconds / 86400)}d old`;
}

function formatValue(value: unknown): string {
  if (Array.isArray(value)) return value.slice(0, 8).map((item) => formatValue(item)).join(", ");
  if (value && typeof value === "object") return JSON.stringify(value);
  return String(value);
}

function copyValue(value: string): void {
  void navigator.clipboard?.writeText(value);
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false);
  return (
    <button
      type="button"
      onClick={() => {
        copyValue(value);
        setCopied(true);
        window.setTimeout(() => setCopied(false), 1200);
      }}
      className="shrink-0 text-[11px] text-text-secondary hover:text-accent"
      aria-label="Copy IOC value"
      title="Copy full value"
    >
      {copied ? "Copied" : "Copy"}
    </button>
  );
}

function Metric({ label: metricLabel, value, detail, percent, tone = "unknown" }: {
  label: string;
  value: string;
  detail?: string;
  percent?: number;
  tone?: Tone;
}) {
  return (
    <div className="min-w-0 rounded-md border border-border bg-bg-elevated/60 p-2.5">
      <div className="text-[10px] uppercase tracking-wider text-text-secondary">{metricLabel}</div>
      <div className="mt-0.5 flex items-baseline justify-between gap-2">
        <span className="text-sm font-semibold text-text-primary">{value}</span>
        {detail && <span className="truncate text-[10px] text-text-secondary">{detail}</span>}
      </div>
      {percent != null && (
        <div className="mt-1.5 h-1.5 overflow-hidden rounded-full bg-bg-card" aria-label={`${metricLabel} ${percent}%`}>
          <div className={`h-full rounded-full ${tone === "malicious" ? "bg-red-400" : tone === "suspicious" ? "bg-amber-400" : tone === "clean" ? "bg-green-400" : "bg-gray-400"}`} style={{ width: `${Math.max(0, Math.min(100, percent))}%` }} />
        </div>
      )}
    </div>
  );
}

function providerMetadata(result: NormalizedResult | undefined, observation: EvidenceObservation | undefined): [string, string][] {
  if (!result && !observation) return [];
  const raw = result?.raw_data ?? {};
  const entries: [string, string][] = [];
  const add = (key: string, value: unknown) => {
    if (value !== null && value !== undefined && value !== "" && entries.length < 6) entries.push([key, formatValue(value)]);
  };

  if (result?.detection_count != null && result.total_engines != null) {
    add("Detection ratio", `${result.detection_count}/${result.total_engines}`);
  } else if (raw.detection_ratio !== undefined) {
    add("Detection ratio", raw.detection_ratio);
  }
  if (result?.reports_count != null) add("Reports", result.reports_count);
  for (const key of [
    "abuse_confidence_score", "abuse_confidence", "threat_type", "classification",
    "asn", "as_name", "asn_name", "country", "city", "org", "isp", "ports",
    "services", "cvss", "cvss_score", "epss", "epss_score", "cwe", "match_count",
  ]) add(key.replace(/_/g, " "), raw[key]);
  if (result?.malware_family) add("Malware family", result.malware_family);
  if (result?.raw_score != null) add("Provider score", result.raw_score.toFixed(3));
  if (entries.length === 0 && observation?.metadata) {
    for (const [key, value] of Object.entries(observation.metadata)) {
      if (!["source_link", "http_status", "retry_count", "retry_after_seconds"].includes(key)) add(key.replace(/_/g, " "), value);
    }
  }
  return entries;
}

function cacheLabel(result: NormalizedResult | undefined, observation: EvidenceObservation | undefined): string {
  const cached = result?.cached ?? observation?.cached;
  const age = result?.cache_age ?? observation?.cache_age;
  const state = result?.execution_state ?? observation?.execution_state;
  if (state && !["success", "not_found"].includes(state)) return "Unavailable";
  if (result?.stale || observation?.stale || result?.cache_status === "stale" || observation?.cache_status === "stale") return `Stale · ${formatAge(age)}`;
  if (cached && age != null && age > 86400) return `Historical · ${formatAge(age)}`;
  if (cached) return `Cached · ${formatAge(age)}`;
  return "Fresh";
}

function evidenceLabel(observation: EvidenceObservation | undefined, result: NormalizedResult | undefined): string {
  if (!observation) return result?.execution_state === "not_found" ? "No record / not in feed" : "Provider result";
  if (observation.execution_state === "not_found") return "No record / not in feed";
  if (observation.execution_state === "not_applicable") return "Provider is not applicable to this IOC type";
  if (!["success"].includes(observation.execution_state)) return "Provider health state";
  if (observation.evidence_class === "direct") return "Direct threat evidence";
  if (observation.evidence_class === "supporting") return "Supporting threat evidence";
  if (observation.evidence_class === "negative") return "Negative evidence (limited)";
  return "Context / enrichment";
}

function CveRecordPanel({ cve, results }: { cve?: CVEInfo; results: NormalizedResult[] }) {
  const raw = results.find((result) => result.raw_data?.cvss || result.raw_data?.cwes)?.raw_data ?? {};
  const cvss = raw.cvss && typeof raw.cvss === "object" ? raw.cvss as Record<string, unknown> : {};
  const score = cve?.cvss_score ?? (typeof cvss.baseScore === "number" ? cvss.baseScore : undefined);
  const severity = cve?.cvss_severity || (typeof cvss.baseSeverity === "string" ? cvss.baseSeverity : "");
  const cwes = cve?.cwe?.length ? cve.cwe : Array.isArray(raw.cwes) ? raw.cwes.map(String) : [];
  const affected = cve?.affected_products?.length ? cve.affected_products : Array.isArray(raw.affected) ? raw.affected.map(String) : [];
  const references = cve?.references?.length ? cve.references : Array.isArray(raw.references) ? raw.references.map(String) : [];
  const kev = cve?.is_in_kev || results.some((result) => result.tags.some((tag) => tag.toLowerCase().includes("kev")));
  const hasRecord = Boolean(cve || score != null || cwes.length || affected.length || references.length);
  if (!hasRecord) return null;

  return (
    <section className="border-y border-amber-500/30 bg-amber-500/5 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2"><div><div className="text-[10px] font-semibold uppercase tracking-wider text-amber-300">Vulnerability record</div><div className="mt-0.5 text-sm font-semibold text-text-primary">{severity ? `${severity} Vulnerability` : "CVE security record"}</div></div>{kev && <span className="rounded-full border border-red-500/40 bg-red-500/10 px-2 py-0.5 text-[10px] font-semibold uppercase text-red-300">CISA KEV / exploitation signal</span>}</div>
      <div className="mt-3 grid grid-cols-2 gap-2 text-xs sm:grid-cols-4"><div><div className="text-[10px] uppercase text-text-secondary">CVSS</div><div className="mt-0.5 font-mono text-base text-text-primary">{score != null ? score.toFixed(1) : "—"}</div></div><div><div className="text-[10px] uppercase text-text-secondary">EPSS</div><div className="mt-0.5 font-mono text-text-primary">{cve?.epss_score != null ? `${(cve.epss_score * 100).toFixed(1)}%` : "—"}</div></div><div><div className="text-[10px] uppercase text-text-secondary">CWE</div><div className="mt-0.5 text-text-primary">{cwes.length ? cwes.slice(0, 3).join(", ") : "—"}</div></div><div><div className="text-[10px] uppercase text-text-secondary">Exploit status</div><div className="mt-0.5 text-text-primary">{kev || cve?.public_exploits_exist || cve?.poc_available ? "Reported" : "No signal found"}</div></div></div>
      {(affected.length > 0 || references.length > 0 || cve?.cvss_vector) && <div className="mt-3 space-y-1 text-xs text-text-secondary">{affected.length > 0 && <div><span className="text-text-primary">Affected products: </span>{affected.slice(0, 5).join(", ")}{affected.length > 5 ? ` +${affected.length - 5} more` : ""}</div>}{cve?.cvss_vector && <div><span className="text-text-primary">Vector: </span><span className="break-all font-mono">{cve.cvss_vector}</span></div>}{references.length > 0 && <div><span className="text-text-primary">References: </span>{references.length}</div>}</div>}
    </section>
  );
}

function ProviderEvidence({ result, observation }: { result?: NormalizedResult; observation?: EvidenceObservation }) {
  const source = result?.source ?? observation?.source ?? "Unknown provider";
  const state = observation?.execution_state ?? result?.execution_state ?? result?.status ?? "unknown";
  const providerVerdict = observation?.provider_verdict ?? result?.provider_verdict ?? result?.verdict;
  const normalizedVerdict = observation?.normalized_verdict ?? result?.normalized_verdict ?? result?.verdict;
  const nestedEvidence = observation?.evidence_items ?? result?.evidence_items ?? [];
  const metadata = providerMetadata(result, observation);
  const errorDetails = [
    state !== "success" && state !== "not_found" ? observation?.reason || result?.tags?.join(", ") : "",
    result?.http_status ? `HTTP ${result.http_status}` : "",
    result?.retry_after_seconds != null ? `retry after ${Math.round(result.retry_after_seconds)}s` : "",
  ].filter(Boolean);

  return (
    <article className="rounded-lg border border-border bg-bg-card/70 p-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div className="flex min-w-0 items-center gap-2">
          <span className="truncate text-sm font-semibold">{source}</span>
          <span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${stateClass(state)}`}>{label(state)}</span>
        </div>
        <span className="text-[11px] text-text-secondary">{evidenceLabel(observation, result)}</span>
      </div>

      <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        <div className="rounded border border-border/70 bg-bg-elevated/40 p-2">
          <div className="text-[10px] uppercase tracking-wider text-text-secondary">Execution Status</div>
          <div className="mt-1 text-xs text-text-primary">{label(state)}</div>
        </div>
        <div className="rounded border border-border/70 bg-bg-elevated/40 p-2">
          <div className="text-[10px] uppercase tracking-wider text-text-secondary">Assessment</div>
          <div className="mt-1 text-xs text-text-primary">Provider: {label(providerVerdict)} · normalized: {label(normalizedVerdict)}</div>
        </div>
        <div className="rounded border border-border/70 bg-bg-elevated/40 p-2">
          <div className="text-[10px] uppercase tracking-wider text-text-secondary">Evidence</div>
          <div className="mt-1 text-xs text-text-primary">{evidenceLabel(observation, result)}{observation?.contribution && observation.contribution !== "neutral" ? ` · ${observation.contribution}` : ""}</div>
        </div>
        <div className="rounded border border-border/70 bg-bg-elevated/40 p-2">
          <div className="text-[10px] uppercase tracking-wider text-text-secondary">Key Metadata</div>
          {metadata.length > 0 ? <div className="mt-1 space-y-0.5 text-xs text-text-primary">{metadata.map(([key, value]) => <div key={key} className="break-words"><span className="text-text-secondary">{key}: </span>{value}</div>)}</div> : <div className="mt-1 text-xs text-text-secondary">No provider-specific fields</div>}
        </div>
        <div className="rounded border border-border/70 bg-bg-elevated/40 p-2">
          <div className="text-[10px] uppercase tracking-wider text-text-secondary">Timestamp</div>
          <div className="mt-1 text-xs text-text-primary">{result?.source_timestamp || observation?.source_timestamp ? `Source ${new Date(result?.source_timestamp ?? observation?.source_timestamp ?? "").toLocaleString()}` : "Source time unavailable"}</div>
          <div className="mt-0.5 text-[10px] text-text-secondary">{result?.observed_at || observation?.observed_at ? `retrieved ${new Date(result?.observed_at ?? observation?.observed_at ?? "").toLocaleString()}` : "retrieval time unavailable"}</div>
        </div>
        <div className="rounded border border-border/70 bg-bg-elevated/40 p-2">
          <div className="text-[10px] uppercase tracking-wider text-text-secondary">Freshness / Cache</div>
          <div className="mt-1 text-xs text-text-primary">{cacheLabel(result, observation)}</div>
          <div className="mt-0.5 text-[10px] text-text-secondary">{result?.latency_ms != null ? `${Math.round(result.latency_ms)}ms` : "latency unavailable"}{(result?.retry_count ?? observation?.metadata?.retry_count ?? 0) ? ` · ${result?.retry_count ?? observation?.metadata?.retry_count} retries` : ""}</div>
        </div>
      </div>

      {(result?.provider_summary || observation?.reason) && <p className="mt-3 rounded border border-accent/20 bg-accent/5 px-2.5 py-2 text-xs text-text-primary"><span className="font-semibold text-accent">Provider finding: </span>{result?.provider_summary || observation?.reason}</p>}
      {errorDetails.length > 0 && <div className="mt-2 rounded border border-rose-500/25 bg-rose-500/5 p-2 text-xs text-rose-200"><span className="font-semibold">Error / Limit: </span>{errorDetails.join(" · ")}</div>}
      {result?.tags && result.tags.length > 0 && <div className="mt-2 flex flex-wrap gap-1">{result.tags.slice(0, 12).map((tag) => <Tag key={tag} label={tag} />)}</div>}
      {nestedEvidence.length > 0 && <details className="mt-2 rounded border border-violet-500/25 bg-violet-500/5 p-2 text-xs"><summary className="cursor-pointer font-semibold text-violet-300">Nested vendor evidence ({nestedEvidence.length})</summary><div className="mt-2 space-y-1.5">{nestedEvidence.map((item, index) => { const details = item.details && typeof item.details === "object" ? item.details : undefined; return <div key={String(item.evidence_id ?? item.evidence_hash ?? index)} className="rounded border border-border/70 bg-bg-elevated/50 p-2"><div className="flex flex-wrap items-center justify-between gap-2"><span className="font-semibold text-text-primary">{String(item.source ?? item.provider ?? "Nested source")}</span><span className="text-[10px] uppercase text-text-secondary">{String(item.evidence_class ?? "metadata")} · {String(item.confidence ?? "low")}</span></div><p className="mt-0.5 text-text-secondary">{String(item.reason ?? "Nested provider evidence preserved for audit.")}</p>{details && <details className="mt-1"><summary className="cursor-pointer text-accent">Details</summary><pre className="mt-1 max-h-32 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-1.5 text-[10px] text-text-secondary">{JSON.stringify(details, null, 2)}</pre></details>}</div>; })}</div></details>}
      {result?.raw_data && Object.keys(result.raw_data).length > 0 && (
        <details className="mt-2 text-xs">
          <summary className="cursor-pointer text-accent">Raw technical data</summary>
          <pre className="mt-2 max-h-56 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-2 text-[11px] text-text-secondary">{JSON.stringify(result.raw_data, null, 2)}</pre>
        </details>
      )}
    </article>
  );
}

function EvidenceCategory({ title, description, observations, results, tone, open = false }: {
  title: string;
  description: string;
  observations: EvidenceObservation[];
  results: NormalizedResult[];
  tone: Tone;
  open?: boolean;
}) {
  const resultBySource = useMemo(() => new Map(results.map((result) => [result.source, result])), [results]);
  return (
    <details className="rounded-lg border border-border bg-bg-secondary/40" open={open}>
      <summary className="flex list-none items-center justify-between gap-3 px-3 py-2.5">
        <span className="flex min-w-0 items-center gap-2"><span className={`h-2 w-2 shrink-0 rounded-full ${tone === "malicious" ? "bg-red-400" : tone === "suspicious" ? "bg-amber-400" : tone === "clean" ? "bg-green-400" : "bg-gray-400"}`} /><span className="text-sm font-semibold">{title}</span><span className="text-xs text-text-secondary">{observations.length}</span></span>
        <span className="text-[11px] text-text-secondary">{description}</span>
      </summary>
      <div className="space-y-2 border-t border-border p-3">
        {observations.length === 0 ? <p className="text-xs text-text-secondary">None recorded.</p> : observations.map((observation) => <ProviderEvidence key={observation.source} observation={observation} result={resultBySource.get(observation.source)} />)}
      </div>
    </details>
  );
}

function HealthRow({ item }: { item: ProviderHealth }) {
  return <div className="flex flex-wrap items-center justify-between gap-2 rounded border border-border/70 bg-bg-elevated/40 px-2.5 py-2 text-xs"><span className="font-medium">{item.source}</span><span className="text-text-secondary">{item.request_count} network attempts · {item.success_count} observations · {item.cache_hit_count} cache hits · {item.rate_limit_count} rate-limited · {item.timeout_count} timeouts · {item.failure_count} failures</span></div>;
}

export default function IocAssessmentCard({
  assessment,
  results,
  cve,
  forceExpanded,
  onOpen,
}: {
  assessment: IOCAssessment;
  results: NormalizedResult[];
  cve?: CVEInfo;
  forceExpanded?: boolean;
  onOpen?: () => void;
}) {
  const [expanded, setExpanded] = useState(false);
  useEffect(() => {
    if (forceExpanded !== undefined) setExpanded(forceExpanded);
  }, [forceExpanded]);

  const status = lookupStatus(assessment);
  const verdictTone = toneForVerdict(assessment.final_verdict);
  const observations = assessment.provider_breakdown;
  const conflicts = assessment.conflicting_evidence.length > 0
    ? assessment.conflicting_evidence
    : observations.filter((item) => item.evidence_class === "conflicting");
  const conflictSources = new Set(conflicts.map((item) => item.source));
  const threat = observations.filter((item) => item.contribution === "positive" && !conflictSources.has(item.source));
  const negative = observations.filter((item) => item.contribution === "negative" && !conflictSources.has(item.source));
  const context = observations.filter((item) => item.role === "context" || item.evidence_class === "contextual").filter((item) => !conflictSources.has(item.source));
  const notApplicable = observations.filter((item) => item.execution_state === "not_applicable");
  const plannedNotApplicable = (assessment.provider_plan ?? []).filter((item) => item.applicable === false);
  const health = observations.filter((item) => !["success", "not_found", "not_applicable"].includes(item.execution_state));
  const notFound = observations.filter((item) => item.execution_state === "not_found");
  const expected = Number(assessment.evidence_summary.expected_providers ?? observations.length);
  const evaluated = Number(assessment.evidence_summary.evaluated_providers ?? observations.filter((item) => ["success", "not_found"].includes(item.execution_state)).length);
  const categories = [threat.length, negative.length, conflicts.length, context.length, health.length, notFound.length, notApplicable.length, plannedNotApplicable.length].reduce((sum, value) => sum + value, 0);
  const domain = assessment.assessment_domain ?? (assessment.ioc_type === "cve" ? "vulnerability" : "ioc_reputation");
  const isVulnerability = domain === "vulnerability";
  const isNonReputation = domain !== "ioc_reputation";
  const displayIoc = assessment.normalized_ioc || assessment.ioc;
  const counts = assessment.evidence_counts ?? {};

  return (
    <article className="overflow-hidden rounded-xl border border-border bg-bg-card shadow-[0_10px_30px_rgba(0,0,0,0.18)]">
      <div role="button" tabIndex={0} onClick={() => setExpanded((value) => !value)} onKeyDown={(event) => { if (event.key === "Enter" || event.key === " ") { event.preventDefault(); setExpanded((value) => !value); } }} aria-expanded={expanded} className="w-full cursor-pointer p-4 text-left hover:bg-bg-elevated/30">
        <div className="flex flex-wrap items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="mb-1 flex flex-wrap items-center gap-2 text-[10px] uppercase tracking-wider text-text-secondary"><span>{label(assessment.ioc_type)}</span><span>·</span><span>{status.value}</span></div>
            <div className="mt-1 text-[10px] uppercase tracking-wider text-text-secondary">Assessment domain: {label(domain)}</div>
            <div className="flex min-w-0 items-center gap-2"><span className="truncate font-mono text-sm sm:text-base" title={displayIoc}>{displayIoc}</span><CopyButton value={displayIoc} /></div>
          </div>
          <div className="flex shrink-0 items-center gap-2"><VerdictBadge verdict={assessment.final_verdict} size="md" /><span className={`rounded-full border px-2 py-0.5 text-[10px] font-semibold uppercase ${toneClass(status.tone)}`}>{status.value}</span><span className="text-text-secondary">{expanded ? "Collapse" : "Expand"}</span></div>
        </div>
        <div className="mt-3 grid grid-cols-2 gap-2 md:grid-cols-4">
          <Metric label={isVulnerability ? "Vulnerability risk" : isNonReputation ? "Reputation" : "Risk score"} value={isNonReputation && !isVulnerability ? "Not applicable" : `${assessment.normalized_score.toFixed(0)}/100`} percent={isNonReputation && !isVulnerability ? undefined : assessment.normalized_score} tone={verdictTone} />
          <Metric label="Confidence" value={`${label(assessment.confidence)}${assessment.confidence_score != null ? ` · ${Math.round(assessment.confidence_score * 100)}%` : ""}`} percent={assessment.confidence_score != null ? assessment.confidence_score * 100 : confidencePercent(assessment.confidence)} tone={verdictTone} />
          <Metric label="Evidence quality" value={`${Math.round(assessment.evidence_strength * 100)}%`} percent={assessment.evidence_strength * 100} tone={assessment.evidence_strength >= 0.7 ? "clean" : "unknown"} />
          <Metric label="Provider coverage" value={expected || observations.length ? `${Math.round(assessment.coverage * 100)}%` : "Not applicable"} detail={expected || observations.length ? `${evaluated}/${expected || observations.length}` : undefined} percent={expected || observations.length ? assessment.coverage * 100 : undefined} tone={assessment.coverage >= 0.8 ? "clean" : "suspicious"} />
        </div>
        <div className="mt-2 flex flex-wrap items-center gap-x-3 gap-y-1 text-[11px] text-text-secondary"><span>{status.detail}</span>{assessment.needs_review && <span className="font-semibold text-amber-300">Needs analyst review</span>}{assessment.freshness && <span>Freshness: {label(assessment.freshness)}</span>}{assessment.cache_status && <span>Evidence: {label(assessment.cache_status)}</span>}</div>
        {onOpen && <button type="button" onClick={(event) => { event.stopPropagation(); onOpen(); }} className="mt-3 rounded-md border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent transition-colors hover:bg-accent/20">Open full IOC analysis</button>}
      </div>

      {isVulnerability && <CveRecordPanel cve={cve} results={results} />}

      {expanded && (
        <div className="space-y-3 border-t border-border p-4">
          <section className={`rounded-lg border p-3 ${toneClass(verdictTone)}`}>
            <div className="text-[10px] font-semibold uppercase tracking-wider opacity-80">Why this verdict?</div>
            <p className="mt-1 text-sm leading-relaxed text-text-primary">{assessment.reason}</p>
            <div className="mt-2 flex flex-wrap gap-2 text-[11px]"><span>{counts.direct_positive ?? threat.length} threat</span><span>{counts.negative ?? negative.length} negative</span><span>{counts.conflicting ?? conflicts.length} conflicting</span><span>{counts.contextual ?? context.length} context</span><span>{counts.non_observation ?? notFound.length} not found</span><span>{health.length} health issue{health.length === 1 ? "" : "s"}</span></div>
            {assessment.review_reasons && assessment.review_reasons.length > 0 && <ul className="mt-2 list-disc space-y-0.5 pl-4 text-xs text-amber-200">{assessment.review_reasons.map((reason) => <li key={reason}>{reason}</li>)}</ul>}
          </section>

          <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
            <EvidenceCategory title="Threat Evidence" description="direct and supporting intelligence" observations={threat} results={results} tone="malicious" open={threat.length > 0} />
            <EvidenceCategory title="Negative Evidence" description="explicit benign signals only" observations={negative} results={results} tone="clean" />
            <EvidenceCategory title="Conflicting Evidence" description="signals that need analyst context" observations={conflicts} results={results} tone="suspicious" open={conflicts.length > 0} />
            <EvidenceCategory title="Context / Enrichment" description="infrastructure, ownership, services" observations={context} results={results} tone="unknown" />
            <EvidenceCategory title="Provider Health" description="excluded from verdict scoring" observations={health} results={results} tone="health" />
            {notApplicable.length > 0 && <EvidenceCategory title="Not Applicable" description="planned provider coverage, excluded from scoring" observations={notApplicable} results={results} tone="unknown" />}
            <EvidenceCategory title="No Record / Not in Feed" description="not proof of benignness" observations={notFound} results={results} tone="unknown" />
            {plannedNotApplicable.length > 0 && <details className="rounded-lg border border-cyan-500/25 bg-cyan-500/5"><summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-3 py-2.5"><span className="text-sm font-semibold text-cyan-200">Not applicable capability plan <span className="ml-1 text-xs text-cyan-300">{plannedNotApplicable.length}</span></span><span className="text-[11px] text-text-secondary">excluded from scoring</span></summary><div className="space-y-1 border-t border-cyan-500/20 p-3">{plannedNotApplicable.map((item, index) => <div key={`${String(item.provider ?? "provider")}-${index}`} className="rounded border border-border/70 bg-bg-elevated/40 px-2.5 py-2 text-xs"><div className="font-medium text-text-primary">{String(item.provider ?? "Unknown provider")}</div><div className="mt-0.5 text-text-secondary">{String(item.reason ?? "Provider does not support this IOC domain")}</div></div>)}</div></details>}
            {isVulnerability && <EvidenceCategory title="Vulnerability Intelligence" description="typed CVSS, EPSS, CWE and lifecycle data" observations={observations.filter((item) => item.evidence_class === "vulnerability")} results={results} tone="suspicious" open />}
            {domain === "attack_technique" && <section className="rounded-lg border border-violet-500/30 bg-violet-500/5 p-3 text-sm"><div className="text-[10px] font-semibold uppercase tracking-wider text-violet-300">ATT&amp;CK technique metadata</div><pre className="mt-2 whitespace-pre-wrap text-xs text-text-secondary">{JSON.stringify(assessment.techniques ?? [], null, 2)}</pre></section>}
          </div>

          {assessment.provider_health.length > 0 && <section className="rounded-lg border border-border bg-bg-secondary/40 p-3"><div className="mb-2 text-xs font-semibold uppercase tracking-wider text-text-secondary">Provider health telemetry</div><div className="space-y-1.5">{assessment.provider_health.map((item) => <HealthRow key={item.source} item={item} />)}</div></section>}
          {categories === 0 && <p className="text-xs text-text-secondary">No provider evidence was returned. This IOC remains unknown until coverage improves.</p>}
        </div>
      )}
    </article>
  );
}
