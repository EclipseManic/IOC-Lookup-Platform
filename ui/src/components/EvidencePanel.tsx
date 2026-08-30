import { useEffect, useMemo, useState } from "react";
import { getSourceInventory, type LookupResponse, type SourceInventoryItem } from "../services/api";

function StatusPill({ value }: { value: string }) {
  const normalized = value.toLowerCase();
  const style = normalized === "success" || normalized === "found"
    ? "text-verdict-clean border-verdict-clean/30 bg-verdict-clean/10"
    : normalized === "not_applicable"
      ? "text-cyan-300 border-cyan-500/30 bg-cyan-500/10"
    : normalized === "rate_limited" || normalized === "timeout" || normalized === "error" || normalized === "unavailable"
      ? "text-verdict-malicious border-verdict-malicious/30 bg-verdict-malicious/10"
      : "text-text-secondary border-border bg-bg-elevated";
  return <span className={`text-[10px] uppercase font-semibold px-1.5 py-0.5 rounded border ${style}`}>{value.replace(/_/g, " ")}</span>;
}

function sourceState(source: SourceInventoryItem): string {
  if (source.public_without_key) return "public";
  return source.configured ? "configured" : "not configured";
}

export default function EvidencePanel({ result }: { result: LookupResponse }) {
  const [sources, setSources] = useState<SourceInventoryItem[]>([]);
  useEffect(() => {
    getSourceInventory().then((inventory) => setSources(inventory.sources)).catch(() => setSources([]));
  }, []);

  const evidence = useMemo(() => {
    const state = (item: { execution_state?: string; status: string }) => item.execution_state || item.status;
    const found = result.results.filter((item) => ["success", "found"].includes(state(item)) && item.verdict !== "error");
    const notFound = result.results.filter((item) => state(item) === "not_found");
    const notApplicable = result.results.filter((item) => state(item) === "not_applicable");
    const unavailable = result.results.filter((item) => !["success", "found", "not_found", "not_applicable"].includes(state(item)));
    const sightings = found.reduce((total, item) => total + (item.reports_count ?? 0), 0);
    const related = result.relationships.length + result.results.reduce((total, item) => total + (item.related_iocs?.length ?? 0), 0);
    const artifacts = found.reduce((total, item) => total + (item.samples?.length ?? 0) + (item.dropped_files?.length ?? 0) + (item.network_iocs?.length ?? 0), 0);
    return { found, notFound, notApplicable, unavailable, sightings, related, artifacts };
  }, [result]);

  const applicable = sources.filter((source) => source.supported_types.includes(result.ioc_type));
  const missing = applicable.filter((source) => !source.public_without_key && !source.configured);
  const health = result.provider_health ?? result.final_assessment?.provider_health ?? [];
  const actionableResults = result.results.filter((item) => (item.execution_state || item.status) !== "not_applicable");
  const plannedNotApplicable = (result.final_assessment?.provider_plan ?? []).filter((item) => item.applicable === false).map((item) => String(item.provider ?? "Unknown provider"));
  const notApplicableSources = evidence.notApplicable.length > 0 ? evidence.notApplicable.map((item) => item.source) : plannedNotApplicable;

  return (
    <div className="space-y-4">
      <div className="bg-bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Evidence at a glance</h3>
        <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
          <div><div className="text-xl font-semibold">{evidence.found.length}</div><div className="text-xs text-text-secondary">successful sources</div></div>
          <div><div className="text-xl font-semibold">{evidence.notFound.length}</div><div className="text-xs text-text-secondary">not found (not clean)</div></div>
          <div><div className="text-xl font-semibold">{evidence.unavailable.length}</div><div className="text-xs text-text-secondary">unavailable</div></div>
          <div><div className="text-xl font-semibold">{notApplicableSources.length}</div><div className="text-xs text-text-secondary">not applicable</div></div>
          <div><div className="text-xl font-semibold">{evidence.sightings}</div><div className="text-xs text-text-secondary">reported sightings</div></div>
          <div><div className="text-xl font-semibold">{evidence.artifacts}</div><div className="text-xs text-text-secondary">linked artifacts</div></div>
        </div>
        <p className="text-xs text-text-secondary mt-3">A missing, rate-limited, or unavailable result is not proof of safety. Evidence is source-specific and time-sensitive.</p>
      </div>

      <div className="bg-bg-card border border-border rounded-lg overflow-hidden">
        <div className="p-4 border-b border-border"><h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">Source provenance</h3></div>
        {actionableResults.length === 0 ? (
          <p className="p-4 text-sm text-text-secondary">No applicable provider returned evidence for this IOC.</p>
        ) : actionableResults.map((item) => {
          const state = item.execution_state || item.status;
          return (
            <div key={item.source} className="p-4 border-b border-border last:border-0 grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_auto] gap-2">
              <div>
                <div className="flex items-center gap-2"><span className="font-medium text-sm">{item.source}</span><StatusPill value={state} /></div>
                <p className="text-xs text-text-secondary mt-1">Provider verdict: {item.provider_verdict ?? item.verdict} · normalized: {item.normalized_verdict ?? item.verdict} · confidence: {item.confidence}</p>
                <p className="text-[11px] text-text-secondary mt-1">
                  {item.cached ? `Cached${item.cache_age != null ? ` ${Math.round(item.cache_age / 60)}m old` : ""}` : "Fresh lookup"}
                  {item.latency_ms != null ? ` · ${Math.round(item.latency_ms)}ms` : ""}
                  {(item.retry_count ?? 0) > 0 ? ` · ${item.retry_count} retries` : ""}
                  {item.source_timestamp ? ` · source time: ${new Date(item.source_timestamp).toLocaleString()}` : ""}
                </p>
                <p className="text-[11px] text-text-secondary mt-1">Assessment domain: {item.assessment_domain ?? result.final_assessment?.assessment_domain ?? "ioc_reputation"}{item.provenance_family ? ` · provenance: ${item.provenance_family}` : ""}{item.evidence_items?.length ? ` · ${item.evidence_items.length} nested evidence item(s)` : ""}</p>
              </div>
              <div className="text-xs text-text-secondary md:text-right">{item.reports_count != null ? `${item.reports_count} reports` : "No report count"}</div>
            </div>
          );
        })}
        {notApplicableSources.length > 0 && <details className="border-t border-border"><summary className="cursor-pointer px-4 py-3 text-xs font-semibold uppercase tracking-wider text-cyan-300">Not applicable by capability ({notApplicableSources.length})</summary><div className="flex flex-wrap gap-1 border-t border-border p-3">{notApplicableSources.map((source) => <StatusPill key={source} value={source} />)}</div></details>}
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-2">Coverage for {result.ioc_type}</h3>
        {result.final_assessment && <p className="text-xs text-text-secondary mb-3">Evaluated coverage: <span className="text-text-primary">{Math.round(result.final_assessment.coverage * 100)}%</span> · cache status: <span className="text-text-primary">{result.final_assessment.cache_status}</span></p>}
        {applicable.length === 0 ? <p className="text-sm text-text-secondary">No reputation adapter is implemented for this IOC type; displayed data is contextual enrichment only.</p> : <div className="flex flex-wrap gap-2">{applicable.map((source) => <StatusPill key={source.name} value={`${source.name}: ${sourceState(source)}`} />)}</div>}
        {missing.length > 0 && <p className="text-xs text-amber-400 mt-3">Not queried because credentials are absent: {missing.map((source) => source.name).join(", ")}.</p>}
        {notApplicableSources.length > 0 && <p className="text-xs text-cyan-300 mt-3">Not applicable by provider capability: {notApplicableSources.join(", ")}.</p>}
        {evidence.unavailable.length > 0 && <p className="text-xs text-verdict-malicious mt-2">Unavailable during this lookup: {evidence.unavailable.map((item) => `${item.source} (${item.execution_state || item.status})`).join(", ")}.</p>}
      </div>

      {health.length > 0 && <div className="bg-bg-card border border-border rounded-lg p-4"><h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-2">Provider health</h3><div className="space-y-1">{health.map((item) => <div key={item.source} className="flex flex-wrap items-center justify-between gap-2 text-xs"><span>{item.source}</span><span className="text-text-secondary">{item.request_count} network attempts · {item.success_count} observations · {item.failure_count} failures{item.rate_limit_count ? ` · ${item.rate_limit_count} rate-limited` : ""}{item.cache_hit_count ? ` · ${item.cache_hit_count} cache hits` : ""}</span></div>)}</div></div>}
    </div>
  );
}
