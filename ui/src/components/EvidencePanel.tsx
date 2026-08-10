import { useEffect, useMemo, useState } from "react";
import { getSourceInventory, type LookupResponse, type SourceInventoryItem } from "../services/api";

function StatusPill({ value }: { value: string }) {
  const style = value === "found" || value === "ok"
    ? "text-verdict-clean border-verdict-clean/30 bg-verdict-clean/10"
    : value === "error" || value === "unavailable"
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
    const found = result.results.filter((item) => item.status === "found" && item.verdict !== "error");
    const unavailable = result.results.filter((item) => item.status === "error" || item.verdict === "error");
    const sightings = found.reduce((total, item) => total + (item.reports_count ?? 0), 0);
    const related = result.relationships.length + result.results.reduce((total, item) => total + (item.related_iocs?.length ?? 0), 0);
    const artifacts = found.reduce((total, item) => total + (item.samples?.length ?? 0) + (item.dropped_files?.length ?? 0) + (item.network_iocs?.length ?? 0), 0);
    return { found, unavailable, sightings, related, artifacts };
  }, [result]);

  const applicable = sources.filter((source) => source.supported_types.includes(result.ioc_type));
  const missing = applicable.filter((source) => !source.public_without_key && !source.configured);

  return (
    <div className="space-y-4">
      <div className="bg-bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-3">Evidence at a glance</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
          <div><div className="text-xl font-semibold">{evidence.found.length}</div><div className="text-xs text-text-secondary">sources with evidence</div></div>
          <div><div className="text-xl font-semibold">{evidence.sightings}</div><div className="text-xs text-text-secondary">reported sightings</div></div>
          <div><div className="text-xl font-semibold">{evidence.related}</div><div className="text-xs text-text-secondary">IOC relationships</div></div>
          <div><div className="text-xl font-semibold">{evidence.artifacts}</div><div className="text-xs text-text-secondary">linked artifacts</div></div>
        </div>
        <p className="text-xs text-text-secondary mt-3">
          A missing result is not proof of safety. Evidence is source-specific and time-sensitive; review source timestamps and collection status before acting.
        </p>
      </div>

      <div className="bg-bg-card border border-border rounded-lg overflow-hidden">
        <div className="p-4 border-b border-border">
          <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">Source provenance</h3>
        </div>
        {result.results.length === 0 ? (
          <p className="p-4 text-sm text-text-secondary">No reputation source returned evidence for this IOC.</p>
        ) : result.results.map((item) => (
          <div key={item.source} className="p-4 border-b border-border last:border-0 grid grid-cols-1 md:grid-cols-[minmax(0,1fr)_auto] gap-2">
            <div>
              <div className="flex items-center gap-2"><span className="font-medium text-sm">{item.source}</span><StatusPill value={item.status} /></div>
              <p className="text-xs text-text-secondary mt-1">
                Verdict: {item.verdict} · confidence: {item.confidence}
                {item.first_seen ? ` · first seen: ${new Date(item.first_seen).toLocaleString()}` : ""}
                {item.last_seen ? ` · last seen: ${new Date(item.last_seen).toLocaleString()}` : ""}
              </p>
            </div>
            <div className="text-xs text-text-secondary md:text-right">
              {item.reports_count !== undefined && item.reports_count !== null ? `${item.reports_count} reports` : "No report count"}
            </div>
          </div>
        ))}
      </div>

      <div className="bg-bg-card border border-border rounded-lg p-4">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider mb-2">Coverage for {result.ioc_type}</h3>
        {applicable.length === 0 ? <p className="text-sm text-text-secondary">No reputation adapter is implemented for this IOC type; displayed data is contextual enrichment only.</p> : (
          <div className="flex flex-wrap gap-2">
            {applicable.map((source) => <StatusPill key={source.name} value={`${source.name}: ${sourceState(source)}`} />)}
          </div>
        )}
        {missing.length > 0 && <p className="text-xs text-amber-400 mt-3">Not queried because credentials are absent: {missing.map((source) => source.name).join(", ")}.</p>}
        {evidence.unavailable.length > 0 && <p className="text-xs text-verdict-malicious mt-2">Unavailable during this lookup: {evidence.unavailable.map((item) => item.source).join(", ")}.</p>}
      </div>
    </div>
  );
}
