import { useState } from "react";
import type { NormalizedResult } from "../services/api";
import Tag from "./Tag";
import VerdictBadge from "./VerdictBadge";

export default function SourceCard({ result }: { result: NormalizedResult }) {
  const [expanded, setExpanded] = useState(false);
  const isCached = result.tags.includes("cached");
  const unavailable = result.verdict === "error" || result.status === "error";

  return (
    <div className="bg-bg-card border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        aria-expanded={expanded}
        aria-controls={`source-detail-${result.source.replace(/\s+/g, "-")}`}
        className="w-full flex items-center justify-between p-3 hover:bg-bg-elevated/50 transition-colors text-left"
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className="text-sm font-semibold truncate">{result.source}</span>
          {isCached && <Tag label="cached" variant="cached" />}
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <VerdictBadge verdict={unavailable ? "unavailable" : result.verdict} />
          {result.raw_score !== null && (
            <span className="text-xs text-text-secondary font-mono w-8 text-right">
              {(result.raw_score * 100).toFixed(0)}
            </span>
          )}
          <svg className={`w-3 h-3 text-text-secondary transition-transform ${expanded ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>
      {expanded && (
        <div id={`source-detail-${result.source.replace(/\s+/g, "-")}`} className="px-3 pb-3 space-y-2 border-t border-border pt-2">
          {result.tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {result.tags.filter(t => t !== "cached").map((t) => (
                <Tag key={t} label={t} />
              ))}
            </div>
          )}
          {result.confidence && (
            <div className="text-xs text-text-secondary">
              Confidence: <span className="text-text-primary">{result.confidence}</span>
            </div>
          )}
          {result.malware_family && (
            <div className="text-xs text-text-secondary">
              Family: <span className="text-verdict-malicious">{result.malware_family}</span>
            </div>
          )}
          {result.categories && result.categories.length > 0 && (
            <div>
              <div className="text-xs text-text-secondary mb-1">Categories:</div>
              <div className="flex flex-wrap gap-1">
                {result.categories.map((c) => (
                  <Tag key={c} label={c} />
                ))}
              </div>
            </div>
          )}
          {result.reports_count !== null && result.reports_count !== undefined && (
            <div className="text-xs text-text-secondary">
              Reports: <span className="text-text-primary">{result.reports_count}</span>
            </div>
          )}
          {(result.first_seen || result.last_seen) && (
            <div className="text-xs text-text-secondary space-y-0.5">
              {result.first_seen && (
                <div>First seen: <span className="text-text-primary font-mono">{result.first_seen}</span></div>
              )}
              {result.last_seen && (
                <div>Last seen: <span className="text-text-primary font-mono">{result.last_seen}</span></div>
              )}
            </div>
          )}
          {result.samples && result.samples.length > 0 && (
            <div>
              <div className="text-xs text-text-secondary mb-1">Samples:</div>
              <div className="flex flex-wrap gap-1">
                {result.samples.map((s) => (
                  <span key={s} className="text-[11px] px-2 py-0.5 bg-bg-elevated border border-border rounded-full font-mono text-text-secondary truncate max-w-[220px]" title={s}>{s}</span>
                ))}
              </div>
            </div>
          )}
          {(result.ssdeep || result.tlsh) && (
            <div className="text-xs text-text-secondary space-y-1">
              {result.ssdeep && <div>SSDeep: <span className="font-mono text-text-primary break-all">{result.ssdeep}</span></div>}
              {result.tlsh && <div>TLSH: <span className="font-mono text-text-primary break-all">{result.tlsh}</span></div>}
            </div>
          )}
          {result.dropped_files && result.dropped_files.length > 0 && (
            <div className="text-xs text-text-secondary">
              Dropped files:
              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-2 text-[11px]">
                {result.dropped_files.join("\n")}
              </pre>
            </div>
          )}
          {result.registry_keys && result.registry_keys.length > 0 && (
            <div className="text-xs text-text-secondary">
              Registry keys:
              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-2 text-[11px]">
                {result.registry_keys.join("\n")}
              </pre>
            </div>
          )}
          {result.network_iocs && result.network_iocs.length > 0 && (
            <div className="text-xs text-text-secondary">
              Network IOCs:
              <pre className="mt-1 max-h-40 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-2 text-[11px]">
                {JSON.stringify(result.network_iocs, null, 2)}
              </pre>
            </div>
          )}
          {result.process_tree && (
            <div className="text-xs text-text-secondary">
              Process tree:
              <pre className="mt-1 max-h-48 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-2 text-[11px]">{result.process_tree}</pre>
            </div>
          )}
          {result.reports && result.reports.length > 0 && (
            <details className="text-xs">
              <summary className="cursor-pointer text-accent">Reports ({result.reports.length})</summary>
              <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-2 text-[11px] text-text-secondary">
                {JSON.stringify(result.reports, null, 2)}
              </pre>
            </details>
          )}
          {result.related_iocs && result.related_iocs.length > 0 && (
            <div>
              <div className="text-xs text-text-secondary mb-1">Related IOCs:</div>
              <div className="flex flex-wrap gap-1">
                {result.related_iocs.map(([ioc, relation]) => (
                  <span key={`${relation}:${ioc}`} className="text-[11px] px-2 py-0.5 bg-bg-elevated border border-border rounded-full font-mono text-text-secondary truncate max-w-[220px]" title={`${relation}: ${ioc}`}>{ioc}</span>
                ))}
              </div>
            </div>
          )}
          {result.source_link && (
            <a href={result.source_link} target="_blank" rel="noopener noreferrer" className="text-xs text-accent hover:underline inline-block">
              View source →
            </a>
          )}
          {result.mitre_attck && result.mitre_attck.length > 0 && (
            <div>
              <div className="text-xs text-text-secondary mb-1">MITRE ATT&CK:</div>
              <div className="flex flex-wrap gap-1">
                {result.mitre_attck.map((m) => (
                  <Tag key={m} label={m} variant="accent" />
                ))}
              </div>
            </div>
          )}
          {result.raw_data && Object.keys(result.raw_data).length > 0 && (
            <details className="text-xs">
              <summary className="cursor-pointer text-accent">Raw source details</summary>
              <pre className="mt-2 max-h-64 overflow-auto whitespace-pre-wrap break-all rounded bg-bg-elevated p-2 text-[11px] text-text-secondary">
                {JSON.stringify(result.raw_data, null, 2)}
              </pre>
            </details>
          )}
        </div>
      )}
    </div>
  );
}
