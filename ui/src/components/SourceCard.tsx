import { useState } from "react";
import type { NormalizedResult } from "../services/api";
import Tag from "./Tag";
import VerdictBadge from "./VerdictBadge";

export default function SourceCard({ result }: { result: NormalizedResult }) {
  const [expanded, setExpanded] = useState(false);
  const isCached = result.tags.includes("cached");

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
          <VerdictBadge verdict={result.verdict} />
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
          {result.reports_count !== null && result.reports_count !== undefined && (
            <div className="text-xs text-text-secondary">
              Reports: <span className="text-text-primary">{result.reports_count}</span>
            </div>
          )}
          {result.source_link && (
            <a href={result.source_link} target="_blank" rel="noopener noreferrer" className="text-xs text-accent hover:underline inline-block">
              View source →
            </a>
          )}
          {(result as any).mitre_attck && (result as any).mitre_attck.length > 0 && (
            <div>
              <div className="text-xs text-text-secondary mb-1">MITRE ATT&CK:</div>
              <div className="flex flex-wrap gap-1">
                {(result as any).mitre_attck.map((m: string) => (
                  <Tag key={m} label={m} variant="accent" />
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
