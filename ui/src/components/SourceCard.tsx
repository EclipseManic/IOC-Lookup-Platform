import { useState } from "react";
import type { NormalizedResult } from "../services/api";
import Tag from "./Tag";
import VerdictBadge from "./VerdictBadge";

const CONTEXT_SOURCES = new Set([
  "IPinfo", "Shodan", "Censys", "GreyNoise", "Team Cymru", "Tor Exit",
  "Etherscan", "Blockchain.info",
]);

function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function cardTone(result: NormalizedResult): { border: string; dot: string } {
  const state = result.execution_state || result.status;
  if (state !== "success" && state !== "not_found") return { border: "border-slate-700", dot: "bg-slate-500" };
  if (CONTEXT_SOURCES.has(result.source)) return { border: "border-sky-500/50", dot: "bg-sky-400" };
  const verdict = result.normalized_verdict || result.verdict;
  if (verdict.includes("malicious") || verdict === "compromised") return { border: "border-red-500/70", dot: "bg-red-400" };
  if (verdict === "suspicious") return { border: "border-amber-500/70", dot: "bg-amber-400" };
  if (["clean", "benign", "harmless", "whitelisted", "not_found"].includes(verdict)) return { border: "border-emerald-500/60", dot: "bg-emerald-400" };
  return { border: "border-slate-600", dot: "bg-slate-400" };
}

function rawSummary(result: NormalizedResult): string {
  if (result.provider_summary) return result.provider_summary;
  if (result.detection_count != null && result.total_engines) return `${result.detection_count}/${result.total_engines} engines flagged`;
  if (result.reports_count != null) return `${result.reports_count} report${result.reports_count === 1 ? "" : "s"} returned`;
  return result.verdict === "unknown" ? "Provider returned context" : `Provider verdict: ${titleCase(result.verdict)}`;
}

function rawValue(result: NormalizedResult, keys: string[]): string | null {
  for (const key of keys) {
    const value = result.raw_data?.[key];
    if (value !== null && value !== undefined && value !== "") {
      if (Array.isArray(value)) return value.slice(0, 4).map(String).join(", ");
      if (typeof value === "object") return JSON.stringify(value);
      return String(value);
    }
  }
  return null;
}

export default function SourceCard({ result }: { result: NormalizedResult }) {
  const [expanded, setExpanded] = useState(false);
  const [showAllTags, setShowAllTags] = useState(false);
  const tone = cardTone(result);
  const state = result.execution_state || result.status;
  const family = result.malware_family || rawValue(result, ["family", "malware_family", "threat_name"]);
  const details = [
    result.detection_count != null && result.total_engines ? `${result.detection_count}/${result.total_engines} engines` : null,
    family ? `Family: ${family}` : null,
    result.reports_count != null ? `${result.reports_count} reports` : null,
  ].filter(Boolean) as string[];

  const filteredTags = result.tags.filter((tag) => tag !== "cached");
  const visibleTags = showAllTags ? filteredTags : filteredTags.slice(0, 8);

  return (
    <article className={`flex flex-col justify-between overflow-hidden rounded-xl border-l-2 border-y border-r bg-bg-card shadow-[0_10px_26px_rgba(0,0,0,0.18)] transition-all ${tone.border}`}>
      <div className="p-4">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2">
              <span className={`h-2 w-2 shrink-0 rounded-full ${tone.dot}`} />
              <h3 className="truncate text-sm font-semibold text-text-primary">{result.source}</h3>
              {CONTEXT_SOURCES.has(result.source) && (
                <span className="rounded border border-sky-500/30 bg-sky-500/10 px-1.5 py-0.5 text-[9px] font-semibold uppercase tracking-wider text-sky-300">
                  context
                </span>
              )}
            </div>
            <p className="mt-2 text-sm font-medium text-text-primary">{rawSummary(result)}</p>
            {details.length > 0 && <p className="mt-1 line-clamp-2 text-xs text-text-secondary">{details.join(" · ")}</p>}
          </div>
          <div className="flex shrink-0 flex-col items-end gap-1">
            <VerdictBadge
              verdict={
                state === "success"
                  ? result.verdict
                  : state === "not_applicable"
                  ? "not_applicable"
                  : state === "not_configured"
                  ? "not_configured"
                  : state === "rate_limited"
                  ? "rate_limited"
                  : state === "not_found"
                  ? (result.verdict || "not_found")
                  : (result.verdict || state || "unavailable")
              }
            />
            {result.cached && (
              <span className="text-[10px] uppercase tracking-wider text-text-secondary">
                {result.stale ? "stale cache" : "cached"}
              </span>
            )}
          </div>
        </div>

        <div className="mt-4 flex flex-wrap items-center gap-x-4 gap-y-2 text-[10px] text-text-secondary">
          <span>{state === "not_found" ? "No matching record observed" : state === "success" ? "Response received" : titleCase(state)}</span>
          {result.latency_ms != null && <span>{Math.round(result.latency_ms)} ms</span>}
          {result.source_timestamp && <span>observed {new Date(result.source_timestamp).toLocaleDateString()}</span>}
          {result.provider_verdict && result.provider_verdict !== result.verdict && <span>native: {titleCase(result.provider_verdict)}</span>}
        </div>

        {filteredTags.length > 0 && (
          <div className="mt-3 flex flex-wrap items-center gap-1">
            {visibleTags.map((tag) => (
              <Tag key={tag} label={tag} />
            ))}
            {filteredTags.length > 8 && (
              <button
                type="button"
                onClick={() => setShowAllTags((prev) => !prev)}
                className="rounded border border-border/80 bg-bg-secondary px-1.5 py-0.5 text-[9px] font-semibold text-accent hover:border-accent transition-colors"
              >
                {showAllTags ? "Show less" : `+${filteredTags.length - 8} more`}
              </button>
            )}
          </div>
        )}
      </div>

      <div className="border-t border-border bg-bg-card/60 p-3 pt-2">
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setExpanded((value) => !value)}
            className="rounded-md border border-border bg-bg-elevated px-2.5 py-1.5 text-[11px] font-semibold text-text-secondary hover:border-accent/50 hover:text-accent transition-colors"
          >
            {expanded ? "Hide raw payload" : "View raw payload"}
          </button>
          {result.source_link && (
            <a
              href={result.source_link}
              target="_blank"
              rel="noopener noreferrer"
              className="rounded-md border border-border px-2.5 py-1.5 text-[11px] font-semibold text-text-secondary hover:border-accent/50 hover:text-accent transition-colors"
            >
              Open source ↗
            </a>
          )}
        </div>

        {expanded && (
          <div className="mt-3 border-t border-border pt-3">
            <div className="mb-2 text-[10px] font-semibold uppercase tracking-wider text-text-secondary">Raw provider payload</div>
            <pre className="max-h-72 overflow-auto whitespace-pre-wrap break-all rounded-lg border border-border bg-[#080b12] p-3 font-mono text-[10px] leading-relaxed text-slate-300">
              {Object.keys(result.raw_data ?? {}).length ? JSON.stringify(result.raw_data, null, 2) : "No raw JSON was returned by this provider."}
            </pre>
          </div>
        )}
      </div>
    </article>
  );
}
