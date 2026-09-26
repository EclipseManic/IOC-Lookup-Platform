import type { NormalizedResult } from "../services/api";

const VERDICT_ORDER = ["malicious", "breached", "suspicious", "clean", "not_breached", "unknown"] as const;
const VERDICT_COLORS: Record<string, string> = {
  malicious: "bg-red-500",
  breached: "bg-rose-500",
  suspicious: "bg-amber-500",
  clean: "bg-green-500",
  not_breached: "bg-emerald-500",
  unknown: "bg-gray-500",
};

export default function ConsensusBar({ results }: { results: NormalizedResult[] }) {
  const counts: Record<string, number> = {};
  let total = 0;
  for (const r of results) {
    let v = r.verdict === "error" || r.status === "error" ? "error" : (r.verdict || "unknown");
    if (v === "compromised" || v === "breached" || v === "pwned") v = "breached";
    else if (v === "not_breached" || v === "not_pwned") v = "not_breached";
    else if (v === "benign") v = "clean";
    counts[v] = (counts[v] || 0) + 1;
    if (v !== "error") total++;
  }
  if (total === 0) return null;

  return (
    <div className="bg-bg-card border border-border rounded-lg p-4">
      <h3 className="text-sm font-semibold mb-3 text-text-secondary uppercase tracking-wider">Source Consensus</h3>
      <div className="flex h-3 rounded-full overflow-hidden">
        {VERDICT_ORDER.map((v) => {
          if (!counts[v]) return null;
          const pct = (counts[v] / total) * 100;
          return (
            <div
              key={v}
              className={VERDICT_COLORS[v]}
              style={{ width: `${pct}%` }}
              title={`${v}: ${counts[v]} (${pct.toFixed(0)}%)`}
            />
          );
        })}
      </div>
      <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2">
        {VERDICT_ORDER.map((v) => {
          if (!counts[v]) return null;
          return (
            <div key={v} className="flex items-center gap-1.5 text-xs">
              <span className={`w-2 h-2 rounded-full ${VERDICT_COLORS[v]}`} />
              <span className="text-text-secondary">{v.replace(/_/g, " ")}</span>
              <span className="text-text-primary font-mono">{counts[v]}</span>
            </div>
          );
        })}
      </div>
      {(counts.error || 0) > 0 && (
        <p className="mt-2 text-xs text-text-secondary">
          {(counts.error || 0)} source{counts.error === 1 ? "" : "s"} unavailable; unavailable sources do not participate in the verdict.
        </p>
      )}
    </div>
  );
}
