const VERDICT_COLORS: Record<string, string> = {
  malicious: "bg-red-500/10 text-red-400 border-red-500/30",
  breached: "bg-rose-500/15 text-rose-400 border-rose-500/40 shadow-[0_0_8px_rgba(244,63,94,0.2)]",
  compromised: "bg-red-500/10 text-red-400 border-red-500/30",
  suspicious: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  clean: "bg-green-500/10 text-green-400 border-green-500/30",
  benign: "bg-green-500/10 text-green-400 border-green-500/30",
  not_breached: "bg-emerald-500/15 text-emerald-400 border-emerald-500/40 shadow-[0_0_8px_rgba(16,185,129,0.2)]",
  not_pwned: "bg-green-500/10 text-green-400 border-green-500/30",
  not_found: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  not_applicable: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
  not_configured: "bg-slate-500/10 text-slate-400 border-slate-500/30",
  rate_limited: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  malicious_test_artifact: "bg-blue-500/10 text-blue-300 border-blue-500/30",
  critical: "bg-red-500/10 text-red-300 border-red-500/40",
  high: "bg-orange-500/10 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/10 text-amber-300 border-amber-500/30",
  low: "bg-lime-500/10 text-lime-300 border-lime-500/30",
  informational: "bg-sky-500/10 text-sky-300 border-sky-500/30",
  context_only: "bg-cyan-500/10 text-cyan-300 border-cyan-500/30",
  technique_metadata: "bg-violet-500/10 text-violet-300 border-violet-500/30",
  technique_metadata_unavailable: "bg-violet-500/10 text-violet-300 border-violet-500/30",
  unknown: "bg-gray-500/10 text-gray-400 border-gray-500/30",
  error: "bg-rose-950/40 text-rose-300 border-rose-400/50",
  unavailable: "bg-rose-950/40 text-rose-300 border-rose-400/50",
};

export default function VerdictBadge({ verdict, size = "sm" }: { verdict: string; size?: "sm" | "md" }) {
  const normalizedKey = verdict.toLowerCase().replace(/\s+/g, "_");
  const cls = VERDICT_COLORS[normalizedKey] || VERDICT_COLORS[verdict] || VERDICT_COLORS.unknown;
  const textSize = size === "sm" ? "text-xs" : "text-sm";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full border font-semibold ${cls} ${textSize}`}>
      {verdict.replace(/_/g, " ")}
    </span>
  );
}
