const VERDICT_COLORS: Record<string, string> = {
  malicious: "bg-red-500/10 text-red-400 border-red-500/30",
  suspicious: "bg-amber-500/10 text-amber-400 border-amber-500/30",
  clean: "bg-green-500/10 text-green-400 border-green-500/30",
  unknown: "bg-gray-500/10 text-gray-400 border-gray-500/30",
  error: "bg-rose-950/40 text-rose-300 border-rose-400/50",
  unavailable: "bg-rose-950/40 text-rose-300 border-rose-400/50",
};

export default function VerdictBadge({ verdict, size = "sm" }: { verdict: string; size?: "sm" | "md" }) {
  const cls = VERDICT_COLORS[verdict] || VERDICT_COLORS.unknown;
  const textSize = size === "sm" ? "text-xs" : "text-sm";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-full border font-semibold ${cls} ${textSize}`}>
      {verdict}
    </span>
  );
}
