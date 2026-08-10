import { DISPLAY_MALICIOUS, DISPLAY_SUSPICIOUS, DISPLAY_CLEAN } from "../lib/thresholds";

const SCORE_COLORS = [
  { threshold: DISPLAY_MALICIOUS, color: "#ef4444", label: "malicious" },
  { threshold: DISPLAY_SUSPICIOUS, color: "#f59e0b", label: "high" },
  { threshold: DISPLAY_CLEAN, color: "#f59e0b", label: "suspicious" },
  { threshold: 0, color: "#22c55e", label: "clean" },
] as const;

function getColor(score: number) {
  for (const c of SCORE_COLORS) {
    if (score >= c.threshold) return c.color;
  }
  return "#6b7280";
}

export default function ScoreRing({ score, size = 80 }: { score: number; size?: number }) {
  const colorLabel = getColor(score) === "#ef4444" ? "malicious" : getColor(score) === "#f59e0b" ? score >= DISPLAY_SUSPICIOUS ? "high risk" : "suspicious" : "clean";
  const radius = 15.5;
  const circumference = 2 * Math.PI * radius;
  const offset = circumference - (score / 100) * circumference;
  const color = getColor(score);

  return (
    <div className="relative" style={{ width: size, height: size }} role="meter" aria-valuenow={score} aria-valuemin={0} aria-valuemax={100} aria-label={`Composite score: ${score.toFixed(0)} out of 100, ${colorLabel}`}>
      <svg className="-rotate-90" width={size} height={size} viewBox="0 0 36 36" aria-hidden="true">
        <circle cx="18" cy="18" r={radius} fill="none" stroke="#1e293b" strokeWidth="3" />
        <circle
          cx="18" cy="18" r={radius}
          fill="none" stroke={color} strokeWidth="3"
          strokeDasharray={circumference}
          strokeDashoffset={offset}
          strokeLinecap="round"
          className="transition-all duration-700 ease-out"
        />
      </svg>
      <span className="absolute inset-0 flex items-center justify-center font-mono font-bold" style={{ fontSize: size * 0.28 }} aria-hidden="true">
        {score.toFixed(0)}
      </span>
    </div>
  );
}
