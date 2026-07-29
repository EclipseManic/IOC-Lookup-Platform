export default function Tag({ label, variant = "default" }: { label: string; variant?: "default" | "accent" | "cached" }) {
  const cls =
    variant === "accent" ? "bg-accent/10 text-accent border-accent/30" :
    variant === "cached" ? "bg-emerald-500/10 text-emerald-400 border-emerald-500/30" :
    "bg-bg-elevated text-text-secondary border-border";
  return (
    <span className={`inline-flex items-center px-2 py-0.5 text-[11px] rounded-full border font-mono ${cls}`}>
      {label}
    </span>
  );
}
