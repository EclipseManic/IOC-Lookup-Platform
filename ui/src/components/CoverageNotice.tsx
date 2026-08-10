import type { LookupResponse } from "../services/api";

export default function CoverageNotice({ result }: { result: LookupResponse }) {
  const notes = result.enrichment?.analysis_notes ?? [];
  const errors = Object.entries(result.enrichment?.completeness ?? {})
    .filter(([, status]) => status === "error" || status.startsWith("http_") || status === "not_configured" || status === "unavailable");
  if (notes.length === 0 && errors.length === 0) return null;

  return (
    <div className="bg-bg-card border border-border rounded-lg p-4 text-sm">
      <h3 className="font-semibold text-text-secondary uppercase tracking-wider text-xs mb-2">Coverage & Limitations</h3>
      {notes.map((note) => <p key={note} className="text-text-primary mb-1">{note}</p>)}
      {errors.length > 0 && (
        <p className="text-text-secondary">
          Coverage unavailable or not configured: {errors.map(([name, status]) => `${name} (${status})`).join(", ")}. These do not represent a malicious/clean verdict.
        </p>
      )}
    </div>
  );
}
