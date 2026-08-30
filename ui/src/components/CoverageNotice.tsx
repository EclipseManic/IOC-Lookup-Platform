import type { LookupResponse } from "../services/api";

export default function CoverageNotice({ result }: { result: LookupResponse }) {
  const notes = result.enrichment?.analysis_notes ?? [];
  const errors = Object.entries(result.enrichment?.completeness ?? {})
    .filter(([, status]) => status === "error" || status.startsWith("http_") || status === "not_configured" || status === "unavailable");
  const assessment = result.final_assessment;
  const providerFailures = assessment
    ? [...assessment.rate_limited_sources, ...assessment.unavailable_sources, ...assessment.error_sources.filter((source) => !assessment.rate_limited_sources.includes(source))]
    : [];
  const domain = assessment?.assessment_domain ?? "ioc_reputation";
  const hasSuccessfulData = result.results.some((r) => r.execution_state === "success" && r.status !== "not_found");
  const noCoverage =
    domain === "ioc_reputation" &&
    result.composite.sources_contributing === 0 &&
    (assessment?.evidence_summary?.evaluated_providers ?? 0) === 0 &&
    !hasSuccessfulData;
  if (notes.length === 0 && errors.length === 0 && providerFailures.length === 0 && !noCoverage) return null;

  return (
    <div className="bg-bg-card border border-border rounded-lg p-4 text-sm">
      {noCoverage && (
        <div className="mb-3 rounded-md border border-amber-500/40 bg-amber-500/10 px-3 py-2 text-amber-300">
          <p className="font-semibold mb-1">NO COVERAGE — 0 sources contributed a result</p>
          <p className="text-xs text-text-secondary">
            This verdict is <span className="text-text-primary">unknown, not a clean signal</span>. The IOC type
            may not be covered by the configured sources, or none of them had data. Verify against an alternate
            source before trusting it.
          </p>
        </div>
      )}
      <h3 className="font-semibold text-text-secondary uppercase tracking-wider text-xs mb-2">Coverage & Limitations</h3>
      {notes.map((note) => <p key={note} className="text-text-primary mb-1">{note}</p>)}
      {errors.length > 0 && (
        <p className="text-text-secondary">
          Coverage unavailable or not configured: {errors.map(([name, status]) => `${name} (${status})`).join(", ")}. These do not represent a malicious/clean verdict.
        </p>
      )}
      {assessment && providerFailures.length > 0 && (
        <p className="text-text-secondary mt-2">
          Provider coverage is incomplete: {providerFailures.join(", ")}. These failures are excluded from reputation scoring; current coverage is {Math.round(assessment.coverage * 100)}%.
        </p>
      )}
    </div>
  );
}
