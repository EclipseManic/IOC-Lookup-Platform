import { useMemo, useState } from "react";
import type { LookupResponse, NormalizedResult } from "../services/api";
import ConsensusBar from "../components/ConsensusBar";
import CoverageNotice from "../components/CoverageNotice";
import EnrichmentPanel from "../components/EnrichmentPanel";
import EvidencePanel from "../components/EvidencePanel";
import ExportMenu, { ExportTab } from "../components/ExportMenu";
import FeedbackWidget from "../components/FeedbackWidget";
import RelationshipGraph from "../components/RelationshipGraph";
import SourceCard from "../components/SourceCard";
import TabBar, { type TabName } from "../components/TabBar";
import VerdictBadge from "../components/VerdictBadge";

function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function hasProviderData(result: NormalizedResult): boolean {
  return (
    result.execution_state === "success" &&
    result.status !== "not_found" &&
    (Object.keys(result.raw_data ?? {}).length > 0 ||
      result.verdict !== "unknown" ||
      result.tags.length > 0 ||
      result.reports_count != null)
  );
}

function SummaryMetric({
  label,
  value,
  detail,
  accent = "text-text-primary",
}: {
  label: string;
  value: string;
  detail?: string;
  accent?: string;
}) {
  return (
    <div className="min-w-[120px] flex-1 border-l border-border pl-4 first:border-l-0 first:pl-0">
      <div className="text-[10px] font-semibold uppercase tracking-wider text-text-secondary">{label}</div>
      <div className={`mt-1 text-lg font-bold ${accent}`}>{value}</div>
      {detail && <div className="mt-0.5 text-[10px] text-text-secondary">{detail}</div>}
    </div>
  );
}

function RawDataView({ results }: { results: NormalizedResult[] }) {
  return (
    <div className="space-y-2">
      <div className="mb-3 rounded-lg border border-violet-500/25 bg-violet-500/5 p-3 text-xs text-violet-200">
        Raw provider payloads are preserved for audit and truncated to 10 KiB per provider.
      </div>
      {results.map((item) => (
        <details key={item.source} className="rounded-xl border border-border bg-bg-card" open={false}>
          <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-sm font-semibold">
            <span className="flex min-w-0 items-center gap-2">
              <span className="truncate">{item.source}</span>
              <span className="text-xs font-normal text-text-secondary">{item.provider_summary || "provider payload"}</span>
            </span>
            <span className="text-xs text-text-secondary">JSON</span>
          </summary>
          <pre className="max-h-[420px] overflow-auto whitespace-pre-wrap break-all border-t border-border bg-[#080b12] p-4 font-mono text-[10px] leading-relaxed text-slate-300">
            {Object.keys(item.raw_data ?? {}).length ? JSON.stringify(item.raw_data, null, 2) : "No raw JSON returned."}
          </pre>
        </details>
      ))}
      {results.length === 0 && (
        <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-secondary">
          No provider payloads are available.
        </div>
      )}
    </div>
  );
}

export default function ResultView({
  result,
  onNewSearch,
}: {
  result: LookupResponse;
  onNewSearch: (v: string, type?: string, refresh?: boolean) => void;
}) {
  const [tab, setTab] = useState<TabName>("Providers");
  const assessment = result.final_assessment;
  const rawVerdict = assessment?.final_verdict || result.composite.verdict;
  const domain = assessment?.assessment_domain || "ioc_reputation";

  // For credential_exposure domain: if HIBP flagged it, surface 'compromised' as the effective verdict
  const verdict = domain === "credential_exposure"
    ? (result.results.some((r) => r.verdict === "malicious") ? "compromised" : rawVerdict)
    : rawVerdict;

  const score = assessment?.normalized_score ?? result.composite.score;
  const confidence = assessment?.confidence || result.composite.confidence;
  const expected = Number(
    assessment?.evidence_summary?.expected_providers ??
      assessment?.provider_breakdown?.length ??
      result.results.length
  );
  const returned = result.results.filter(hasProviderData);
  const noData = result.results.filter((item) => !hasProviderData(item));
  const flagged = result.results.filter((item) =>
    ["malicious", "suspicious", "compromised"].includes(item.normalized_verdict || item.verdict)
  ).length;

  const analysisSeconds = useMemo(() => {
    const latencies = result.results.map((item) => item.latency_ms ?? 0);
    return Math.max(...latencies, 0) / 1000;
  }, [result.results]);

  // Score formatting per domain
  const displayScore =
    domain === "ioc_reputation" || !assessment?.assessment_domain
      ? `${Math.round(score)}/100`
      : domain === "credential_exposure"
      ? (returned.length > 0 && result.results.some((r) => r.verdict === "malicious") ? "Pwned" : "Not Pwned")
      : domain === "vulnerability"
      ? (result.enrichment?.cve?.cvss_score != null ? `CVSS ${result.enrichment.cve.cvss_score}/10` : `${Math.round(score)}/100`)
      : "N/A";

  const handleNodeClick = (value: string) => onNewSearch(value);

  return (
    <div className="space-y-5">
      {/* Header bar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div>
          <div className="flex items-center gap-2">
            <span className="status-dot" />
            <span className="text-[10px] font-semibold uppercase tracking-[0.18em] text-accent">Live assessment</span>
          </div>
          <h2 className="mt-1 text-xl font-bold tracking-tight">Threat Intelligence Results</h2>
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => onNewSearch(result.normalized, result.ioc_type, true)}
            className="rounded-md border border-accent/40 bg-accent/10 px-3 py-2 text-xs font-semibold text-accent hover:bg-accent/20 transition-colors"
          >
            Refresh live
          </button>
          <ExportMenu result={result} />
        </div>
      </div>

      {/* Main Metric Banner */}
      <section className="overflow-hidden rounded-2xl border border-border bg-bg-card shadow-[0_18px_45px_rgba(0,0,0,0.28)]">
        <div className="border-b border-border bg-bg-secondary/70 px-5 py-4">
          <div className="flex flex-wrap items-center gap-2 text-[10px] font-semibold uppercase tracking-wider text-text-secondary">
            <span className="rounded border border-border bg-bg-elevated px-2 py-1 font-mono text-accent">
              {result.ioc_type}
            </span>
            <span>Indicator Value</span>
          </div>
          <div className="mt-2 flex flex-wrap items-center gap-3">
            <code className="min-w-0 break-all font-mono text-base font-semibold text-text-primary sm:text-lg">
              {result.normalized}
            </code>
            <button
              type="button"
              className="rounded border border-border px-2 py-1 text-[11px] font-medium text-text-secondary hover:border-accent hover:text-accent transition-colors"
              onClick={() => void navigator.clipboard?.writeText(result.normalized)}
            >
              Copy
            </button>
            <VerdictBadge verdict={verdict} size="md" />
          </div>
        </div>

        <div className="flex flex-wrap gap-5 px-5 py-4">
          <SummaryMetric
            label="Verdict"
            value={titleCase(verdict)}
            accent={
              verdict === "compromised" || verdict.includes("malicious") || verdict === "critical" || verdict === "high"
                ? "text-red-400"
                : verdict === "suspicious" || verdict === "medium"
                ? "text-amber-400"
                : verdict === "clean" || verdict === "benign" || verdict === "not_pwned" || verdict === "low"
                ? "text-emerald-400"
                : "text-slate-300"
            }
          />
          <SummaryMetric
            label={
              domain === "credential_exposure"
                ? "Breach status"
                : domain === "vulnerability"
                ? "Severity score"
                : "Risk score"
            }
            value={displayScore}
            detail={
              domain === "credential_exposure"
                ? "HIBP k-anonymity check"
                : domain === "vulnerability"
                ? (result.enrichment?.cve?.cvss_severity ? `CVSS ${result.enrichment.cve.cvss_severity}` : "NVD / NIST CVE context")
                : domain && domain !== "ioc_reputation"
                ? titleCase(domain)
                : "weighted evidence"
            }
            accent={
              (domain === "credential_exposure" && displayScore === "Pwned") ||
              (domain === "vulnerability" && (verdict === "critical" || verdict === "high"))
                ? "text-red-400"
                : "text-accent"
            }
          />
          <SummaryMetric
            label="Confidence"
            value={titleCase(confidence)}
            detail={
              assessment?.confidence_score != null
                ? `${Math.round(assessment.confidence_score * 100)}% score`
                : undefined
            }
          />
          <SummaryMetric
            label="Provider coverage"
            value={`${returned.length}/${expected || result.results.length}`}
            detail={`${flagged} flagged · ${noData.length} no data`}
            accent="text-sky-300"
          />
          <SummaryMetric
            label="Analysis time"
            value={`${analysisSeconds.toFixed(1)}s`}
            detail={`${result.results.length} total providers`}
          />
        </div>
      </section>

      {/* Analyst executive summary */}
      {result.executive_summary && (
        <div className="rounded-xl border border-border bg-bg-card p-4 text-sm leading-relaxed text-text-secondary">
          <span className="mr-2 text-[10px] font-semibold uppercase tracking-wider text-accent">Analyst summary</span>
          {result.executive_summary}
        </div>
      )}

      {/* Consensus Bar */}
      {assessment && <ConsensusBar results={result.results} />}
      <CoverageNotice result={result} />

      {/* Tabs */}
      <TabBar active={tab} onChange={setTab} />

      <div id="result-panel" role="tabpanel" aria-label={`${tab} results`}>
        {tab === "Providers" && (
          <div className="space-y-4">
            <div className="flex flex-wrap items-end justify-between gap-3">
              <div>
                <h3 className="text-sm font-semibold uppercase tracking-[0.14em] text-text-secondary">Provider data</h3>
                <p className="mt-1 text-xs text-text-secondary">Live returned threat intelligence per active provider.</p>
              </div>
              <div className="flex gap-3 text-[10px] text-text-secondary">
                <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-red-400" />malicious</span>
                <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-amber-400" />suspicious</span>
                <span><i className="mr-1 inline-block h-2 w-2 rounded-full bg-sky-400" />context</span>
              </div>
            </div>

            {returned.length > 0 ? (
              <div className="grid grid-cols-1 gap-3 xl:grid-cols-2">
                {returned.map((item) => (
                  <SourceCard key={item.source} result={item} />
                ))}
              </div>
            ) : domain === "credential_exposure" ? (
              <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-6 text-center">
                <h4 className="text-sm font-bold text-emerald-300">✓ No Public Breach Found</h4>
                <p className="mt-1 text-xs text-text-secondary">
                  This credential was not found in any public breach database checked by HIBP. This does not guarantee it has never been compromised.
                </p>
              </div>
            ) : flagged === 0 ? (
              <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-6 text-center">
                <h4 className="text-sm font-bold text-blue-200">Clean Threat Feed Posture</h4>
                <p className="mt-1 text-xs text-text-secondary">
                  0 out of {result.results.length} queried threat feeds flagged this indicator. No active blocklist sightings observed.
                </p>
              </div>
            ) : (
              <div className="rounded-xl border border-amber-500/30 bg-amber-500/5 p-6 text-center text-sm text-amber-200">
                No providers returned usable data.
              </div>
            )}

            {noData.length > 0 && (
              <details className="rounded-xl border border-border bg-bg-card">
                <summary className="flex cursor-pointer list-none items-center justify-between px-4 py-3 text-sm font-semibold text-text-secondary">
                  <span>No data / Inactive providers ({noData.length})</span>
                  <span className="text-xs font-normal">click to expand</span>
                </summary>
                <div className="grid grid-cols-1 gap-2 border-t border-border p-3 md:grid-cols-2">
                  {noData.map((item) => (
                    <SourceCard key={item.source} result={item} />
                  ))}
                </div>
              </details>
            )}
          </div>
        )}

        {tab === "Enrichment" && <EnrichmentPanel enrichment={result.enrichment} iocType={result.ioc_type} />}
        {tab === "Evidence" && <EvidencePanel result={result} />}
        {tab === "Raw Data" && <RawDataView results={result.results} />}
        {tab === "Relationships" && (
          result.relationships.length > 0 ? (
            <RelationshipGraph mainIoc={result.normalized} relationships={result.relationships} onNodeClick={handleNodeClick} />
          ) : (
            <div className="rounded-xl border border-border bg-bg-card p-10 text-center text-sm text-text-secondary">
              No relationships found for this IOC.
            </div>
          )
        )}
        {tab === "Export" && <ExportTab result={result} />}
      </div>

      {/* Analyst Feedback Widget (cleanly positioned at the bottom of the evaluation) */}
      <div className="border-t border-border/80 pt-4">
        <FeedbackWidget ioc={result.normalized} />
      </div>
    </div>
  );
}
