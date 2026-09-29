import { useMemo, useState } from "react";
import type { LookupResponse, NormalizedResult } from "../services/api";
import type { ResultSourceMeta } from "../hooks/useLookup";
import type { NavigateEvent } from "../App";
import AbuseReportsPanel from "../components/AbuseReportsPanel";
import ConsensusBar from "../components/ConsensusBar";
import ContextIntelCard, { hasContextIntel } from "../components/ContextIntelCard";
import CoverageNotice from "../components/CoverageNotice";
import EnrichmentPanel from "../components/EnrichmentPanel";
import EvidencePanel from "../components/EvidencePanel";
import ExportMenu, { ExportTab } from "../components/ExportMenu";
import PanelBoundary from "../components/PanelBoundary";
import FeedbackWidget from "../components/FeedbackWidget";
import HostingPivotCard from "../components/HostingPivotCard";
import HostVulnerabilityMatrix from "../components/HostVulnerabilityMatrix";
import InfostealerExposureCard from "../components/InfostealerExposureCard";
import RelationshipGraph from "../components/RelationshipGraph";
import ScoreRing from "../components/ScoreRing";
import SourceCard from "../components/SourceCard";
import SubdomainsCard from "../components/SubdomainsCard";
import TabBar, { type TabName } from "../components/TabBar";
import VerdictBadge from "../components/VerdictBadge";
import WebPreviewCard from "../components/WebPreviewCard";
import WhoisCard from "../components/WhoisCard";

function titleCase(value: string): string {
  return value.replace(/_/g, " ").replace(/\b\w/g, (character) => character.toUpperCase());
}

function hashType(value: string): "md5" | "sha1" | "sha256" {
  if (value.length === 32) return "md5";
  if (value.length === 40) return "sha1";
  return "sha256";
}

function defangValue(text: string): string {
  return text
    .replace(/https?:\/\//gi, (m) => (m.toLowerCase().startsWith("https") ? "hxxps://" : "hxxp://"))
    .replace(/\./g, "[.]");
}

/**
 * Coerce an unknown enrichment value into a display string. Missing / non-numeric
 * values render as an em dash rather than crashing or printing "NaN".
 */
function fmtMetric(value: unknown, suffix = ""): string {
  if (value === null || value === undefined || value === "") return "—";
  const numeric = Number(value);
  if (!Number.isFinite(numeric)) return "—";
  const formatted = numeric.toLocaleString(undefined, { maximumFractionDigits: 8 });
  return suffix ? `${formatted} ${suffix}` : formatted;
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

function StatCard({
  label,
  value,
  detail,
  accent = "text-text-primary",
  subtext,
}: {
  label: string;
  value: string;
  detail?: string;
  accent?: string;
  subtext?: string;
}) {
  return (
    <div className="rounded-xl border border-border/80 bg-bg-card/70 p-3.5 flex flex-col justify-between transition-colors hover:border-border">
      <div>
        <div className="text-[10px] font-bold uppercase tracking-wider text-text-secondary">{label}</div>
        <div className={`mt-1 text-lg font-extrabold tracking-tight ${accent}`}>{value}</div>
      </div>
      {(detail || subtext) && (
        <div className="mt-2 text-[11px] text-text-secondary border-t border-border/40 pt-1.5 flex items-center justify-between">
          {detail && <span>{detail}</span>}
          {subtext && <span className="font-mono text-[10px] text-accent/80">{subtext}</span>}
        </div>
      )}
    </div>
  );
}

function RawDataView({ results }: { results: NormalizedResult[] }) {
  const [filter, setFilter] = useState("");
  const filtered = filter.trim()
    ? results.filter((r) => r.source.toLowerCase().includes(filter.toLowerCase()))
    : results;

  const copyAll = () => {
    const allJson = Object.fromEntries(results.map((r) => [r.source, r.raw_data ?? {}]));
    void navigator.clipboard?.writeText(JSON.stringify(allJson, null, 2));
  };

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 rounded-xl border border-border bg-bg-card p-3">
        <div className="flex items-center gap-2">
          <input
            type="text"
            placeholder="Filter provider payloads..."
            value={filter}
            onChange={(e) => setFilter(e.target.value)}
            className="rounded-lg border border-border bg-bg-elevated px-3 py-1.5 text-xs text-text-primary placeholder:text-text-secondary/60 focus:border-accent focus:outline-none w-56"
          />
          <span className="text-xs text-text-secondary">
            Showing {filtered.length} of {results.length}
          </span>
        </div>
        <button
          type="button"
          onClick={copyAll}
          className="rounded-md border border-border bg-bg-elevated px-3 py-1.5 text-xs font-semibold text-text-secondary hover:text-accent hover:border-accent transition-colors"
        >
          Copy All Raw JSON
        </button>
      </div>

      <div className="space-y-2">
        {filtered.map((item) => (
          <details key={item.source} className="group rounded-xl border border-border bg-bg-card transition-all" open={false}>
            <summary className="flex cursor-pointer list-none items-center justify-between gap-3 px-4 py-3 text-xs font-semibold select-none hover:bg-bg-elevated/30 rounded-xl">
              <div className="flex min-w-0 items-center gap-2.5">
                <span className="text-accent font-bold">{item.source}</span>
                <span className="text-[11px] font-normal text-text-secondary truncate">
                  {item.provider_summary || (item.verdict ? `verdict: ${item.verdict}` : "payload")}
                </span>
              </div>
              <div className="flex items-center gap-2 text-[10px] text-text-secondary font-mono">
                {item.latency_ms != null && <span>{Math.round(item.latency_ms)}ms</span>}
                <span className="rounded bg-bg-elevated px-1.5 py-0.5 border border-border/60">JSON</span>
              </div>
            </summary>
            <pre className="max-h-[460px] overflow-auto whitespace-pre-wrap break-all border-t border-border bg-[#06080e] p-4 font-mono text-[11px] leading-relaxed text-slate-300">
              {Object.keys(item.raw_data ?? {}).length ? JSON.stringify(item.raw_data, null, 2) : "No raw JSON payload returned."}
            </pre>
          </details>
        ))}
      </div>
    </div>
  );
}

export default function ResultView({
  result,
  onNewSearch,
  meta,
}: {
  result: LookupResponse;
  onNewSearch: (v: string, type?: string, refresh?: boolean) => void;
  meta?: ResultSourceMeta;
}) {
  const [tab, setTab] = useState<TabName>("Investigation");
  const [providerFilter, setProviderFilter] = useState<"all" | "flagged" | "clean" | "no_data">("all");
  const [providerSearch, setProviderSearch] = useState("");
  const [copiedRaw, setCopiedRaw] = useState(false);
  const [copiedDefanged, setCopiedDefanged] = useState(false);

  const assessment = result.final_assessment;
  const rawVerdict = assessment?.final_verdict || result.composite.verdict;
  const domain = assessment?.assessment_domain || "ioc_reputation";
  const rescanType = result.password_prehashed ? "password_sha1" : result.ioc_type;

  // For credential_exposure domain: surface breached or not_breached
  const verdict = domain === "credential_exposure"
    ? (rawVerdict === "breached" || rawVerdict === "compromised" || result.results.some((r) => r.verdict === "breached" || r.verdict === "compromised" || r.verdict === "malicious")
        ? "breached"
        : (rawVerdict === "not_breached" || rawVerdict === "not_pwned" || rawVerdict === "clean" || rawVerdict === "benign")
        ? "not_breached"
        : rawVerdict)
    : rawVerdict;

  const score = assessment?.normalized_score ?? result.composite.score;
  const confidence = assessment?.confidence || result.composite.confidence;
  const expected = Number(
    assessment?.evidence_summary?.expected_providers ??
      assessment?.provider_breakdown?.length ??
      result.results.length
  );

  const returned = useMemo(() => result.results.filter(hasProviderData), [result.results]);
  const noData = useMemo(() => result.results.filter((item) => !hasProviderData(item)), [result.results]);

  const flaggedList = useMemo(() => {
    return returned.filter((item) =>
      ["malicious", "suspicious", "compromised", "breached", "pwned", "high", "critical"].includes(
        item.normalized_verdict || item.verdict
      )
    );
  }, [returned]);

  const cleanList = useMemo(() => {
    return returned.filter((item) =>
      ["clean", "benign", "harmless", "whitelisted", "not_pwned", "not_breached", "low"].includes(
        item.normalized_verdict || item.verdict
      )
    );
  }, [returned]);

  const flaggedCount = flaggedList.length;

  const analysisSeconds = useMemo(() => {
    const latencies = result.results.map((item) => item.latency_ms ?? 0);
    return Math.max(...latencies, 0) / 1000;
  }, [result.results]);

  const displayScore =
    rawVerdict === "context_only"
      ? "Context only"
      : domain === "credential_exposure"
      ? (verdict === "breached" ? "Breached" : "Not Breached")
      : domain === "ioc_reputation" || !assessment?.assessment_domain
      ? `${Math.round(score)}/100`
      : domain === "vulnerability"
      ? (result.enrichment?.cve?.cvss_score != null ? `CVSS ${result.enrichment.cve.cvss_score}/10` : `${Math.round(score)}/100`)
      : `${Math.round(score)}/100`;

  const handleCopyRaw = () => {
    void navigator.clipboard?.writeText(result.normalized);
    setCopiedRaw(true);
    setTimeout(() => setCopiedRaw(false), 2000);
  };

  const handleCopyDefanged = () => {
    void navigator.clipboard?.writeText(defangValue(result.normalized));
    setCopiedDefanged(true);
    setTimeout(() => setCopiedDefanged(false), 2000);
  };

  const handleNodeClick = (value: string) => onNewSearch(value);

  // Filtered providers based on tab & search query
  const displayedProviders = useMemo(() => {
    let base = result.results;
    if (providerFilter === "flagged") base = flaggedList;
    else if (providerFilter === "clean") base = cleanList;
    else if (providerFilter === "no_data") base = noData;
    else base = returned;

    if (providerSearch.trim()) {
      const q = providerSearch.toLowerCase();
      return base.filter((r) => r.source.toLowerCase().includes(q) || (r.provider_summary ?? "").toLowerCase().includes(q));
    }
    return base;
  }, [result.results, providerFilter, flaggedList, cleanList, noData, returned, providerSearch]);

  // Determine if domain-aware technical intelligence exists for the right column
  const enrichment = result.enrichment;
  const isDomainOrUrl = result.ioc_type === "domain" || result.ioc_type === "url";
  const isIp = result.ioc_type === "ipv4" || result.ioc_type === "ipv6";
  // password_sha1 is the type Batch.tsx navigates with for credential rows, so it
  // must be treated as a credential here or its column collapses.
  const isCred = result.ioc_type === "email" || result.ioc_type === "username"
    || result.ioc_type === "password" || result.ioc_type === "password_sha1";
  const isCve = result.ioc_type === "cve";
  const isCrypto = result.ioc_type === "btc" || result.ioc_type === "eth";
  // "Context" indicator types: the backend produces structured enrichment.extra.*
  // data for these (ASN routing, MITRE ATT&CK metadata, host artifacts, file
  // hashes, filenames/paths, user-agents, MACs, fuzzy hashes). They previously
  // had no dedicated card, so their data was only reachable in the Raw Data tab.
  const isContextType = [
    "asn", "mitre_attack", "mutex", "named_pipe", "registry_key", "service_name",
    "filename", "windows_path", "linux_path", "user_agent", "mac",
    "md5", "sha1", "sha256", "ssdeep",
  ].includes(result.ioc_type);

  const spfValue = enrichment?.email_security?.spf;
  const spfConfigured = Boolean(spfValue && spfValue !== "missing");

  const hasTechnicalIntel = Boolean(
    enrichment?.web_preview ||
    enrichment?.whois ||
    (enrichment?.hosting_ip_intel && Object.keys(enrichment.hosting_ip_intel).length > 0) ||
    (enrichment?.subdomains?.subdomains && enrichment.subdomains.subdomains.length > 0) ||
    enrichment?.host_intel ||
    (enrichment?.open_ports && enrichment.open_ports.length > 0) ||
    (enrichment?.abuse_reports && enrichment.abuse_reports.length > 0) ||
    enrichment?.infostealer ||
    enrichment?.breach ||
    enrichment?.email_security ||
    enrichment?.cve ||
    enrichment?.geoip ||
    enrichment?.extra?.bitcoin ||
    enrichment?.extra?.ethereum ||
    hasContextIntel(enrichment?.extra)
  );

  // Indicator types that have a dedicated technical-intelligence module in the
  // right column. For these, we keep the two-column layout and show a small
  // placeholder when no enrichment came back, instead of silently collapsing to
  // a single column (which reads as a broken/empty panel).
  const expectsTechnicalIntel = isDomainOrUrl || isIp || isCred || isCve || isCrypto || isContextType;
  const showRightColumn = hasTechnicalIntel || expectsTechnicalIntel;

  return (
    <div className="space-y-6">
      {/* 1. Header Toolbar */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <span className="relative flex h-2.5 w-2.5">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-accent opacity-75" />
              <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-accent" />
            </span>
            <span className="text-[11px] font-bold uppercase tracking-[0.2em] text-accent">
              Threat Intelligence Console
            </span>
          </div>
          <span className="text-text-secondary/40">/</span>
          <span className="text-xs font-semibold text-text-secondary">Investigation Active</span>
        </div>

        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={() => onNewSearch(result.normalized, rescanType, true)}
            className="flex items-center gap-1.5 rounded-lg border border-accent/40 bg-accent/10 px-3 py-1.5 text-xs font-semibold text-accent hover:bg-accent/20 transition-colors shadow-sm"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            <span>Run Live Re-Scan</span>
          </button>
          <ExportMenu result={result} />
        </div>
      </div>

      {/* Historical Snapshot Notice */}
      {meta?.isHistorical && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-sky-500/30 bg-sky-950/20 px-4 py-3 text-xs text-sky-200 shadow-sm">
          <div className="flex items-center gap-2.5">
            <span className="flex h-2.5 w-2.5 rounded-full bg-sky-400 shadow-[0_0_8px_rgba(56,189,248,0.6)]" />
            <div>
              <span className="font-bold text-sky-100">Historical Snapshot: </span>
              <span className="text-sky-300/80">
                Loaded instant pre-calculated analysis {meta.scannedAt ? `(originally scanned ${new Date(meta.scannedAt).toLocaleString()})` : ""}. No external API keys were billed.
              </span>
            </div>
          </div>
          <button
            type="button"
            onClick={() => onNewSearch(result.normalized, rescanType, true)}
            className="flex items-center gap-1.5 rounded-lg border border-accent bg-accent/20 px-3 py-1.5 text-xs font-bold text-accent hover:bg-accent/30 transition-all shadow-sm"
          >
            <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <polyline points="23 4 23 10 17 10" />
              <polyline points="1 20 1 14 7 14" />
              <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
            </svg>
            <span>Run Live Re-Scan</span>
          </button>
        </div>
      )}

      {/* Batch Inspection Notice */}
      {meta?.fromBatch && (
        <div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-indigo-500/30 bg-indigo-950/20 px-4 py-3 text-xs text-indigo-200 shadow-sm">
          <div className="flex items-center gap-2.5">
            <span className="flex h-2.5 w-2.5 rounded-full bg-indigo-400 shadow-[0_0_8px_rgba(129,140,248,0.6)]" />
            <div>
              <span className="font-bold text-indigo-100">Batch Inspection Record: </span>
              <span className="text-indigo-300/80">
                Loaded multi-provider assessment directly from batch {meta.batchId ? `#${meta.batchId}` : ""}. 0 external API calls made.
              </span>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {meta.batchId && (
              <button
                type="button"
                onClick={() =>
                  window.dispatchEvent(
                    new CustomEvent<NavigateEvent>("navigate", {
                      detail: { page: "lookup", tool: "batch", batchId: meta.batchId },
                    })
                  )
                }
                className="flex items-center gap-1.5 rounded-lg border border-indigo-500/40 bg-indigo-500/15 px-3 py-1.5 text-xs font-semibold text-indigo-200 hover:bg-indigo-500/25 transition-all shadow-sm"
              >
                <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                  <line x1="19" y1="12" x2="5" y2="12" />
                  <polyline points="12 19 5 12 12 5" />
                </svg>
                <span>Back to Batch #{meta.batchId}</span>
              </button>
            )}
            <button
              type="button"
              onClick={() => onNewSearch(result.normalized, rescanType, true)}
              className="flex items-center gap-1.5 rounded-lg border border-accent bg-accent/20 px-3 py-1.5 text-xs font-bold text-accent hover:bg-accent/30 transition-all shadow-sm"
            >
              <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <polyline points="23 4 23 10 17 10" />
                <polyline points="1 20 1 14 7 14" />
                <path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15" />
              </svg>
              <span>Run Live Re-Scan</span>
            </button>
          </div>
        </div>
      )}

      {/* 2. Primary Hero Threat Assessment Banner */}
      <section className="overflow-hidden rounded-2xl border border-border bg-gradient-to-b from-bg-card to-bg-card/90 shadow-[0_20px_50px_rgba(0,0,0,0.35)]">
        {/* Top Indicator Header Bar */}
        <div className="flex flex-wrap items-center justify-between gap-4 border-b border-border bg-bg-secondary/60 px-6 py-4">
          <div className="flex min-w-0 flex-1 flex-wrap items-center gap-3">
            <span className="rounded-lg border border-accent/40 bg-accent/10 px-2.5 py-1 font-mono text-xs font-bold uppercase tracking-wider text-accent shadow-sm">
              {result.ioc_type}
            </span>
            <code className="min-w-0 break-all font-mono text-base font-bold text-text-primary sm:text-xl selection:bg-accent selection:text-black">
              {result.normalized}
            </code>
            <div className="flex items-center gap-1.5">
              <button
                type="button"
                onClick={handleCopyRaw}
                className="rounded border border-border/80 bg-bg-elevated px-2 py-1 text-[11px] font-medium text-text-secondary hover:border-accent hover:text-accent transition-colors"
                title="Copy raw indicator"
              >
                {copiedRaw ? "Copied!" : "Copy"}
              </button>
              <button
                type="button"
                onClick={handleCopyDefanged}
                className="rounded border border-border/80 bg-bg-elevated px-2 py-1 text-[11px] font-medium text-text-secondary hover:border-accent hover:text-accent transition-colors"
                title="Copy defanged (safe for tickets & chats)"
              >
                {copiedDefanged ? "Defanged Copied!" : "Defang"}
              </button>
            </div>
          </div>

          <div className="flex items-center gap-3">
            <VerdictBadge verdict={verdict} size="md" />
          </div>
        </div>

        {/* Hero Metrics & Score Ring */}
        <div className="grid grid-cols-1 gap-6 p-6 lg:grid-cols-12 items-center">
          {/* Left Ring and Primary Assessment */}
          <div className="flex items-center gap-5 lg:col-span-4 border-b border-border/60 pb-5 lg:border-b-0 lg:border-r lg:pb-0 lg:pr-6">
            <div className="shrink-0 drop-shadow-[0_0_15px_rgba(56,189,248,0.2)]">
              <ScoreRing score={Math.max(0, Math.min(100, score))} size={86} />
            </div>
            <div className="min-w-0 flex-1">
              <div className="text-[10px] font-bold uppercase tracking-wider text-text-secondary">
                Threat Verdict
              </div>
              <div className={`mt-0.5 text-2xl font-black uppercase tracking-tight ${
                verdict === "breached" || verdict === "compromised" || verdict.includes("malicious") || verdict === "critical" || verdict === "high"
                  ? "text-rose-400 drop-shadow-[0_0_12px_rgba(244,63,94,0.3)]"
                  : verdict === "not_breached" || verdict === "clean" || verdict === "benign" || verdict === "not_pwned" || verdict === "low"
                  ? "text-emerald-400 drop-shadow-[0_0_12px_rgba(16,185,129,0.3)]"
                  : verdict === "suspicious" || verdict === "medium"
                  ? "text-amber-400"
                  : "text-slate-300"
              }`}>
                {titleCase(verdict)}
              </div>
              <div className="mt-1 flex items-center gap-2 text-xs text-text-secondary">
                <span className="font-semibold text-text-primary">{displayScore}</span>
                <span>·</span>
                <span>{domain ? titleCase(domain) : "Composite Reputation"}</span>
              </div>
            </div>
          </div>

          {/* Key Metrics Grid */}
          <div className="grid grid-cols-2 gap-3 sm:grid-cols-4 lg:col-span-8">
            <StatCard
              label="Confidence"
              value={titleCase(confidence)}
              detail={assessment?.confidence_score != null ? `${Math.round(assessment.confidence_score * 100)}% reliability` : "Calibrated"}
              accent={confidence === "high" ? "text-emerald-400" : confidence === "medium" ? "text-sky-300" : "text-amber-400"}
            />
            <StatCard
              label="Provider Consensus"
              value={`${flaggedCount}/${returned.length}`}
              detail={flaggedCount > 0 ? `${flaggedCount} engines flagged` : "0 detections recorded"}
              accent={flaggedCount > 0 ? "text-red-400" : "text-emerald-400"}
            />
            <StatCard
              label="Engine Coverage"
              value={`${returned.length}/${expected || result.results.length}`}
              detail={`${noData.length} no-data / inactive`}
              accent="text-sky-300"
            />
            <StatCard
              label="Latency & Provenance"
              value={`${analysisSeconds.toFixed(1)}s`}
              detail={result.results.some((r) => r.cached) ? "Cached signals mixed" : "100% Live lookup"}
            />
          </div>
        </div>

        {/* Analyst Executive Guidance Banner */}
        {result.executive_summary && (
          <div className="border-t border-border/80 bg-bg-secondary/40 px-6 py-3.5 text-xs leading-relaxed text-text-secondary flex items-start gap-3">
            <span className="shrink-0 rounded bg-accent/15 px-2 py-0.5 text-[10px] font-bold uppercase tracking-wider text-accent border border-accent/30 mt-0.5">
              Analyst Brief
            </span>
            <p className="text-text-primary/90 font-medium">
              {result.executive_summary}
            </p>
          </div>
        )}
      </section>

      {/* Coverage Limitations / Health Alerts */}
      <CoverageNotice result={result} />

      {/* 3. Global Tab Navigation Bar */}
      <TabBar
        active={tab}
        onChange={setTab}
        badges={{
          Relationships: result.relationships?.length || 0,
          "Raw Data": result.results?.length || 0,
        }}
      />

      {/* 4. Tab Content Panels */}
      <div id="result-panel" role="tabpanel" aria-label={`${tab} results`}>
        {tab === "Investigation" && (
          <div className="space-y-6">
            {/* Global Source Consensus Visual Distribution Bar */}
            <ConsensusBar results={result.results} />

            {/* Unified 2-Column Responsive Workspace */}
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 items-start">
              {/* LEFT COLUMN: Threat Feeds & Provider Consensus */}
              <div className={`space-y-4 ${showRightColumn ? "lg:col-span-7" : "lg:col-span-12"}`}>
                {/* Providers Header & Filter Bar */}
                <div className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
                  <div className="flex flex-wrap items-center justify-between gap-3">
                    <div>
                      <h3 className="text-xs font-bold uppercase tracking-[0.14em] text-text-primary">
                        Provider Threat Intelligence
                      </h3>
                      <p className="mt-0.5 text-[11px] text-text-secondary">
                        Real-time threat feeds, blocklists, and detection engines.
                      </p>
                    </div>

                    <div className="flex items-center gap-2">
                      <input
                        type="text"
                        placeholder="Search provider..."
                        value={providerSearch}
                        onChange={(e) => setProviderSearch(e.target.value)}
                        className="rounded-lg border border-border bg-bg-elevated px-2.5 py-1 text-xs text-text-primary placeholder:text-text-secondary/60 focus:border-accent focus:outline-none w-36 sm:w-44"
                      />
                    </div>
                  </div>

                  {/* Filter Pills */}
                  <div className="flex flex-wrap items-center gap-1.5 border-t border-border/60 pt-3">
                    <button
                      type="button"
                      onClick={() => setProviderFilter("all")}
                      className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors ${
                        providerFilter === "all"
                          ? "bg-accent/15 text-accent border border-accent/40"
                          : "bg-bg-elevated text-text-secondary border border-border/70 hover:text-text-primary"
                      }`}
                    >
                      Active ({returned.length})
                    </button>
                    <button
                      type="button"
                      onClick={() => setProviderFilter("flagged")}
                      className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors flex items-center gap-1.5 ${
                        providerFilter === "flagged"
                          ? "bg-red-500/20 text-red-300 border border-red-500/50"
                          : "bg-bg-elevated text-text-secondary border border-border/70 hover:text-text-primary"
                      }`}
                    >
                      <span className={`h-1.5 w-1.5 rounded-full ${flaggedCount > 0 ? "bg-red-400" : "bg-text-secondary"}`} />
                      Flagged ({flaggedCount})
                    </button>
                    <button
                      type="button"
                      onClick={() => setProviderFilter("clean")}
                      className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors ${
                        providerFilter === "clean"
                          ? "bg-emerald-500/20 text-emerald-300 border border-emerald-500/50"
                          : "bg-bg-elevated text-text-secondary border border-border/70 hover:text-text-primary"
                      }`}
                    >
                      Clean / Benign ({cleanList.length})
                    </button>
                    {noData.length > 0 && (
                      <button
                        type="button"
                        onClick={() => setProviderFilter("no_data")}
                        className={`rounded-lg px-2.5 py-1 text-xs font-semibold transition-colors ${
                          providerFilter === "no_data"
                            ? "bg-slate-500/20 text-slate-300 border border-slate-500/50"
                            : "bg-bg-elevated text-text-secondary border border-border/70 hover:text-text-primary"
                        }`}
                      >
                        No Data ({noData.length})
                      </button>
                    )}
                  </div>
                </div>

                {/* Provider Cards List */}
                {displayedProviders.length > 0 ? (
                  <div className="grid grid-cols-1 gap-3">
                    {displayedProviders.map((item) => (
                      <SourceCard key={item.source} result={item} />
                    ))}
                  </div>
                ) : domain === "credential_exposure" ? (
                  <div className="rounded-xl border border-emerald-500/30 bg-emerald-500/5 p-6 text-center">
                    <h4 className="text-sm font-bold text-emerald-300">✓ Clean Credential Signal</h4>
                    <p className="mt-1 text-xs text-text-secondary">
                      No public exposure records observed in queried threat databases.
                    </p>
                  </div>
                ) : (
                  <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-xs text-text-secondary">
                    No providers match the selected filter.
                  </div>
                )}

                {/* Correlated Malware Indicators (AlienVault OTX / URLhaus) */}
                {Boolean((enrichment?.malware_urls?.length ?? 0) > 0 || (enrichment?.associated_hashes?.length ?? 0) > 0) && (
                  <section className="rounded-xl border border-red-500/30 bg-red-950/10 p-4 space-y-3">
                    <div className="flex items-center justify-between border-b border-red-500/20 pb-2">
                      <div className="flex items-center gap-2">
                        <span className="flex h-5 w-5 items-center justify-center rounded bg-red-500/20 text-red-400">
                          <svg className="w-3.5 h-3.5" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2">
                            <path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z" />
                            <line x1="12" y1="9" x2="12" y2="13" />
                            <line x1="12" y1="17" x2="12.01" y2="17" />
                          </svg>
                        </span>
                        <h4 className="text-xs font-bold uppercase tracking-wider text-red-300">
                          Correlated Malware & C2 Indicators
                        </h4>
                      </div>
                      <span className="text-[10px] text-text-secondary">AlienVault OTX Threat Pulses</span>
                    </div>

                    {enrichment.malware_urls && enrichment.malware_urls.length > 0 && (
                      <div className="space-y-1.5">
                        <span className="text-[11px] font-semibold text-red-400 block">
                          Malicious URLs Observed on Host ({enrichment.malware_urls.length})
                        </span>
                        <div className="max-h-36 overflow-y-auto space-y-1 font-mono text-xs">
                          {enrichment.malware_urls.map((url, i) => (
                            <div
                              key={i}
                              onClick={() => onNewSearch(url, "url")}
                              className="truncate rounded bg-bg-elevated/70 p-2 text-slate-300 border border-border/50 hover:border-accent hover:text-accent cursor-pointer transition-colors"
                              title={`Click to pivot into: ${url}`}
                            >
                              {url}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {enrichment.associated_hashes && enrichment.associated_hashes.length > 0 && (
                      <div className="space-y-1.5 pt-1">
                        <span className="text-[11px] font-semibold text-amber-400 block">
                          Associated Malware Hashes ({enrichment.associated_hashes.length})
                        </span>
                        <div className="flex flex-wrap gap-1.5 font-mono text-xs max-h-32 overflow-y-auto">
                          {enrichment.associated_hashes.map((hash, i) => (
                            <button
                              key={i}
                              type="button"
                              onClick={() => onNewSearch(hash, hashType(hash))}
                              className="rounded bg-bg-elevated px-2 py-1 text-[11px] border border-border/60 text-slate-300 hover:border-accent hover:text-accent transition-colors"
                              title={`Click to pivot into hash: ${hash}`}
                            >
                              {hash.slice(0, 16)}...
                            </button>
                          ))}
                        </div>
                      </div>
                    )}
                  </section>
                )}
              </div>

              {/* RIGHT COLUMN: Domain-Aware Contextual Technical Intelligence */}
              {showRightColumn && (
                <PanelBoundary label="Technical intelligence">
                <div className="space-y-4 lg:col-span-5">
                  {/* Indicator Specific Modules */}

                  {/* DOMAIN / URL INTELLIGENCE */}
                  {isDomainOrUrl && (
                    <>
                      {enrichment?.web_preview && (
                        <WebPreviewCard preview={enrichment.web_preview} domainOrUrl={result.normalized} />
                      )}
                      {enrichment?.whois && (
                        <WhoisCard whois={enrichment.whois} />
                      )}
                      {Boolean(enrichment?.hosting_ip_intel) && (
                        <HostingPivotCard hostingIpIntel={enrichment?.hosting_ip_intel} />
                      )}
                      {enrichment?.subdomains && (
                        <SubdomainsCard subdomainsData={enrichment.subdomains} />
                      )}
                    </>
                  )}

                  {/* IP ADDRESS INTELLIGENCE */}
                  {isIp && (
                    <>
                      {/* Network & Geo Context Widget */}
                      {enrichment?.geoip && (
                        <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
                          <div className="flex items-center justify-between border-b border-border/60 pb-2">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
                              Network & Routing Context
                            </h4>
                            <span className="text-[10px] text-text-secondary">BGP / ASN</span>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
                              <span className="text-[10px] uppercase text-text-secondary block">Country</span>
                              <span className="font-semibold text-text-primary mt-0.5 block truncate">
                                {enrichment.geoip.country || enrichment.geoip.country_code || "—"}
                              </span>
                            </div>
                            <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
                              <span className="text-[10px] uppercase text-text-secondary block">City</span>
                              <span className="font-semibold text-text-primary mt-0.5 block truncate">
                                {enrichment.geoip.city || "—"}
                              </span>
                            </div>
                            <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50 col-span-2">
                              <span className="text-[10px] uppercase text-text-secondary block">ISP / Autonomous System</span>
                              <span className="font-semibold text-text-primary mt-0.5 block truncate">
                                {enrichment.geoip.isp || enrichment.geoip.org || "—"} {enrichment.geoip.asn ? `(${enrichment.geoip.asn})` : ""}
                              </span>
                            </div>
                          </div>
                        </section>
                      )}

                      {/* Shodan Host Vulnerability Matrix */}
                      {(enrichment?.host_intel || (enrichment?.open_ports && enrichment.open_ports.length > 0)) && (
                        <HostVulnerabilityMatrix
                          hostIntel={enrichment?.host_intel}
                          geoip={enrichment?.geoip}
                          legacyPorts={enrichment?.open_ports}
                        />
                      )}

                      {/* AbuseIPDB Reports Timeline */}
                      {enrichment?.abuse_reports && enrichment.abuse_reports.length > 0 && (
                        <AbuseReportsPanel reports={enrichment.abuse_reports} />
                      )}
                    </>
                  )}

                  {/* CREDENTIAL / IDENTITY INTELLIGENCE */}
                  {isCred && (
                    <>
                      {enrichment?.infostealer && (
                        <InfostealerExposureCard infostealer={enrichment.infostealer} domainOrUser={result.normalized} />
                      )}

                      {/* Identity & Breach Exposure Highlight */}
                      {Boolean(enrichment?.breach || enrichment?.email_security) && (
                        <section className="rounded-xl border border-red-500/25 bg-red-950/10 p-4 space-y-3">
                          <div className="flex items-center justify-between border-b border-red-500/20 pb-2">
                            <h4 className="text-xs font-bold uppercase tracking-wider text-red-300">
                              Identity & Exposure Verification
                            </h4>
                            <span className="text-[10px] text-text-secondary">HIBP & XposedOrNot</span>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-xs">
                            <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
                              <span className="text-[10px] uppercase text-text-secondary block">Public Breaches</span>
                              <span className={`font-bold mt-0.5 block ${
                                (enrichment?.breach?.breach_count ?? 0) > 0 ? "text-red-400" : "text-emerald-400"
                              }`}>
                                {enrichment?.breach?.breach_count ?? "0"}
                              </span>
                            </div>
                            <div className="rounded-lg bg-bg-elevated/50 p-2.5 border border-border/50">
                              <span className="text-[10px] uppercase text-text-secondary block">Email Security (SPF)</span>
                              <span className={`font-semibold mt-0.5 block ${
                                spfConfigured ? "text-emerald-400" : "text-amber-400"
                              }`}>
                                {spfConfigured ? spfValue : "Unverified"}
                              </span>
                            </div>
                          </div>
                        </section>
                      )}
                    </>
                  )}

                  {/* CVE / VULNERABILITY INTELLIGENCE */}
                  {isCve && (
                    enrichment?.cve ? (
                    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
                      <div className="flex items-center justify-between border-b border-border/60 pb-2">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
                          CVE Exploitability Context
                        </h4>
                        <span className="text-[10px] text-text-secondary">NVD / NIST</span>
                      </div>
                      <div className="space-y-2 text-xs">
                        {enrichment?.cve?.cvss_score != null && (
                          <div className="flex justify-between border-b border-border/40 pb-1.5">
                            <span className="text-text-secondary">CVSS Score:</span>
                            <span className="font-bold text-red-400">{enrichment.cve.cvss_score} ({enrichment.cve.cvss_severity ?? "N/A"})</span>
                          </div>
                        )}
                        {enrichment?.cve?.epss_score != null && (
                          <div className="flex justify-between border-b border-border/40 pb-1.5">
                            <span className="text-text-secondary">EPSS Exploit Probability:</span>
                            <span className="font-mono text-amber-400">{((enrichment.cve.epss_score as number) * 100).toFixed(2)}%</span>
                          </div>
                        )}
                        {enrichment?.cve?.is_in_kev && (
                          <div className="rounded bg-red-500/15 border border-red-500/30 p-2 text-[11px] text-red-300 font-semibold">
                            ⚠ Known Exploited Vulnerability (CISA KEV) active threat
                          </div>
                        )}
                        {enrichment?.cve?.affected_products && enrichment.cve.affected_products.length > 0 && (
                          <div className="text-[11px] text-text-secondary pt-1">
                            <span className="font-semibold text-text-primary">Affected products:</span>{" "}
                            {enrichment.cve.affected_products.slice(0, 3).join(", ")}
                          </div>
                        )}
                      </div>
                    </section>
                    ) : (
                    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
                      <div className="flex items-center justify-between border-b border-border/60 pb-2">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
                          CVE Exploitability Context
                        </h4>
                        <span className="text-[10px] text-text-secondary">NVD / NIST</span>
                      </div>
                      <p className="text-[11px] text-text-secondary">
                        No CVE enrichment available for this indicator. The verdict above is
                        derived from provider intelligence; CVSS, EPSS, and CISA KEV context
                        could not be retrieved from the vulnerability feeds.
                      </p>
                    </section>
                    )
                  )}

                  {/* CRYPTO WALLET METRICS */}
                  {Boolean(enrichment?.extra?.bitcoin || enrichment?.extra?.ethereum) && (
                    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
                      <div className="flex items-center justify-between border-b border-border/60 pb-2">
                        <h4 className="text-xs font-bold uppercase tracking-wider text-text-primary">
                          On-Chain Ledger Activity
                        </h4>
                        <span className="text-[10px] text-text-secondary">Blockchain Explorer</span>
                      </div>

                      {/* BITCOIN */}
                      {Boolean(enrichment?.extra?.bitcoin) && (() => {
                        const btc = (enrichment?.extra?.bitcoin as Record<string, unknown>) ?? {};
                        const recent = Array.isArray(btc.recent_transactions)
                          ? (btc.recent_transactions as Record<string, unknown>[])
                          : [];
                        return (
                          <div className="space-y-2 text-xs">
                            <div className="flex items-center gap-1.5">
                              <span className="rounded bg-amber-500/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-amber-400 border border-amber-500/30">
                                BTC
                              </span>
                              <span className="text-[10px] text-text-secondary">Bitcoin</span>
                            </div>
                            <div className="space-y-1.5 font-mono">
                              <div className="flex justify-between">
                                <span className="text-text-secondary">Balance:</span>
                                <span className="text-text-primary font-bold">
                                  {fmtMetric(btc.final_balance_btc, "BTC")}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-text-secondary">Transactions:</span>
                                <span className="text-text-primary">{fmtMetric(btc.n_tx)}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-text-secondary">Total Received:</span>
                                <span className="text-emerald-400">{fmtMetric(btc.total_received_btc, "BTC")}</span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-text-secondary">Total Sent:</span>
                                <span className="text-rose-400">{fmtMetric(btc.total_sent_btc, "BTC")}</span>
                              </div>
                            </div>
                            {recent.length > 0 && (
                              <div className="space-y-1 pt-1">
                                <span className="text-[10px] uppercase tracking-wider text-text-secondary block">
                                  Recent Transactions ({recent.length})
                                </span>
                                <div className="max-h-32 overflow-y-auto space-y-1 font-mono text-[11px]">
                                  {recent.map((tx, i) => {
                                    const hash = tx.hash != null ? String(tx.hash) : "";
                                    return (
                                      <div
                                        key={hash || i}
                                        className="flex items-center justify-between gap-2 rounded bg-bg-elevated/60 px-2 py-1 border border-border/50"
                                      >
                                        <span className="truncate text-slate-300" title={hash}>
                                          {hash ? `${hash.slice(0, 18)}…` : "—"}
                                        </span>
                                        <span className="shrink-0 text-text-secondary">
                                          {fmtMetric(tx.result_btc, "BTC")}
                                        </span>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })()}

                      {/* ETHEREUM */}
                      {Boolean(enrichment?.extra?.ethereum) && (() => {
                        const eth = (enrichment?.extra?.ethereum as Record<string, unknown>) ?? {};
                        const recent = Array.isArray(eth.recent_transactions)
                          ? (eth.recent_transactions as Record<string, unknown>[])
                          : [];
                        return (
                          <div className={`space-y-2 text-xs ${enrichment?.extra?.bitcoin ? "border-t border-border/40 pt-3" : ""}`}>
                            <div className="flex items-center gap-1.5">
                              <span className="rounded bg-indigo-500/15 px-1.5 py-0.5 text-[10px] font-bold uppercase tracking-wider text-indigo-300 border border-indigo-500/30">
                                ETH
                              </span>
                              <span className="text-[10px] text-text-secondary">Ethereum</span>
                            </div>
                            <div className="space-y-1.5 font-mono">
                              <div className="flex justify-between">
                                <span className="text-text-secondary">Balance:</span>
                                <span className="text-text-primary font-bold">
                                  {fmtMetric(eth.balance_eth, "ETH")}
                                </span>
                              </div>
                              <div className="flex justify-between">
                                <span className="text-text-secondary">Transactions:</span>
                                <span className="text-text-primary">{fmtMetric(eth.transaction_count)}</span>
                              </div>
                            </div>
                            {recent.length > 0 && (
                              <div className="space-y-1 pt-1">
                                <span className="text-[10px] uppercase tracking-wider text-text-secondary block">
                                  Recent Transactions ({recent.length})
                                </span>
                                <div className="max-h-32 overflow-y-auto space-y-1 font-mono text-[11px]">
                                  {recent.map((tx, i) => {
                                    const hash = tx.hash != null ? String(tx.hash) : "";
                                    return (
                                      <div
                                        key={hash || i}
                                        className="flex items-center justify-between gap-2 rounded bg-bg-elevated/60 px-2 py-1 border border-border/50"
                                      >
                                        <span className="truncate text-slate-300" title={hash}>
                                          {hash ? `${hash.slice(0, 18)}…` : "—"}
                                        </span>
                                        <span className="shrink-0 text-text-secondary">
                                          {fmtMetric(tx.value_eth, "ETH")}
                                        </span>
                                      </div>
                                    );
                                  })}
                                </div>
                              </div>
                            )}
                          </div>
                        );
                      })()}
                    </section>
                  )}

                  {/* Fallback WHOIS if not rendered yet */}
                  {!isDomainOrUrl && enrichment?.whois && (
                    <WhoisCard whois={enrichment.whois} />
                  )}

                  {/* CONTEXT INDICATOR INTELLIGENCE: ASN, MITRE ATT&CK, host
                      artifacts, file hashes, filenames/paths, user-agents, MACs
                      and fuzzy hashes. These render inline so structured data is
                      never buried in the Raw Data tab. */}
                  <ContextIntelCard extra={enrichment?.extra} />

                  {/* No-data placeholder: column is shown because this indicator
                      type has technical modules, but no enrichment was returned. */}
                  {!hasTechnicalIntel && (
                    <section className="rounded-xl border border-dashed border-border bg-bg-card/50 p-6 text-center">
                      <h4 className="text-xs font-bold uppercase tracking-wider text-text-secondary">
                        Technical Intelligence
                      </h4>
                      <p className="mt-2 text-[11px] leading-relaxed text-text-secondary">
                        No technical intelligence available for this indicator. Enrichment
                        providers returned no infrastructure, on-chain, or contextual data —
                        the assessment above is based on provider reputation signals.
                      </p>
                    </section>
                  )}
                </div>
                </PanelBoundary>
              )}
            </div>
          </div>
        )}

        {/* Dedicated Deep-Dive Tabs */}
        {tab === "Enrichment" && (
          <PanelBoundary label="Enrichment">
            <EnrichmentPanel enrichment={result.enrichment} iocType={result.ioc_type} />
          </PanelBoundary>
        )}

        {tab === "Evidence" && (
          <PanelBoundary label="Evidence">
            <EvidencePanel result={result} />
          </PanelBoundary>
        )}

        {tab === "Raw Data" && (
          <PanelBoundary label="Raw data">
            <RawDataView results={result.results} />
          </PanelBoundary>
        )}

        {tab === "Relationships" && (
          result.relationships && result.relationships.length > 0 ? (
            <PanelBoundary label="Relationship graph">
              <RelationshipGraph
                mainIoc={result.normalized}
                relationships={result.relationships}
                onNodeClick={handleNodeClick}
              />
            </PanelBoundary>
          ) : (
            <div className="rounded-xl border border-border bg-bg-card p-12 text-center text-xs text-text-secondary">
              No graph relationships discovered for this indicator.
            </div>
          )
        )}

        {tab === "Export" && (
          <PanelBoundary label="Export">
            <ExportTab result={result} />
          </PanelBoundary>
        )}
      </div>

      {/* Analyst Feedback Loop (Ground Truth Reporting) */}
      <div className="border-t border-border/80 pt-5">
        <FeedbackWidget ioc={result.normalized} />
      </div>
    </div>
  );
}
