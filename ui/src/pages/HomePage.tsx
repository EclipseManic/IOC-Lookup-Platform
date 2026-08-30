import { useCallback, useEffect, useRef, useState } from "react";
import { useLookup } from "../hooks/useLookup";
import PipelineProgress from "../components/PipelineProgress";
import SearchBar from "../components/SearchBar";
import { SkeletonHeader, SkeletonSourceGrid } from "../components/LoadingSkeleton";
import { getKeyHealth, type KeyHealthResponse, type LookupResponse } from "../services/api";
import type { Tool } from "../App";
import ResultView from "./ResultView";
import SourceCoveragePanel from "../components/SourceCoveragePanel";
import PrivacyNotice from "../components/PrivacyNotice";
import History from "./History";
import Investigations from "./Investigations";
import Batch from "./Batch";

export default function HomePage({ initialValue = "", tool = null, initialBatchId = "" }: { initialValue?: string; tool?: Tool | null; initialBatchId?: string }) {
  const { state, submit, reset } = useLookup();
  const submittedRef = useRef<string | null>(null);
  const [keyHealth, setKeyHealth] = useState<KeyHealthResponse | null>(null);

  useEffect(() => {
    if (tool) return;
    getKeyHealth().then(setKeyHealth).catch(() => undefined);
  }, [tool]);

  useEffect(() => {
    if (initialValue && !tool && submittedRef.current !== initialValue) {
      submittedRef.current = initialValue;
      submit(initialValue);
    }
  }, [initialValue, tool, submit]);

  const handleSearch = useCallback((value: string, iocType?: string) => {
    submittedRef.current = value;
    submit(value, iocType);
    window.dispatchEvent(new CustomEvent("ioc-sync", { detail: { value } }));
  }, [submit]);

  const panelId = tool ? `panel-${tool}` : "panel-lookup";

  if (tool) {
    return (
      <div id={panelId} role="tabpanel" aria-labelledby={`tab-tool-${tool}`} tabIndex={-1} className="page-enter outline-none">
        {tool === "investigations" && <Investigations />}
        {tool === "batch" && <Batch initialBatchId={initialBatchId} />}
        {tool === "history" && <History />}
      </div>
    );
  }

  return (
    <div id={panelId} role="tabpanel" aria-labelledby="tab-tool-lookup" tabIndex={-1} className="page-enter outline-none">
      <div className="flex items-center justify-between gap-4 pb-5 border-b border-border">
        <div>
          <h2 className="text-2xl font-extrabold tracking-tight text-text-primary">Indicator Lookup</h2>
          <p className="text-sm text-text-secondary mt-0.5">Search IPs, domains, URLs, hashes, emails, or CVEs — 20+ sources in one pass</p>
        </div>
        <div className="hidden items-center gap-3 md:flex">
          <div className="flex items-center gap-2 rounded-lg border border-border bg-bg-card px-3 py-2 text-xs font-medium text-text-secondary"><span className="status-dot" aria-hidden="true" /><span>Systems online</span></div>
          {keyHealth && <div className="rounded-lg border border-sky-500/25 bg-sky-500/5 px-3 py-2 text-xs text-sky-200" title={keyHealth.missing_keys.length ? `Missing: ${keyHealth.missing_keys.join(", ")}` : "All configured providers are active"}><span className="font-semibold">API coverage</span><span className="ml-2 font-mono">{keyHealth.active_providers}/{keyHealth.total_providers}</span></div>}
        </div>
      </div>

      <div className="max-w-3xl mx-auto mt-8 mb-8">
        <SearchBar onSearch={handleSearch} initialValue={initialValue} disabled={state.status === "loading"} />
      </div>

      <div className="max-w-6xl mx-auto" aria-live="polite" aria-label="Lookup results">
        {state.status === "idle" && (
          <div className="flex flex-col items-center justify-center py-16 text-center text-text-secondary">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5" className="w-12 h-12 mb-4" aria-hidden="true">
              <circle cx="11" cy="11" r="7" />
              <path d="M21 21l-4.3-4.3" strokeLinecap="round" />
            </svg>
            <h3 className="text-lg font-bold text-text-secondary mb-1.5">No indicators analyzed yet</h3>
            <p className="text-sm">Enter an IOC above to begin triage across 20+ threat-intel sources.</p>
          </div>
        )}

        {state.status === "loading" && (
          <div className="space-y-6">
            <PipelineProgress stages={state.stages} progress={state.progress} />
            <SkeletonHeader />
            <SkeletonSourceGrid />
          </div>
        )}

        {state.status === "error" && (
          <div className="bg-verdict-malicious/10 border border-verdict-malicious/30 rounded-lg p-4 text-center">
            <p className="text-verdict-malicious font-medium mb-2">Error</p>
            <p className="text-sm text-text-secondary">{state.error}</p>
            <button onClick={reset} className="mt-3 px-4 py-1.5 text-sm bg-accent text-[#06070d] rounded-lg hover:bg-accent/90 transition-colors">
              Try Again
            </button>
          </div>
        )}

        {state.status === "done" && (
          <ResultView result={state.result as LookupResponse} onNewSearch={(v, type, refresh) => { submit(v, type, refresh); }} />
        )}
      </div>

      <div className="max-w-6xl mx-auto mt-8 space-y-4">
        <PrivacyNotice />
        <SourceCoveragePanel />
      </div>
    </div>
  );
}
