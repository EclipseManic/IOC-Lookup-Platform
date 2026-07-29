import { useCallback, useEffect, useRef } from "react";
import { useLookup } from "../hooks/useLookup";
import PipelineProgress from "../components/PipelineProgress";
import SearchBar from "../components/SearchBar";
import { SkeletonHeader, SkeletonSourceGrid } from "../components/LoadingSkeleton";
import type { LookupResponse } from "../services/api";
import ResultView from "./ResultView";

export default function HomePage({ initialValue = "" }: { initialValue?: string }) {
  const { state, submit, reset } = useLookup();
  const hasSubmitted = useRef(false);

  useEffect(() => {
    if (initialValue && !hasSubmitted.current) {
      hasSubmitted.current = true;
      submit(initialValue);
    }
  }, [initialValue, submit]);

  const handleSearch = useCallback((value: string) => {
    submit(value);
  }, [submit]);

  return (
    <div>
      <div className="text-center py-12">
        <h1 className="text-4xl font-bold mb-2">Threat Intelligence Lookup</h1>
        <p className="text-text-secondary">Search IPs, domains, URLs, hashes, emails, or CVEs</p>
      </div>

      <div className="max-w-2xl mx-auto mb-8">
        <SearchBar onSearch={handleSearch} initialValue={initialValue} />
      </div>

      <div className="max-w-4xl mx-auto" aria-live="polite" aria-label="Lookup results">
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
            <button onClick={reset} className="mt-3 px-4 py-1.5 text-sm bg-accent text-white rounded-lg hover:bg-accent/90 transition-colors">
              Try Again
            </button>
          </div>
        )}

        {state.status === "done" && (
          <ResultView result={state.result as LookupResponse} onNewSearch={(v) => { submit(v); }} />
        )}
      </div>
    </div>
  );
}
