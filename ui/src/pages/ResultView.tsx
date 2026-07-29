import { useCallback, useState } from "react";
import type { LookupResponse } from "../services/api";
import ConsensusBar from "../components/ConsensusBar";
import EnrichmentPanel from "../components/EnrichmentPanel";
import ExportMenu, { ExportTab } from "../components/ExportMenu";
import RelationshipGraph from "../components/RelationshipGraph";
import SearchBar from "../components/SearchBar";
import SourceCard from "../components/SourceCard";
import TabBar from "../components/TabBar";
import type { TabName } from "../components/TabBar";
import ThreatHeader from "../components/ThreatHeader";

export default function ResultView({ result, onNewSearch }: { result: LookupResponse; onNewSearch: (v: string) => void }) {
  const [tab, setTab] = useState<TabName>("Overview");

  const handleNodeClick = useCallback((value: string) => {
    onNewSearch(value);
  }, [onNewSearch]);

  return (
    <div className="space-y-4">
      <SearchBar onSearch={onNewSearch} initialValue={result.input} />

      <div className="flex items-center justify-between">
        <h2 className="text-lg font-bold">Analysis Results</h2>
        <ExportMenu result={result} />
      </div>

      <ThreatHeader result={result} />
      <ConsensusBar results={result.results} />
      <TabBar active={tab} onChange={setTab} />

      {tab === "Overview" && (
        <div className="space-y-4">
          {result.executive_summary && (
            <div className="bg-bg-card border border-border rounded-lg p-4">
              <h3 className="text-sm font-semibold mb-2 text-text-secondary uppercase tracking-wider">Executive Summary</h3>
              <p className="text-sm leading-relaxed">{result.executive_summary}</p>
            </div>
          )}
          <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
            {result.results.filter((r) => r.source !== "CVE").map((r) => (
              <SourceCard key={r.source} result={r} />
            ))}
          </div>
        </div>
      )}

      {tab === "Sources" && (
        <div className="space-y-2">
          {result.results.map((r) => (
            <SourceCard key={r.source} result={r} />
          ))}
        </div>
      )}

      {tab === "Enrichment" && result.enrichment && (
        <EnrichmentPanel enrichment={result.enrichment} />
      )}

      {tab === "Relationships" && (
        result.relationships && result.relationships.length > 0 ? (
          <RelationshipGraph mainIoc={result.normalized} relationships={result.relationships} onNodeClick={handleNodeClick} />
        ) : (
          <div className="bg-bg-card border border-border rounded-lg p-8 text-center text-text-secondary text-sm">
            No relationships found for this IOC.
          </div>
        )
      )}

      {tab === "Export" && (
        <ExportTab result={result} />
      )}
    </div>
  );
}
