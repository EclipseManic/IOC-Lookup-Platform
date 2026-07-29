import type { LookupResponse } from "../services/api";
import ScoreRing from "./ScoreRing";
import VerdictBadge from "./VerdictBadge";

export default function ThreatHeader({ result }: { result: LookupResponse }) {
  const { composite, ioc_type, normalized } = result;
  const confidenceColor =
    composite.confidence === "high" ? "text-green-400" :
    composite.confidence === "medium" ? "text-amber-400" : "text-gray-400";

  return (
    <div className="bg-bg-card border border-border rounded-lg p-5 flex items-center gap-5">
      <ScoreRing score={composite.score} size={80} />
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-mono px-2 py-0.5 bg-bg-elevated rounded text-text-secondary uppercase">
            {ioc_type}
          </span>
          <VerdictBadge verdict={composite.verdict} size="md" />
          <span className={`text-xs ${confidenceColor}`}>({composite.confidence})</span>
        </div>
        <p className="font-mono text-lg break-all">{normalized}</p>
        <p className="text-xs text-text-secondary mt-0.5">
          {result.results.length} sources · {composite.sources_contributing} contributing
        </p>
      </div>
    </div>
  );
}
