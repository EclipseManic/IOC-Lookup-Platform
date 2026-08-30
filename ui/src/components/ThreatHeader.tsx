import { useState } from "react";
import type { LookupResponse } from "../services/api";
import ScoreRing from "./ScoreRing";
import VerdictBadge from "./VerdictBadge";

export default function ThreatHeader({ result }: { result: LookupResponse }) {
  const { composite, ioc_type, normalized } = result;
  const assessment = result.final_assessment;
  const domain = assessment?.assessment_domain || "ioc_reputation";
  const isReputation = domain === "ioc_reputation";
  const verdict = assessment?.final_verdict || composite.verdict;
  const score = assessment?.normalized_score ?? composite.score;
  const confidence = assessment?.confidence || composite.confidence;
  const [copied, setCopied] = useState(false);
  const confidenceColor =
    confidence === "high" ? "text-green-400" :
    confidence === "medium" ? "text-amber-400" : "text-gray-400";

  const copyIoc = async () => {
    try {
      await navigator.clipboard.writeText(normalized);
      setCopied(true);
      setTimeout(() => setCopied(false), 1500);
    } catch {
      // Clipboard unavailable; ignore.
    }
  };

  return (
    <div className="bg-bg-card border border-border rounded-lg p-5 flex items-center gap-5">
      {isReputation ? (
        <ScoreRing score={score} size={80} />
      ) : (
        <div className="flex h-20 w-20 shrink-0 flex-col items-center justify-center rounded-full border border-border bg-bg-elevated text-center">
          <span className="text-[10px] uppercase tracking-wider text-text-secondary">{domain.replace(/_/g, " ")}</span>
          <span className="mt-1 text-xs font-semibold text-text-primary">typed assessment</span>
        </div>
      )}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 mb-1">
          <span className="text-xs font-mono px-2 py-0.5 bg-bg-elevated rounded text-text-secondary uppercase">
            {ioc_type}
          </span>
          {!isReputation && <span className="text-xs text-text-secondary">{domain.replace(/_/g, " ")}</span>}
          <VerdictBadge verdict={verdict} size="md" />
          <span className={`text-xs ${confidenceColor}`}>({confidence})</span>
        </div>
        <div className="flex items-center gap-2 min-w-0">
          <p className="font-mono text-lg break-all">{normalized}</p>
          <button
            onClick={copyIoc}
            aria-label="Copy IOC value"
            title="Copy IOC value"
            className="shrink-0 text-text-secondary hover:text-accent transition-colors"
          >
            {copied ? (
              <svg className="w-4 h-4 text-verdict-clean" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M5 13l4 4L19 7" />
              </svg>
            ) : (
              <svg className="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" aria-hidden="true">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M8 5H6a2 2 0 00-2 2v12a2 2 0 002 2h10a2 2 0 002-2v-1M8 5a2 2 0 002 2h2a2 2 0 002-2M8 5a2 2 0 012-2h2a2 2 0 012 2m0 0h2a2 2 0 012 2v3" />
              </svg>
            )}
          </button>
        </div>
        <p className="text-xs text-text-secondary mt-0.5">
          {result.results.length} sources · {composite.sources_contributing} contributing
        </p>
        {isReputation && (composite.malicious_sources ?? 0) + (composite.suspicious_sources ?? 0) + (composite.clean_sources ?? 0) > 0 && (
          <p className="text-xs text-text-secondary mt-0.5">
            Source votes: <span className="text-verdict-malicious">{composite.malicious_sources ?? 0} malicious</span> · <span className="text-verdict-suspicious">{composite.suspicious_sources ?? 0} suspicious</span> · <span className="text-verdict-clean">{composite.clean_sources ?? 0} clean</span>
            {typeof composite.agreement === "number" && (
              <> · agreement {Math.round(composite.agreement * 100)}%</>
            )}
          </p>
        )}
      </div>
    </div>
  );
}
