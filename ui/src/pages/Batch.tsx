import { useCallback, useEffect, useRef, useState } from "react";
import { showToast } from "../components/Toast";
import {
  getBatchResult,
  getBatchStatus,
  startBatch,
  uploadBatchFile,
  type BatchResult,
  type BatchStatus,
} from "../services/api";

const VERDICT_COLORS: Record<string, string> = {
  malicious: "#ef4444",
  suspicious: "#f59e0b",
  clean: "#22c55e",
  unknown: "#6b7280",
  error: "#ef4444",
};

function VerdictDonut({ summary }: { summary: BatchResult["summary"] }) {
  const total = Object.values(summary).reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  let offset = 0;
  const slices = Object.entries(summary).filter(([_, v]) => v > 0);
  const r = 50;
  const circ = 2 * Math.PI * r;
  return (
    <div className="flex items-center gap-6">
      <div className="relative w-32 h-32 shrink-0">
        <svg viewBox="0 0 120 120" className="w-32 h-32 -rotate-90">
          {slices.map(([verdict, count]) => {
            const pct = count / total;
            const dash = pct * circ;
            offset += dash;
            return (
              <circle
                key={verdict}
                cx="60" cy="60" r={r} fill="none"
                stroke={VERDICT_COLORS[verdict] || "#6b7280"}
                strokeWidth="12"
                strokeDasharray={`${dash} ${circ - dash}`}
                strokeDashoffset={circ - offset + dash}
                strokeLinecap="butt"
              />
            );
          })}
        </svg>
        <span className="absolute inset-0 flex items-center justify-center text-lg font-bold font-mono">{total}</span>
      </div>
      <div className="space-y-1.5">
        {slices.map(([verdict, count]) => (
          <div key={verdict} className="flex items-center gap-2 text-sm">
            <span className="w-3 h-3 rounded-sm" style={{ backgroundColor: VERDICT_COLORS[verdict] || "#6b7280" }} />
            <span className="text-text-secondary w-20">{verdict}</span>
            <span className="font-mono">{count}</span>
            <span className="text-text-secondary text-xs">({(count / total * 100).toFixed(0)}%)</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function IOCResultCard({ item }: { item: any }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div className="bg-bg-card border border-border rounded-lg overflow-hidden">
      <button
        onClick={() => setExpanded(!expanded)}
        className="w-full flex items-center justify-between p-3 hover:bg-bg-elevated/50 transition-colors text-left"
      >
        <div className="flex items-center gap-2 min-w-0">
          <span className="font-mono text-sm truncate">{item._ioc || item.ioc}</span>
          <span className="text-[10px] px-1.5 py-0.5 bg-bg-elevated rounded text-text-secondary uppercase">{item.ioc_type}</span>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={item.verdict === "malicious" ? "text-verdict-malicious" : item.verdict === "suspicious" ? "text-verdict-suspicious" : item.verdict === "clean" ? "text-verdict-clean" : "text-verdict-unknown"}>
            {item.verdict}
          </span>
          <svg className={`w-3 h-3 text-text-secondary transition-transform ${expanded ? "rotate-180" : ""}`} fill="none" viewBox="0 0 24 24" stroke="currentColor">
            <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
          </svg>
        </div>
      </button>
      {expanded && (
        <div className="px-3 pb-3 space-y-1 border-t border-border pt-2">
          <div className="text-xs text-text-secondary">Source: <span className="text-text-primary">{item.source}</span></div>
          {item.raw_score !== null && <div className="text-xs text-text-secondary">Score: <span className="text-text-primary">{(item.raw_score * 100).toFixed(0)}</span></div>}
          {item.tags?.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {item.tags.map((t: string) => (
                <span key={t} className="text-[10px] px-1.5 py-0.5 bg-bg-elevated rounded text-text-secondary">{t}</span>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

export default function Batch() {
  const [iocs, setIocs] = useState("");
  const [batchId, setBatchId] = useState<string | null>(null);
  const [status, setStatus] = useState<BatchStatus | null>(null);
  const [result, setResult] = useState<BatchResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [dragOver, setDragOver] = useState(false);
  const pollingRef = useRef<number | null>(null);

  const stopPolling = useCallback(() => {
    if (pollingRef.current !== null) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  useEffect(() => {
    return stopPolling;
  }, [stopPolling]);

  async function pollBatch(bid: string) {
    stopPolling();
    const interval = window.setInterval(async () => {
      try {
        const s = await getBatchStatus(bid);
        setStatus(s);
        if (s.status === "done") {
          stopPolling();
          const r = await getBatchResult(bid);
          setResult(r);
          setLoading(false);
          showToast(`Batch complete: ${r.completed}/${r.total} IOCs`, "success");
        }
      } catch {
        stopPolling();
        setLoading(false);
        showToast("Batch polling failed", "error");
      }
    }, 1000);
    pollingRef.current = interval;
  }

  async function handleSubmit() {
    const list = iocs.split("\n").map((s) => s.trim()).filter(Boolean);
    if (list.length === 0) { showToast("Enter at least one IOC", "error"); return; }
    if (list.length > 100) { showToast("Maximum 100 IOCs", "error"); return; }
    setLoading(true);
    setBatchId(null);
    setStatus(null);
    setResult(null);
    try {
      const { batch_id } = await startBatch(list);
      setBatchId(batch_id);
      await pollBatch(batch_id);
    } catch (e: any) {
      showToast(e.message, "error");
      setLoading(false);
    }
  }

  async function handleFileUpload(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setLoading(true);
    setBatchId(null);
    setStatus(null);
    setResult(null);
    try {
      const { batch_id } = await uploadBatchFile(file);
      setBatchId(batch_id);
      await pollBatch(batch_id);
    } catch (e: any) {
      showToast(e.message, "error");
      setLoading(false);
    }
  }

  const list = iocs.split("\n").map((s) => s.trim()).filter(Boolean);
  const overLimit = list.length > 100;

  return (
    <div>
      <div className="mb-6">
        <h2 className="text-lg font-bold">Batch Processing</h2>
        <p className="text-sm text-text-secondary">Analyze up to 100 IOCs at once. Paste IOCs or upload a CSV/JSON file.</p>
      </div>

      {!batchId && (
        <div className="space-y-4">
          <div className="flex gap-4">
            <label
              className={`flex-1 flex flex-col items-center justify-center h-32 border-2 border-dashed rounded-lg cursor-pointer transition-colors ${
                dragOver ? "border-accent bg-accent/5" : "border-border hover:border-accent/50"
              }`}
              onDragOver={(e) => { e.preventDefault(); setDragOver(true); }}
              onDragLeave={() => setDragOver(false)}
              onDrop={(e) => {
                e.preventDefault();
                setDragOver(false);
                const f = e.dataTransfer.files?.[0];
                if (f) {
                  const input = document.createElement("input");
                  input.type = "file";
                  const dt = new DataTransfer();
                  dt.items.add(f);
                  input.files = dt.files;
                  const evt = { target: { files: dt.files } } as any;
                  handleFileUpload(evt);
                }
              }}
            >
              <svg className="w-8 h-8 text-text-secondary mb-2" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={1.5} d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12" />
              </svg>
              <span className="text-xs text-text-secondary">Drop CSV/JSON file or click to browse</span>
              <input type="file" accept=".csv,.json,.txt" onChange={handleFileUpload} className="hidden" />
            </label>
          </div>

          <div>
            <textarea
              value={iocs}
              onChange={(e) => setIocs(e.target.value)}
              placeholder="Paste IOCs here, one per line&#10;e.g.&#10;8.8.8.8&#10;example.com&#10;d41d8cd98f00b204e9800998ecf8427e"
              className="w-full h-40 px-4 py-3 bg-bg-card border border-border rounded-lg text-text-primary placeholder-text-secondary outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all font-mono text-sm resize-y"
              disabled={loading}
            />
            <div className="flex items-center justify-between mt-2">
              <span className={`text-xs font-mono ${overLimit ? "text-verdict-malicious" : "text-text-secondary"}`}>
                {list.length} IOC{list.length !== 1 ? "s" : ""}{overLimit ? " (max 100)" : ""}
              </span>
              <button
                onClick={handleSubmit}
                disabled={loading || list.length === 0 || overLimit}
                className="px-5 py-2 bg-accent text-white text-sm rounded-lg hover:bg-accent/90 disabled:opacity-40 disabled:cursor-not-allowed transition-colors font-medium"
              >
                {loading ? "Starting..." : "Analyze Batch"}
              </button>
            </div>
          </div>
        </div>
      )}

      {status && !result && (
        <div className="bg-bg-card border border-border rounded-lg p-6 text-center">
          <div
            role="progressbar"
            aria-label="Batch progress"
            aria-valuemin={0}
            aria-valuemax={100}
            aria-valuenow={Math.round(status.progress)}
            className="w-full bg-bg-elevated rounded-full h-2 mb-4"
          >
            <div className="h-2 rounded-full bg-gradient-to-r from-accent to-accent-secondary transition-all duration-500" style={{ width: `${status.progress}%` }} />
          </div>
          <p className="text-sm text-text-secondary">
            Processing {status.completed}/{status.total} IOCs...
          </p>
          <p className="text-xs text-text-secondary mt-1">{status.progress.toFixed(0)}% complete</p>
        </div>
      )}

      {result && (
        <div className="space-y-6">
          <div className="bg-bg-card border border-border rounded-lg p-5">
            <h3 className="text-sm font-semibold mb-4 text-text-secondary uppercase tracking-wider">Results Summary</h3>
            <VerdictDonut summary={result.summary} />
            <div className="mt-4 flex gap-2">
              <button
                onClick={() => {
                  const blob = new Blob([JSON.stringify(result, null, 2)], { type: "application/json" });
                  const url = URL.createObjectURL(blob);
                  const a = document.createElement("a");
                  a.href = url; a.download = "batch-results.json"; a.click();
                  URL.revokeObjectURL(url);
                }}
                className="px-3 py-1.5 text-xs bg-accent text-white rounded-md hover:bg-accent/90 transition-colors"
              >
                Download JSON
              </button>
              <button
                onClick={() => {
                  setIocs("");
                  setBatchId(null);
                  setStatus(null);
                  setResult(null);
                }}
                className="px-3 py-1.5 text-xs bg-bg-elevated border border-border rounded-md text-text-secondary hover:text-text-primary transition-colors"
              >
                New Batch
              </button>
            </div>
          </div>

          <div>
            <h3 className="text-sm font-semibold mb-3 text-text-secondary uppercase tracking-wider">Per-IOC Results</h3>
            <div className="space-y-2">
              {result.results.map((item, i) => (
                <IOCResultCard key={i} item={item} />
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  );
}
