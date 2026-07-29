import { useEffect, useState } from "react";

interface HistoryItem {
  id: number;
  value: string;
  ioc_type: string;
  verdict: string | null;
  score: number | null;
  confidence: string | null;
  created_at: string | null;
}

export default function History() {
  const [items, setItems] = useState<HistoryItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState("");
  const [typeFilter, setTypeFilter] = useState("");

  function load() {
    setLoading(true);
    fetch("/api/recent")
      .then(r => r.json())
      .then(data => setItems(data))
      .catch(() => setItems([]))
      .finally(() => setLoading(false));
  }

  useEffect(load, []);

  function clearAll() {
    Promise.all(items.map(i =>
      fetch(`/api/recent/${i.id}`, { method: "DELETE" })
    )).finally(load);
  }

  function deleteItem(id: number, e: React.MouseEvent) {
    e.stopPropagation();
    fetch(`/api/recent/${id}`, { method: "DELETE" }).finally(load);
  }

  const types = [...new Set(items.map(i => i.ioc_type))].sort();
  const filtered = items.filter(i => {
    if (filter && !i.value.toLowerCase().includes(filter.toLowerCase())) return false;
    if (typeFilter && i.ioc_type !== typeFilter) return false;
    return true;
  });

  if (loading) {
    return <div className="text-center py-16 text-text-secondary">Loading...</div>;
  }

  if (items.length === 0) {
    return (
      <div className="text-center py-16 text-text-secondary">
        <h2 className="text-2xl font-bold mb-2">History</h2>
        <p>No lookup history yet. Search for an IOC to get started.</p>
      </div>
    );
  }

  return (
    <div className="page-enter">
      <div className="flex items-center justify-between mb-4">
        <h2 className="text-lg font-bold">Lookup History</h2>
        <button
          onClick={clearAll}
          className="text-xs px-3 py-1.5 bg-bg-elevated border border-border rounded-md text-text-secondary hover:text-text-primary transition-colors"
        >
          Clear All
        </button>
      </div>

      <div className="flex gap-3 mb-4">
        <input
          type="text"
          placeholder="Filter by IOC value..."
          value={filter}
          onChange={e => setFilter(e.target.value)}
          className="flex-1 px-3 py-1.5 bg-bg-card border border-border rounded-lg text-sm text-text-primary placeholder:text-text-secondary/50 focus:outline-none focus:border-accent"
          aria-label="Filter by IOC value"
        />
        <select
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value)}
          className="px-3 py-1.5 bg-bg-card border border-border rounded-lg text-sm text-text-primary focus:outline-none focus:border-accent"
          aria-label="Filter by IOC type"
        >
          <option value="">All types</option>
          {types.map(t => (
            <option key={t} value={t}>{t}</option>
          ))}
        </select>
      </div>

      <div className="space-y-2">
        {filtered.map(item => (
          <div
            key={item.id}
            onClick={() => { window.dispatchEvent(new CustomEvent("navigate", { detail: { page: "home", ioc: item.value } })); }}
            className="flex items-center gap-3 px-4 py-2.5 bg-bg-card border border-border rounded-lg hover:bg-bg-elevated transition-colors cursor-pointer"
          >
            <div className="flex-1 min-w-0">
              <div className="font-mono text-xs truncate">{item.value}</div>
              <div className="flex items-center gap-2 mt-1">
                <span className="text-[10px] font-mono px-1.5 py-0.5 bg-bg-elevated rounded text-text-secondary uppercase">
                  {item.ioc_type}
                </span>
                {item.score !== null && (
                  <span className="text-xs text-text-secondary">Score: {item.score.toFixed(0)}</span>
                )}
              </div>
            </div>

            <div className="flex items-center gap-3">
              {item.verdict && (
                <span className={
                  "text-xs font-medium px-2 py-0.5 rounded " +
                  (item.verdict === "malicious" ? "text-verdict-malicious bg-verdict-malicious/10" :
                   item.verdict === "suspicious" ? "text-verdict-suspicious bg-verdict-suspicious/10" :
                   item.verdict === "clean" ? "text-verdict-clean bg-verdict-clean/10" :
                   "text-verdict-unknown bg-verdict-unknown/10")
                }>
                  {item.verdict}
                </span>
              )}
              {item.created_at && (
                <span className="text-xs text-text-secondary hidden sm:block whitespace-nowrap">
                  {new Date(item.created_at).toLocaleString()}
                </span>
              )}
              <button
                onClick={e => deleteItem(item.id, e)}
                className="text-text-secondary hover:text-red-400 transition-colors p-1"
                title="Delete"
                aria-label={`Delete ${item.value}`}
              >
                <svg className="w-3.5 h-3.5" fill="none" viewBox="0 0 24 24" stroke="currentColor">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16" />
                </svg>
              </button>
            </div>
          </div>
        ))}
      </div>

      {filtered.length === 0 && (
        <div className="text-center py-12 text-text-secondary">No matching entries.</div>
      )}
    </div>
  );
}
