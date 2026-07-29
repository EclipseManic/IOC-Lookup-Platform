import { useState } from "react";

const EXAMPLES = ["8.8.8.8", "example.com", "d41d8cd98f00b204e9800998ecf8427e", "CVE-2024-3094"];

export default function SearchBar({ onSearch, initialValue = "" }: { onSearch: (value: string) => void; initialValue?: string }) {
  const [value, setValue] = useState(initialValue);

  function handleSubmit() {
    const v = value.trim();
    if (v) onSearch(v);
  }

  return (
    <div role="search" aria-label="IOC lookup">
      <div className="relative">
        <input
          type="text"
          value={value}
          onChange={(e) => setValue(e.target.value)}
          onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
          placeholder="Enter IOC value (IP, domain, hash, URL, email, CVE)..."
          aria-label="Search IOC"
          className="w-full px-4 py-3 bg-bg-card border border-border rounded-lg text-text-primary placeholder-text-secondary outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all font-mono text-sm"
        />
        <button
          onClick={handleSubmit}
          aria-label="Submit search"
          className="absolute right-2 top-1/2 -translate-y-1/2 px-3 py-1.5 bg-accent text-white text-sm rounded-md hover:bg-accent/90 transition-colors font-medium"
        >
          Search
        </button>
      </div>
      <div className="flex gap-2 mt-2 flex-wrap" role="group" aria-label="Example IOCs">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            onClick={() => { setValue(ex); onSearch(ex); }}
            className="px-3 py-1 text-xs bg-bg-elevated border border-border rounded-full text-text-secondary hover:text-text-primary hover:border-accent transition-colors font-mono"
          >
            {ex}
          </button>
        ))}
      </div>
    </div>
  );
}
