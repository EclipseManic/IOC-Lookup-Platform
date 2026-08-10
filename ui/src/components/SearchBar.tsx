import { useState } from "react";

const EXAMPLES = ["8.8.8.8", "example.com", "d41d8cd98f00b204e9800998ecf8427e", "CVE-2024-3094"];

const MAX_IOC_LENGTH = 2048;

function validateIOC(value: string): string | null {
  if (!value) return "Enter an IOC value";
  if (value.length > MAX_IOC_LENGTH) return `Max length ${MAX_IOC_LENGTH} characters`;
  return null;
}

export default function SearchBar({
  onSearch,
  initialValue = "",
  disabled = false,
}: {
  onSearch: (value: string, iocType?: string) => void;
  initialValue?: string;
  disabled?: boolean;
}) {
  const [value, setValue] = useState(initialValue);
  const [iocType, setIocType] = useState("auto");
  const [error, setError] = useState<string | null>(null);

  function handleSubmit() {
    const v = value.trim();
    const err = validateIOC(v);
    if (err) {
      setError(err);
      return;
    }
    setError(null);
    if (iocType === "auto") onSearch(v);
    else onSearch(v, iocType);
  }

  return (
    <div role="search" aria-label="IOC lookup">
      <div className="relative flex gap-2">
        <input
          type="text"
          value={value}
          onChange={(e) => { setValue(e.target.value); if (error) setError(null); }}
          onKeyDown={(e) => e.key === "Enter" && handleSubmit()}
          placeholder="Enter IOC value (IP, domain, hash, URL, email, CVE)..."
          aria-label="Search IOC"
          aria-invalid={!!error}
          disabled={disabled}
          maxLength={MAX_IOC_LENGTH}
          className="min-w-0 flex-1 px-4 py-3 bg-bg-card border border-border rounded-lg text-text-primary placeholder-text-secondary outline-none focus:border-accent focus:ring-1 focus:ring-accent transition-all font-mono text-sm disabled:opacity-50"
        />
        <select
          aria-label="IOC type"
          value={iocType}
          onChange={(e) => setIocType(e.target.value)}
          disabled={disabled}
          className="w-36 px-2 py-3 bg-bg-card border border-border rounded-lg text-text-secondary text-xs disabled:opacity-50"
        >
          <option value="auto">Auto detect</option>
          <option value="ipv4">IPv4</option>
          <option value="ipv6">IPv6</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="email">Email</option>
          <option value="md5">MD5</option>
          <option value="sha1">SHA-1</option>
          <option value="sha256">SHA-256</option>
          <option value="ssdeep">SSDeep</option>
          <option value="btc">Bitcoin address</option>
          <option value="cve">CVE</option>
          <option value="mitre_attack">MITRE ATT&CK</option>
          <option value="asn">ASN</option>
          <option value="mutex">Mutex</option>
          <option value="named_pipe">Named pipe</option>
          <option value="registry_key">Registry key</option>
          <option value="service_name">Service name</option>
        </select>
        <button
          onClick={handleSubmit}
          disabled={disabled}
          aria-label="Submit search"
          className="shrink-0 px-4 py-1.5 bg-accent text-white text-sm rounded-md hover:bg-accent/90 disabled:opacity-40 transition-colors font-medium"
        >
          {disabled ? "Searching..." : "Search"}
        </button>
      </div>
      {error && (
        <p className="mt-1 text-xs text-verdict-malicious" role="alert">{error}</p>
      )}
      <div className="flex gap-2 mt-2 flex-wrap" role="group" aria-label="Example IOCs">
        {EXAMPLES.map((ex) => (
          <button
            key={ex}
            onClick={() => { setValue(ex); setError(null); onSearch(ex); }}
            disabled={disabled}
            className="px-3 py-1 text-xs bg-bg-elevated border border-border rounded-full text-text-secondary hover:text-text-primary hover:border-accent transition-colors font-mono disabled:opacity-50"
          >
            {ex}
          </button>
        ))}
      </div>
    </div>
  );
}
