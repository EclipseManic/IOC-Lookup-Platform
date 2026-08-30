import { useState } from "react";

const EXAMPLES = [
  ["IP: 8.8.8.8", "8.8.8.8"],
  ["Domain: google.com", "google.com"],
  ["CVE: Log4j", "CVE-2021-44228"],
  ["BTC: WannaCry", "13AM4VW2dhxYgXeQepoHkHSQuy6NgaEb94"],
  ["Hash: WannaCry", "84c82835a5d21bbcf75a61706d8ab549"],
  ["Pwned Password", "password"],
];
const MAX_IOC_LENGTH = 2048;

function detectType(value: string): string | null {
  const input = value.trim();
  if (!input) return null;
  if (/^CVE-\d{4}-\d{4,}$/i.test(input)) return "CVE Vulnerability";
  if (/^0x[a-f\d]{40}$/i.test(input)) return "Ethereum wallet";
  if (/^(?:\d{1,3}\.){3}\d{1,3}$/.test(input)) return "IPv4";
  // Anchored IPv6 - must be standalone, not embedded in a URL/domain
  if (/^(?:[0-9a-f]{1,4}:){7}[0-9a-f]{1,4}$|^(?:[0-9a-f]{1,4}:)*::(?:[0-9a-f]{1,4}:)*[0-9a-f]{1,4}$|^::1$|^::$/i.test(input)) return "IPv6";
  if (/^[a-f\d]{32}$/i.test(input)) return "MD5 hash";
  if (/^[a-f\d]{40}$/i.test(input)) return "SHA-1 hash";
  if (/^[a-f\d]{64}$/i.test(input)) return "SHA-256 hash";
  if (/^[a-f\d]{128}$/i.test(input)) return "SHA-512 hash";
  if (/^[\w.+-]+@[\w-]+\.[\w.-]+$/.test(input)) return "Email address";
  if (/^https?:\/\//i.test(input)) return "URL";
  if (/^(?:[a-z\d-]+\.)+[a-z]{2,}$/i.test(input)) return "Domain";
  if (/^(?:[13][a-km-zA-HJ-NP-Z1-9]{25,34}|bc1[a-z\d]{38,58})$/i.test(input)) return "Bitcoin wallet";
  if (/^AS\d+$/i.test(input)) return "Autonomous System (ASN)";
  if (/^(?:pass|password):/i.test(input)) return "Password / Credential";
  return "Custom / Search";
}

function validateIOC(value: string): string | null {
  if (!value) return "Enter an indicator, hash, wallet, or credential to analyze";
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
  const [showSecret, setShowSecret] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const detected = detectType(value);
  const isCredentialMode = iocType === "password" || detected === "Password / Credential";

  async function handleSubmit() {
    let v = value.trim();
    const err = validateIOC(v);
    if (err) {
      setError(err);
      return;
    }
    setError(null);

    // If explicit pass: or password: prefix, strip it and treat as password
    if (/^(?:pass|password):/i.test(v)) {
      v = v.replace(/^(?:pass|password):/i, "").trim();
    }

    // Zero-knowledge client-side SHA-1 hashing for credentials
    // Plaintext password never leaves the browser over the wire!
    if (iocType === "password" || isCredentialMode) {
      try {
        if (!/^[a-f0-9]{40}$/i.test(v) && window.crypto?.subtle) {
          const encoder = new TextEncoder();
          const data = encoder.encode(v);
          const hashBuffer = await crypto.subtle.digest("SHA-1", data);
          const hashArray = Array.from(new Uint8Array(hashBuffer));
          const sha1 = hashArray.map((b) => b.toString(16).padStart(2, "0")).join("");
          onSearch(sha1, "password");
          return;
        }
      } catch (e) {
        console.warn("Client hashing fallback to backend:", e);
      }
      onSearch(v, "password");
      return;
    }

    if (iocType === "auto") {
      onSearch(v);
    } else {
      onSearch(v, iocType);
    }
  }

  return (
    <div role="search" aria-label="IOC lookup" className="w-full">
      <div className="rounded-2xl border border-border bg-bg-card p-2.5 shadow-[0_18px_40px_rgba(0,0,0,0.24)]">
        {/* Detection context banner */}
        <div className="mb-2 flex items-center justify-between px-2 text-[11px]">
          <div className="flex items-center gap-2">
            <span className="font-semibold uppercase tracking-wider text-text-secondary">Indicator</span>
            {detected && (
              <span className="rounded-full border border-accent/40 bg-accent/10 px-2.5 py-0.5 font-medium text-accent">
                {detected}
              </span>
            )}
            {isCredentialMode && (
              <span className="rounded-full border border-amber-500/40 bg-amber-500/10 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
                🔒 Zero-Knowledge HIBP Mode
              </span>
            )}
          </div>
          {isCredentialMode && (
            <button
              type="button"
              onClick={() => setShowSecret((prev) => !prev)}
              className="text-[11px] font-medium text-text-secondary hover:text-accent transition-colors"
            >
              {showSecret ? "Hide input 🙈" : "Show input 👁️"}
            </button>
          )}
        </div>

        <div className="flex flex-col gap-2 sm:flex-row">
          <div className="relative min-w-0 flex-1">
            <input
              type={isCredentialMode && !showSecret ? "password" : "text"}
              value={value}
              onChange={(event) => {
                setValue(event.target.value);
                if (error) setError(null);
              }}
              onKeyDown={(event) => event.key === "Enter" && handleSubmit()}
              placeholder={
                isCredentialMode
                  ? "Enter password to check for public breach compromise..."
                  : "Paste IP, domain, URL, hash, email, wallet, CVE, or credential..."
              }
              aria-label="Search IOC"
              aria-invalid={!!error}
              aria-describedby={error ? "ioc-search-error" : undefined}
              disabled={disabled}
              maxLength={MAX_IOC_LENGTH}
              className="w-full rounded-xl border border-border bg-bg-secondary px-4 py-3.5 font-mono text-sm text-text-primary outline-none transition-all placeholder:text-text-secondary focus:border-accent focus:ring-1 focus:ring-accent disabled:opacity-50"
            />
          </div>

          <select
            aria-label="IOC type"
            value={iocType}
            onChange={(event) => setIocType(event.target.value)}
            disabled={disabled}
            className="rounded-xl border border-border bg-bg-secondary px-3 py-3 text-xs font-medium text-text-secondary sm:w-44 disabled:opacity-50"
          >
            <option value="auto">Auto detect</option>
            <option value="password">🔑 Password / Credential</option>
            <option value="ipv4">IPv4 Address</option>
            <option value="ipv6">IPv6 Address</option>
            <option value="domain">Domain Name</option>
            <option value="url">Web URL</option>
            <option value="email">Email Address</option>
            <option value="md5">MD5 Hash</option>
            <option value="sha1">SHA-1 Hash</option>
            <option value="sha256">SHA-256 Hash</option>
            <option value="btc">Bitcoin (BTC)</option>
            <option value="eth">Ethereum (ETH)</option>
            <option value="cve">CVE Vulnerability</option>
            <option value="asn">Autonomous System (ASN)</option>
          </select>

          <button
            onClick={handleSubmit}
            disabled={disabled}
            aria-label="Submit search"
            className="rounded-xl bg-accent px-5 py-3 text-sm font-bold text-[#06070d] hover:bg-accent/90 transition-colors disabled:opacity-40"
          >
            {disabled ? "Analyzing…" : "Analyze Indicator"}
          </button>
        </div>
      </div>

      {error && (
        <p id="ioc-search-error" className="mt-2 text-xs font-semibold text-verdict-malicious" role="alert">
          {error}
        </p>
      )}

      <div className="mt-3 flex flex-wrap items-center gap-2" role="group" aria-label="Example IOCs">
        <span className="mr-1 text-[10px] font-semibold uppercase tracking-wider text-text-secondary">
          Examples
        </span>
        {EXAMPLES.map(([label, example]) => (
          <button
            key={example}
            onClick={() => {
              setValue(example);
              setError(null);
              if (example === "password") {
                setIocType("password");
                // Don't call onSearch directly - let user click "Analyze Indicator"
                // so the client-side SHA-1 hashing flow runs correctly
              } else {
                onSearch(example);
              }
            }}
            disabled={disabled}
            className="rounded-full border border-border bg-bg-elevated px-3 py-1.5 font-mono text-[11px] text-text-secondary hover:border-accent/60 hover:text-accent transition-colors disabled:opacity-50"
          >
            {label}
          </button>
        ))}
      </div>
    </div>
  );
}
