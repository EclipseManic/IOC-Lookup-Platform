import type { EnrichmentData } from "../services/api";

function formatValue(value: unknown): string {
  if (Array.isArray(value))
    return value.every((item) => typeof item !== "object" || item === null)
      ? value.join(", ")
      : JSON.stringify(value, null, 2);
  if (typeof value === "object" && value !== null) return JSON.stringify(value, null, 2);
  return String(value);
}

function Section({ title, data }: { title: string; data: object }) {
  const entries = Object.entries(data).filter(
    ([_, value]) =>
      value !== null &&
      value !== undefined &&
      value !== "" &&
      !(Array.isArray(value) && value.length === 0)
  );
  if (entries.length === 0) return null;
  return (
    <section className="rounded-xl border border-border bg-bg-card p-4">
      <h4 className="mb-3 text-xs font-semibold uppercase tracking-[0.14em] text-accent">{title}</h4>
      <div className="space-y-1.5 text-xs font-mono">
        {entries.map(([key, value]) => (
          <div key={key} className="flex gap-3 border-b border-border/50 pb-1.5 last:border-0">
            <span className="shrink-0 text-text-secondary">{key.replace(/_/g, " ")}:</span>
            <span className="min-w-0 whitespace-pre-wrap break-all text-text-primary">
              {formatValue(value)}
            </span>
          </div>
        ))}
      </div>
    </section>
  );
}

function Stat({ label, value, accent = "text-text-primary" }: { label: string; value: string | number; accent?: string }) {
  return (
    <div className="rounded-lg border border-border/70 bg-bg-elevated/50 p-3">
      <div className="text-[10px] uppercase tracking-wider text-text-secondary">{label}</div>
      <div className={`mt-1 truncate text-sm font-semibold ${accent}`}>{value}</div>
    </div>
  );
}

export default function EnrichmentPanel({
  enrichment,
  iocType,
}: {
  enrichment: EnrichmentData;
  iocType?: string;
}) {
  const sections: [string, object][] = [];
  const extra = enrichment.extra ?? {};
  const bitcoin =
    extra.bitcoin && typeof extra.bitcoin === "object"
      ? (extra.bitcoin as Record<string, unknown>)
      : null;
  const ethereum =
    extra.ethereum && typeof extra.ethereum === "object"
      ? (extra.ethereum as Record<string, unknown>)
      : null;

  if (enrichment.geoip) sections.push(["Network location", enrichment.geoip]);
  if (enrichment.open_ports?.length) sections.push(["Open ports", { ports: enrichment.open_ports }]);
  if (enrichment.whois) sections.push(["WHOIS / domain age", enrichment.whois]);
  if (enrichment.dns) sections.push(["DNS records", enrichment.dns]);
  if (enrichment.ssl) sections.push(["SSL certificate", enrichment.ssl]);
  if (enrichment.reverse_dns) sections.push(["Reverse DNS", enrichment.reverse_dns]);
  if (enrichment.subdomains) sections.push(["Subdomains", enrichment.subdomains]);
  if (enrichment.breach) sections.push(["Breach exposure & credentials", enrichment.breach]);
  if (enrichment.email_security) sections.push(["Email security & delivery", enrichment.email_security]);
  if (enrichment.cve) sections.push(["CVE context", enrichment.cve]);
  if (enrichment.passive_dns) sections.push(["Passive DNS", enrichment.passive_dns]);
  if (enrichment.favicon) sections.push(["Favicon", enrichment.favicon]);
  if (enrichment.url_preview && Object.keys(enrichment.url_preview).length)
    sections.push(["URL preview", enrichment.url_preview]);
  if (enrichment.redirect_chain?.length)
    sections.push(["Redirect chain", { chain: enrichment.redirect_chain }]);
  if (bitcoin) sections.push(["Bitcoin wallet", bitcoin]);
  if (ethereum) sections.push(["Ethereum wallet", ethereum]);
  const consumed = new Set(["bitcoin", "ethereum"]);
  const additional = Object.fromEntries(
    Object.entries(extra).filter(([key]) => !consumed.has(key))
  );
  if (Object.keys(additional).length) sections.push(["Additional context", additional]);

  const geo = enrichment.geoip;
  const wallet = bitcoin || ethereum;
  const breach = enrichment.breach as Record<string, unknown> | undefined;
  const emailSec = enrichment.email_security as Record<string, unknown> | undefined;
  const contextLabel = iocType ? `${iocType.toUpperCase()} context` : "Contextual enrichment";

  return (
    <div className="space-y-4">
      <div>
        <div className="text-[10px] font-semibold uppercase tracking-[0.16em] text-accent">{contextLabel}</div>
        <h3 className="mt-1 text-lg font-bold">Enrichment & OSINT Data</h3>
        <p className="mt-1 text-xs text-text-secondary">
          Corroborating technical signals that augment the composite threat evaluation.
        </p>
      </div>

      {/* Network Geo Metrics */}
      {geo && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat label="Country" value={geo.country || geo.country_code || "—"} />
          <Stat label="City" value={geo.city || "—"} />
          <Stat label="ISP / Org" value={geo.isp || geo.org || "—"} />
          <Stat label="ASN" value={geo.asn || "—"} />
        </div>
      )}

      {/* Identity & Breach Exposure Highlight */}
      {(breach || emailSec || iocType === "email" || iocType === "password") && (
        <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-3.5">
          <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-red-400">
            Identity & Credential Exposure Summary
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat
              label="Breach Count"
              value={String(breach?.breaches_count ?? breach?.count ?? "0")}
              accent={Number(breach?.breaches_count ?? 0) > 0 ? "text-red-400" : "text-emerald-400"}
            />
            <Stat
              label="Infostealer Compromise"
              value={String(breach?.stealer_count ?? (breach?.stealer_infections ? "Detected" : "None"))}
              accent={breach?.stealer_infections ? "text-red-400" : "text-text-primary"}
            />
            <Stat
              label="Spam Reports"
              value={String(breach?.spam_reports ?? breach?.appears ?? "0")}
            />
            <Stat
              label="MX / Mail Delivery"
              value={emailSec?.has_mx ? "Valid MX" : emailSec ? "No MX" : "Verified"}
              accent={emailSec?.has_mx === false ? "text-amber-400" : "text-emerald-400"}
            />
          </div>
        </div>
      )}

      {/* Wallet Metrics */}
      {wallet && (
        <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
          <Stat label="Balance" value={String(wallet.balance_btc ?? wallet.balance_eth ?? "—")} />
          <Stat label="Transactions" value={String(wallet.transaction_count ?? wallet.n_tx ?? "—")} />
          <Stat label="Total received" value={String(wallet.total_received_btc ?? "—")} />
          <Stat label="Total sent" value={String(wallet.total_sent_btc ?? "—")} />
        </div>
      )}

      {sections.map(([title, data]) => (
        <Section key={title} title={title} data={data} />
      ))}
      {Object.keys(enrichment.completeness ?? {}).length > 0 && (
        <Section title="Collection Status" data={enrichment.completeness} />
      )}
      {enrichment.analysis_notes?.length ? (
        <Section title="Analyst Notes" data={{ notes: enrichment.analysis_notes }} />
      ) : null}
      {sections.length === 0 && (
        <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-secondary">
          No enrichment data available for this IOC.
        </div>
      )}
    </div>
  );
}
