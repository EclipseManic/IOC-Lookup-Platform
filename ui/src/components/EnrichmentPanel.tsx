import type { ReactNode } from "react";
import type { EnrichmentData } from "../services/api";
import HostVulnerabilityMatrix from "./HostVulnerabilityMatrix";
import InfostealerExposureCard from "./InfostealerExposureCard";
import WebPreviewCard from "./WebPreviewCard";
import AbuseReportsPanel from "./AbuseReportsPanel";
import DataProvenanceBadge from "./DataProvenanceBadge";
import EthereumWalletCard from "./EthereumWalletCard";
import type { EthereumContext } from "../services/api";

function formatValue(value: unknown): string {
  if (Array.isArray(value))
    return value.every((item) => typeof item !== "object" || item === null)
      ? value.join(", ")
      : JSON.stringify(value, null, 2);
  if (typeof value === "object" && value !== null) return JSON.stringify(value, null, 2);
  return String(value);
}

function Section({
  title,
  data,
  badge,
}: {
  title: string;
  data: object;
  badge?: ReactNode;
}) {
  const entries = Object.entries(data).filter(
    ([_, value]) =>
      value !== null &&
      value !== undefined &&
      value !== "" &&
      !(Array.isArray(value) && value.length === 0)
  );
  if (entries.length === 0 && !badge) return null;
  return (
    <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border/50 pb-2">
        <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">{title}</h4>
        {badge}
      </div>
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

function Stat({
  label,
  value,
  accent = "text-text-primary",
}: {
  label: string;
  value: string | number;
  accent?: string;
}) {
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
  onPivot,
}: {
  enrichment: EnrichmentData;
  iocType?: string;
  onPivot?: (value: string) => void;
}) {
  const sections: [string, object][] = [];
  const extra = enrichment.extra ?? {};
  const bitcoin =
    extra.bitcoin && typeof extra.bitcoin === "object"
      ? (extra.bitcoin as unknown as Record<string, unknown>)
      : null;
  const ethereum =
    extra.ethereum && typeof extra.ethereum === "object"
      ? extra.ethereum
      : null;

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
  const ethereumWallet: EthereumContext | null = ethereum;

  const consumed = new Set(["bitcoin", "ethereum"]);
  const additional = Object.fromEntries(
    Object.entries(extra).filter(([key]) => !consumed.has(key))
  );
  if (Object.keys(additional).length) sections.push(["Additional context", additional]);

  const geo = enrichment.geoip;
  const wallet = bitcoin;
  const breach = enrichment.breach as Record<string, unknown> | undefined;
  const breachCount = typeof breach?.breach_count === "number" ? breach.breach_count : 0;
  const breachSource = typeof breach?.source === "string" ? breach.source : "None";
  const exposedTypeCount = Array.isArray(breach?.exposed_data_types) ? breach.exposed_data_types.length : 0;
  const emailSec = enrichment.email_security as Record<string, unknown> | undefined;
  const spfValue = typeof emailSec?.spf === "string" ? emailSec.spf : "";
  const spfConfigured = Boolean(spfValue && spfValue !== "missing");
  const contextLabel = iocType ? `${iocType.toUpperCase()} context` : "Contextual enrichment";

  const hasHostIntel = !!enrichment.host_intel || (enrichment.open_ports && enrichment.open_ports.length > 0);
  const hostingIps = Object.entries(enrichment.hosting_ip_intel ?? {});

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

      {/* 1. Web Preview Card (urlscan.io proxied live preview) */}
      {enrichment.web_preview && (
        <WebPreviewCard preview={enrichment.web_preview} domainOrUrl={iocType} />
      )}

      {/* 2. Infostealer Attack Surface (Hudson Rock) */}
      {enrichment.infostealer && (
        <InfostealerExposureCard infostealer={enrichment.infostealer} domainOrUser={iocType} />
      )}

      {/* 3. Host Intelligence & Attack Surface Matrix (Shodan InternetDB / Active) */}
      {hasHostIntel && (
        <HostVulnerabilityMatrix
          hostIntel={enrichment.host_intel}
          geoip={enrichment.geoip}
          legacyPorts={enrichment.open_ports}
        />
      )}

      {/* 4. Sysadmin Abuse & Incident Reports (AbuseIPDB verbose) */}
      {enrichment.abuse_reports && enrichment.abuse_reports.length > 0 && (
        <AbuseReportsPanel reports={enrichment.abuse_reports} />
      )}

      {/* 5. Domain Hosting IP Pivot Intelligence */}
      {hostingIps.length > 0 && (
        <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">
              Hosting Infrastructure Pivot
            </h4>
            <span className="text-[10px] text-text-secondary">Resolved A-Records Context</span>
          </div>
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {hostingIps.map(([ip, rawInfo]) => {
              const info = rawInfo as Record<string, unknown>;
              const isRiot = !!info.riot;
              const riotName = (info.riot_name as string) || "Cloudflare / CDN Provider";
              const isDatacenter = !!info.is_datacenter;
              const org = (info.org as string) || (info.isp as string) || "";

              return (
                <div
                  key={ip}
                  className="rounded-lg border border-border/70 bg-bg-elevated/40 p-3 space-y-1.5 text-xs font-mono"
                >
                  <div className="flex items-center justify-between font-bold">
                    <span className="text-text-primary">{ip}</span>
                    {isRiot ? (
                      <span className="rounded-full bg-emerald-500/10 text-emerald-400 border border-emerald-500/30 px-2 py-0.2 text-[10px]">
                        RIOT (Known Good CDN)
                      </span>
                    ) : isDatacenter ? (
                      <span className="rounded-full bg-purple-500/10 text-purple-400 border border-purple-500/30 px-2 py-0.2 text-[10px]">
                        Datacenter IP
                      </span>
                    ) : null}
                  </div>
                  <div className="text-[11px] text-text-secondary">
                    {isRiot ? (
                      <span>Provider: <strong className="text-emerald-300">{riotName}</strong></span>
                    ) : org ? (
                      <span>Network: {org}</span>
                    ) : (
                      <span>Resolved Host IP</span>
                    )}
                  </div>
                </div>
              );
            })}
          </div>
        </section>
      )}

      {/* 6. Malware URLs & Associated Hashes (OTX / URLhaus) */}
      {(enrichment.malware_urls?.length || enrichment.associated_hashes?.length) && (
        <section className="rounded-xl border border-border bg-bg-card p-4 space-y-3">
          <div className="flex items-center justify-between border-b border-border/50 pb-2">
            <h4 className="text-xs font-semibold uppercase tracking-[0.14em] text-accent">
              Associated Malware & C2 Indicators
            </h4>
            <span className="text-[10px] text-text-secondary">AlienVault OTX Correlated</span>
          </div>

          {enrichment.malware_urls && enrichment.malware_urls.length > 0 && (
            <div className="space-y-1">
              <span className="text-[11px] font-semibold text-red-400 block">
                Malicious URLs on Host ({enrichment.malware_urls.length})
              </span>
              <div className="max-h-32 overflow-y-auto space-y-1 font-mono text-xs">
                {enrichment.malware_urls.map((url, i) => (
                  <div key={i} className="truncate rounded bg-bg-elevated/70 p-1.5 text-text-secondary border border-border/40" title={url}>
                    {url}
                  </div>
                ))}
              </div>
            </div>
          )}

          {enrichment.associated_hashes && enrichment.associated_hashes.length > 0 && (
            <div className="space-y-1 pt-2">
              <span className="text-[11px] font-semibold text-amber-400 block">
                Associated Malware Hashes ({enrichment.associated_hashes.length})
              </span>
              <div className="flex flex-wrap gap-1 font-mono text-xs">
                {enrichment.associated_hashes.map((h, i) => (
                  <span key={i} className="rounded bg-bg-elevated px-2 py-0.5 text-[11px] border border-border/50 text-text-secondary">
                    {h.slice(0, 16)}...
                  </span>
                ))}
              </div>
            </div>
          )}
        </section>
      )}

      {/* Identity & Breach Exposure Highlight */}
      {(breach || emailSec || iocType === "email" || iocType === "password" || iocType === "username") && (
        <div className="rounded-xl border border-red-500/20 bg-red-950/10 p-3.5">
          <div className="mb-2 text-[10px] font-bold uppercase tracking-wider text-red-400">
            Identity & Credential Exposure Summary
          </div>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Stat
              label="Breach Count"
              value={String(breachCount)}
              accent={breachCount > 0 ? "text-red-400" : "text-emerald-400"}
            />
            <Stat
              label="Breach Source"
              value={breachSource}
            />
            <Stat
              label="Exposed Data Types"
              value={String(exposedTypeCount)}
            />
            <Stat
              label="SPF"
              value={spfConfigured ? spfValue : emailSec ? "Missing" : "Unavailable"}
              accent={spfConfigured ? "text-emerald-400" : "text-amber-400"}
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

      {/* WHOIS section with Data Provenance Badge */}
      {enrichment.whois && (
        <Section
          title="WHOIS / Registration Record"
          data={enrichment.whois}
          badge={
            <DataProvenanceBadge
              tier={enrichment.whois.fallback_tier_used}
              privacyProtected={enrichment.whois.privacy_protected}
              isNewlyRegistered={enrichment.whois.is_newly_registered}
            />
          }
        />
      )}

      {/* Remaining Standard Sections */}
      {ethereumWallet && (
        <EthereumWalletCard wallet={ethereumWallet} onPivot={onPivot} />
      )}

      {sections.map(([title, data]) => (
        <Section key={title} title={title} data={data} />
      ))}

      {Object.keys(enrichment.completeness ?? {}).length > 0 && (
        <Section title="Collection Completeness Audit" data={enrichment.completeness} />
      )}

      {enrichment.analysis_notes?.length ? (
        <Section title="Analyst Notes" data={{ notes: enrichment.analysis_notes }} />
      ) : null}

      {sections.length === 0 && !enrichment.whois && !hasHostIntel && !enrichment.web_preview && !enrichment.infostealer && (
        <div className="rounded-xl border border-border bg-bg-card p-8 text-center text-sm text-text-secondary">
          No enrichment data available for this IOC.
        </div>
      )}
    </div>
  );
}
