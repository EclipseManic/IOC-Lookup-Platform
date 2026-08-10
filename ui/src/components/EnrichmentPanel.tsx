import type { EnrichmentData } from "../services/api";

function formatValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value.every((item) => typeof item !== "object" || item === null)
      ? value.join(", ")
      : JSON.stringify(value, null, 2);
  }
  if (typeof value === "object" && value !== null) return JSON.stringify(value, null, 2);
  return String(value);
}

function Section({ title, data }: { title: string; data: object }) {
  const entries = Object.entries(data).filter(([_, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && v.length === 0));
  if (entries.length === 0) return null;
  return (
    <div className="bg-bg-elevated rounded-lg p-3">
      <h4 className="text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wider">{title}</h4>
      <div className="text-xs font-mono space-y-0.5">
        {entries.map(([k, v]) => (
          <div key={k}>
            <span className="text-text-secondary">{k.replace(/_/g, " ")}: </span>
            <span className="text-text-primary whitespace-pre-wrap break-all">{formatValue(v)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function EnrichmentPanel({ enrichment }: { enrichment: EnrichmentData }) {
  const sections: [string, object][] = [];
  if (enrichment.geoip) sections.push(["GeoIP", enrichment.geoip]);
  if (enrichment.whois) sections.push(["WHOIS", enrichment.whois]);
  if (enrichment.dns) sections.push(["DNS", enrichment.dns]);
  if (enrichment.reverse_dns) sections.push(["Reverse DNS", enrichment.reverse_dns]);
  if (enrichment.ssl) sections.push(["SSL", enrichment.ssl]);
  if (enrichment.subdomains) sections.push(["Subdomains", enrichment.subdomains]);
  if (enrichment.cve) sections.push(["CVE", enrichment.cve]);
  if (enrichment.email_security) sections.push(["Email Security", enrichment.email_security]);
  if (enrichment.open_ports && enrichment.open_ports.length > 0) {
    sections.push(["Open Ports", { ports: enrichment.open_ports }]);
  }
  if (enrichment.breach) sections.push(["Breach Data", enrichment.breach]);
  if (enrichment.passive_dns) sections.push(["Passive DNS", enrichment.passive_dns]);
  if (enrichment.favicon) sections.push(["Favicon", enrichment.favicon]);
  if (enrichment.url_preview && Object.keys(enrichment.url_preview).length > 0) {
    sections.push(["URL Preview", enrichment.url_preview]);
  }
  if (enrichment.redirect_chain && enrichment.redirect_chain.length > 0) {
    sections.push(["Redirect Chain", {
      chain: enrichment.redirect_chain.map((r) => r.url || r.redirect_url || JSON.stringify(r)),
    }]);
  }
  if (enrichment.completeness && Object.keys(enrichment.completeness).length > 0) {
    sections.push(["Collection Status", enrichment.completeness]);
  }
  if (enrichment.analysis_notes && enrichment.analysis_notes.length > 0) {
    sections.push(["Analyst Notes", { notes: enrichment.analysis_notes }]);
  }
  if (enrichment.extra && Object.keys(enrichment.extra).length > 0) {
    sections.push(["Additional Data", enrichment.extra]);
  }

  if (sections.length === 0) return null;

  return (
    <div>
      <h3 className="text-sm font-semibold mb-3 text-text-secondary uppercase tracking-wider">Enrichment Data</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
        {sections.map(([title, data]) => (
          <Section key={title} title={title} data={data} />
        ))}
      </div>
    </div>
  );
}
