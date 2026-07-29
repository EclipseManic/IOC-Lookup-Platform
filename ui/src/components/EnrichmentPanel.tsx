import type { EnrichmentData } from "../services/api";

function Section({ title, data }: { title: string; data: Record<string, any> }) {
  const entries = Object.entries(data).filter(([_, v]) => v !== null && v !== undefined && v !== "" && !(Array.isArray(v) && v.length === 0));
  if (entries.length === 0) return null;
  return (
    <div className="bg-bg-elevated rounded-lg p-3">
      <h4 className="text-xs font-semibold text-text-secondary mb-2 uppercase tracking-wider">{title}</h4>
      <div className="text-xs font-mono space-y-0.5">
        {entries.map(([k, v]) => (
          <div key={k}>
            <span className="text-text-secondary">{k.replace(/_/g, " ")}: </span>
            <span className="text-text-primary">{Array.isArray(v) ? v.join(", ") : String(v)}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

export default function EnrichmentPanel({ enrichment }: { enrichment: EnrichmentData }) {
  const sections: [string, Record<string, any>][] = [];
  if (enrichment.geoip) sections.push(["GeoIP", enrichment.geoip]);
  if (enrichment.whois) sections.push(["WHOIS", enrichment.whois]);
  if (enrichment.dns) sections.push(["DNS", enrichment.dns]);
  if (enrichment.reverse_dns) sections.push(["Reverse DNS", enrichment.reverse_dns]);
  if (enrichment.ssl) sections.push(["SSL", enrichment.ssl]);
  if (enrichment.subdomains) sections.push(["Subdomains", enrichment.subdomains]);
  if (enrichment.cve) sections.push(["CVE", enrichment.cve]);
  if (enrichment.email_security) sections.push(["Email Security", enrichment.email_security]);

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
