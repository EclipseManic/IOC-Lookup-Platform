# IOC Platform — Deep UI Specification, Data Representation & Gap Analysis

> **Document Version**: 1.0  
> **Status**: Comprehensive Architectural UI Reference & Gap Audit  
> **Purpose**: Define with maximum depth how the UI must represent every piece of intelligence from the backend across all indicator types and edge cases, compare it against the current UI implementation, and define the exact differences and fixes.

---

## Part 1: The Ideal UI Design Specification (Derived from Backend Architecture)

An enterprise-grade Threat Intelligence platform must transform complex multi-source telemetry into an immediate, actionable operational picture. It must never dump raw data onto the analyst; every data point must be parsed, visually prioritized, and contextually placed based on the indicator being investigated.

---

### 1.1 Indicator-Specific Data Representation Matrix

The backend generates completely different data payloads depending on the indicator type. The UI must adapt dynamically:

```
┌────────────────────────────────────────────────────────────────────────────────────────────────────────┐
│                                    DYNAMIC DOMAIN-AWARE PRESENTATION                                   │
├───────────────────┬───────────────────────────────────┬────────────────────────────────────────────────┤
│ INDICATOR TYPE    │ PRIMARY OPERATIONAL FOCUS         │ KEY TECHNICAL WIDGETS & TELEMETRY              │
├───────────────────┼───────────────────────────────────┼────────────────────────────────────────────────┤
│ Domain / URL      │ Phishing, C2, Brand Impersonation │ • Live Proxied Screenshot Preview (urlscan.io) │
│                   │ & Infrastructure Provenance       │ • Brand Impersonation & Phishing Warning Banner│
│                   │                                   │ • WHOIS Provenance (Tier 1/2/3, Age, Privacy)  │
│                   │                                   │ • Resolved Hosting IP & CDN Bypass Detection   │
│                   │                                   │ • Certificate Transparency Subdomains Table    │
│                   │                                   │ • SSL/TLS Certificate Validity & SANs          │
├───────────────────┼───────────────────────────────────┼────────────────────────────────────────────────┤
│ IPv4 / IPv6       │ Network Attack Surface, Open Ports│ • Interactive Port Vulnerability Matrix (Ports)│
│                   │ & Operator Reputation             │ • Running Services Dictionary (SSH, RDP, etc.) │
│                   │                                   │ • Unpatched Software CVEs & CPE Identifiers    │
│                   │                                   │ • AbuseIPDB Sysadmin Complaints Timeline       │
│                   │                                   │ • Network Privacy Tags (VPN, Tor, Proxy, DC)   │
│                   │                                   │ • GeoIP & Autonomous System (ASN) Telemetry    │
├───────────────────┼───────────────────────────────────┼────────────────────────────────────────────────┤
│ Email / Username /│ Identity Theft, Credential Stuffs,│ • Cavalier Infostealer Exposure Card           │
│ Password          │ & Corporate Portal Breach         │ • Employee vs. Client Compromised Accounts     │
│                   │                                   │ • Stealer Family Breakdown (RedLine, Vidar...) │
│                   │                                   │ • Exposed Corporate Portals (VPN, Okta, etc.)  │
│                   │                                   │ • Password Hygiene Weak % Gauge                │
│                   │                                   │ • Email Delivery Security (SPF, DKIM, DMARC)   │
│                   │                                   │ • Aggregated Breach Timeline (XposedOrNot/COMB)│
├───────────────────┼───────────────────────────────────┼────────────────────────────────────────────────┤
│ File Hashes       │ Malware Signatures & Sandbox Run  │ • Multi-Engine AV Consensus (VirusTotal, etc.) │
│ (MD5/SHA1/SHA256) │                                   │ • Behavioral Sandbox Verdicts (Tria.ge, Falcon)│
│                   │                                   │ • Known-Good / Whitelist Match (Hashlookup)    │
│                   │                                   │ • File Metadata (Size, MIME, File Names)       │
├───────────────────┼───────────────────────────────────┼────────────────────────────────────────────────┤
│ CVE               │ Vulnerability Severity & Exploit  │ • CVSS v3.1 Radial Dial & Attack Vector Vector │
│                   │                                   │ • CISA KEV Exploitation Badge (Known Active)   │
│                   │                                   │ • EPSS Exploit Probability Score & Percentile  │
│                   │                                   │ • Affected Software Versions & Vendor Advisories│
├───────────────────┼───────────────────────────────────┼────────────────────────────────────────────────┤
│ Cryptocurrency    │ Financial Crime & Ransom Laundering│ • Wallet Balance (BTC / ETH) & Transaction Count│
│ (BTC / ETH)       │                                   │ • Total Satoshis / Ether Received vs. Sent     │
│                   │                                   │ • ChainAbuse Victim Crime Reports & Fraud Tags │
└───────────────────┴───────────────────────────────────┴────────────────────────────────────────────────┘
```

---

### 1.2 The Master Layout Hierarchy

The UI should follow a **2-Column Asymmetric Grid (55% / 45%)** rather than burying intelligence in horizontal tabs:

```
┌─────────────────────────────────────────────────────────────────────────────────────────────┐
│ 1. GLOBAL NAV: 🛡️ IOC Platform   [ Capabilities / Home ]   [ Investigation Console ]       │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 2. SEARCH COMMAND BAR:                                                                      │
│    [ Type Selector: Auto ▼ ]  [ Defanged Input Field ]  [ Local Hashing Pill ]  [ Analyze ]│
│    Quick Indicators: [ 8.8.8.8 ]  [ google.com ]  [ CVE-2021-44228 ]  [ WannaCry ]          │
├─────────────────────────────────────────────────────────────────────────────────────────────┤
│ 3. EXECUTIVE THREAT HERO BANNER:                                                            │
│    ┌─────────────────┐ ┌─────────────────────────────────────────┐ ┌──────────────────────┐│
│    │ RADIAL RISK DIAL│ │ VERDICT BADGE (Critical / Suspicious / Clean) │ SOURCE COVERAGE      ││
│    │ [ 88.5 / 100 ]  │ │ Executive SOC Summary & Action Guidance │ 11/11 Active (100%)  ││
│    └─────────────────┘ └─────────────────────────────────────────┘ └──────────────────────┘│
│    Actions: [ Re-scan Live ]  [ Add to Investigation ]  [ Copy Link ]  [ Export Report ▼ ]  │
├──────────────────────────────────────────────┬──────────────────────────────────────────────┤
│ 4. LEFT COLUMN: THREAT REPUTATION (55%)      │ 5. RIGHT COLUMN: TECHNICAL INTELLIGENCE (45%)│
│                                              │                                              │
│ A. Consensus Distribution Bar                │ Contextually adapts based on IOC type:       │
│    (Malicious 40% | Suspicious 20% | Clean)  │                                              │
│                                              │ • [Domain/URL]:                              │
│ B. Provider Consensus Grid                   │   - Live Website Screenshot Preview          │
│    Filterable: [All] [Flagged] [Clean]       │   - Brand Impersonation Alert Banner         │
│    Each Card Displays:                       │   - WHOIS Provenance (Tier, Age, Privacy)    │
│    - Provider Name & Direct Source Link      │   - Resolved Hosting IP & CDN Status         │
│    - Normalized Verdict Badge & Latency      │   - Certificate Transparency Subdomains      │
│    - Evidence Weight & Normalized Signal     │                                              │
│    - Threat Category Tags & Detection Ratio  │ • [IP Address]:                              │
│    - Collapsible Raw JSON Response           │   - Host Open Ports & Vulnerability Matrix   │
│                                              │   - AbuseIPDB Complaints Feed (Timeline)     │
│ C. Active Malware & C2 Indicators            │   - GeoIP & Autonomous System (ASN) Card     │
│    - Malicious URLs hosted on asset          │                                              │
│    - Associated malware file hashes          │ • [Email / Username / Password]:             │
│                                              │   - Infostealer Attack Surface Telemetry     │
│ D. Analyst Override & Community Feedback     │   - Stealer Families & Corporate Portals     │
│    - One-click False Positive marking        │   - Email Delivery Security (SPF/DKIM/DMARC) │
│    - Custom note annotation                  │   - Public Breach History (XposedOrNot/COMB) │
├──────────────────────────────────────────────┴──────────────────────────────────────────────┤
│ 6. BOTTOM DEEP-DIVE TABS:                                                                   │
│    [ Interactive Relationship Graph ]   [ Evidence Scoring Math ]   [ Complete Raw Payload ]│
└─────────────────────────────────────────────────────────────────────────────────────────────┘
```

---

### 1.3 Detailed Section-by-Section Data Representation

#### Section 1: Executive Threat Hero Banner
- **Radial Risk Dial (`ScoreRing`)**:
  - Value: Animated SVG arc representing composite score ($0.0$ to $100.0$).
  - Color Interpolation:
    - $\ge 70.0$: Crimson Red (`#EF4444`)
    - $25.0 - 69.9$: Amber Gold (`#F59E0B`)
    - $< 25.0$: Emerald Green (`#10B981`)
    - Unknown / Context: Slate Gray (`#64748B`)
- **Verdict & SOC Guidance**:
  - Bold verdict badge: `CRITICAL THREAT`, `MALICIOUS`, `SUSPICIOUS`, `BENIGN`, `CONTEXT ONLY`, or `UNKNOWN`.
  - Executive action advice:
    - If Malicious: *"High-confidence threat. Block indicator at perimeter firewall and DNS sinkhole immediately."*
    - If Suspicious: *"Anomalous traits detected. Quarantine asset and cross-reference proxy logs."*
    - If Benign: *"Known legitimate infrastructure or clean asset. No blocking recommended."*
- **Provenance Badges**:
  - `Tier 1: RDAP Verified` (Cyan pill)
  - `Tier 2: Direct Port 43` (Blue pill)
  - `Tier 3: Passive VT Fallback` (Orange pill)
  - `Privacy Protected` (Purple shield pill)
  - `Newly Registered Domain (<30d)` (Pulsing red alert pill)

---

#### Section 2: Left Column — Provider Reputation & Evidence Grid
- **Consensus Bar**:
  - Horizontal bar visualizing percentage of engines voting Malicious (Red), Suspicious (Amber), Clean (Green), No Data (Slate).
- **Filter Tabs**:
  - Buttons: `All Providers (11)`, `Flagged Only (3)`, `Clean (8)`, `No Data (0)`.
- **Individual Provider Cards**:
  - **Header**: Provider name, external link icon, latency badge (e.g., `420ms`), cache status (`Live Query` vs `Cache Hit`).
  - **Verdict Chip**: Color-coded normalized verdict.
  - **Telemetry Row**: Provider weight (e.g. `Weight: 1.1`), Evidence Signal (`+1.0`), Detection count (e.g., `52/89 engines`).
  - **Tags**: Threat taxonomy chips (e.g., `c2_server`, `malware:RedLine`, `scanner`).
  - **Collapsible Raw Inspector**: `<details>` dropdown revealing formatted JSON payload for that specific provider.

---

#### Section 3: Right Column — Domain-Specific Technical Widgets

##### For Domain / URL:
1. **Web Preview Card**:
   - Live screenshot thumbnail fetched through `/api/screenshot?scan_id={uuid}` (preventing IP leak).
   - Click-to-zoom modal for visual website inspection.
   - HTTP Server banner (e.g., `nginx/1.24.0`), HTML language, ASN name.
   - TLS Issuer and validity countdown (`Expires in 42 days`).
   - Brand Impersonation Alert: Pulsing banner if `detected_brands` contains impersonated targets (e.g., `Microsoft 365`, `PayPal`).
2. **WHOIS & Registration Provenance Card**:
   - Registrar name, registration date, expiration date.
   - Domain Age badge: Calculated in days, with a warning if `< 30 days`.
   - Nameservers list (e.g., `ns1.cloudflare.com`).
   - Data provenance tier indicator (Tier 1 vs 2 vs 3).
3. **Hosting Infrastructure Pivot Card**:
   - Resolved A-record IP address.
   - GreyNoise RIOT badge: If Cloudflare/Akamai/Fastly, highlights *"Known Good CDN (Bypassed recursive scan)"*.
   - Hosting provider / Autonomous System.
4. **Subdomains Explorer**:
   - Scrollable table of subdomains harvested from Certificate Transparency logs.
   - Inline search filter to instantly find `vpn.`, `mail.`, `api.` subdomains.

##### For IP Address:
1. **Host Vulnerability Matrix**:
   - Grid of open ports color-coded by service risk:
     - High-risk / Remote Admin (Red): Port 22 (SSH), Port 3389 (RDP), Port 445 (SMB), Port 23 (Telnet).
     - Standard Web (Blue): Port 80 (HTTP), Port 443 (HTTPS), Port 8080 (HTTP-Alt).
     - Database / Cache (Amber): Port 3306 (MySQL), Port 5432 (Postgres), Port 6379 (Redis).
   - Unpatched Software CVEs: Clickable CVE chips linking to NVD with CVSS severity.
   - Running Software CPEs: Software identifier strings (e.g., `cpe:/a:apache:http_server:2.4.49`).
   - Network Privacy Badges: `VPN`, `Tor Exit Node`, `Proxy`, `Datacenter`, `Anycast`.
2. **Abuse Complaints Timeline**:
   - Chronological feed of AbuseIPDB sysadmin complaints.
   - Reporter country flag, relative timestamp (`3 days ago`).
   - Threat category chips (`SSH Brute-Force`, `Port Scan`, `Web Attack`).
   - Truncated sysadmin comments with expand toggle.

##### For Email / Username / Password:
1. **Infostealer Attack Surface Card**:
   - Cavalier breach telemetry:
     - Metric 1: Total Employee Credentials Compromised.
     - Metric 2: Total Client Credentials Compromised.
     - Metric 3: Total Compromised URLs.
   - Stealer Family Breakdown: Bar chart or chip count (`RedLine: 12`, `Vidar: 4`, `Lumma: 2`).
   - Compromised Corporate Portals: List of exposed enterprise URLs (`vpn.company.com`, `okta.company.com`).
   - Password Hygiene Gauge: % of compromised passwords classified as Weak vs. Strong.
2. **Email Security Posture**:
   - Visual verification chips: `SPF: Pass`, `DKIM: Pass`, `DMARC: Pass`.
   - MX mail server delivery verification.
3. **Public Breach Timeline**:
   - Aggregated breach names and dates from XposedOrNot and COMB.

---

### 1.4 Edge Case UI Specifications

| Edge Case Scenario | Correct UI Presentation | What to AVOID |
| :--- | :--- | :--- |
| **Provider Rate Limited (HTTP 429)** | Show amber badge `Rate Limited (Free Tier Quota)`. Exclude from score denominator. | Do NOT show red "Error" or lower the score. |
| **Provider Not Found (404)** | Show slate badge `Not Found / Clean`. Explain that indicator is not in blocklist. | Do NOT treat as system failure. |
| **Newly Registered Domain (<30d)** | Pulsing red warning banner: `High Risk: Domain registered only X days ago`. | Do NOT display age as plain neutral text. |
| **Cloudflare / CDN IP on Domain Pivot** | Emerald badge: `Cloudflare Edge Node (Port scanning skipped to avoid CDN noise)`. | Do NOT scan shared CDN edge ports. |
| **Password Input** | Input masked with toggle. Green badge: `Hashed locally with SHA-1 before network send`. | Never send plaintext password over wire. |
| **Transient Network / DNS Outage** | Show toast `Retrying provider...` with countdown, retaining warm cache data. | Do NOT kill the entire analysis with a crash screen. |
| **Zero Positive Detections (Clean)** | Blue banner: `Clean Security Posture: 0 of 11 feeds flagged this asset`. | Do NOT display empty blank cards. |

---

## Part 2: Gap Analysis (Ideal UI Spec vs. Current UI)

Now we compare our Ideal Specification directly against the active frontend codebase (`ui/src/`).

---

### 2.1 Summary of Gaps

```
┌───────────────────────────────────────┬───────────────────┬───────────────────┬────────────────────────────────────┐
│ FEATURE AREA                          │ IDEAL SPEC        │ CURRENT UI        │ STATUS & GAP SEVERITY              │
├───────────────────────────────────────┼───────────────────┼───────────────────┼────────────────────────────────────┤
│ High-Value Technical Intelligence    │ Elevated to front │ Buried in 2nd-tier│ 🔴 CRITICAL: User has to click     │
│ (Screenshots, Port Matrix, Stealers)  │ 2-column dashboard│ "Enrichment" tab  │ "Enrichment" to see best features. │
├───────────────────────────────────────┼───────────────────┼───────────────────┼────────────────────────────────────┤
│ Landing Page vs Operational Console   │ Direct entry to   │ Dual tabs: Home   │ 🟠 MAJOR: Marketing landing page   │
│                                       │ triage console    │ vs Lookup         │ creates friction for SOC analysts. │
├───────────────────────────────────────┼───────────────────┼───────────────────┼────────────────────────────────────┤
│ Domain-Aware Layouts                  │ Dynamic layout per│ Identical layout  │ 🔴 CRITICAL: Domains, IPs, and     │
│                                       │ indicator type    │ for all IOC types │ Emails look identical.             │
├───────────────────────────────────────┼───────────────────┼───────────────────┼────────────────────────────────────┤
│ Raw Data Formatting                   │ Styled telemetry  │ JSON.stringify()  │ 🟠 MAJOR: Looks like raw debug     │
│                                       │ cards and chips   │ key-value dumps   │ console in several sections.       │
├───────────────────────────────────────┼───────────────────┼───────────────────┼────────────────────────────────────┤
│ Search Command Bar                    │ Smart defanger +  │ Basic text box +  │ 🟡 MEDIUM: Lacks one-click pills,  │
│                                       │ IOC selector pills│ simple dropdown   │ defanging on paste, k-anon cues.   │
├───────────────────────────────────────┼───────────────────┼───────────────────┼────────────────────────────────────┤
│ Radial Risk Dial                      │ Animated circular │ Plain text boxes  │ 🟡 MEDIUM: Lacks visual visual dial│
│                                       │ gauge (0-100)     │ in simple cards   │ expected by security analysts.     │
├───────────────────────────────────────┼───────────────────┼───────────────────┼────────────────────────────────────┤
│ Polling Resilience                    │ Tolerant polling  │ Aborts on 1st     │ 🟢 FIXED: Polling now tolerates    │
│                                       │ with retries      │ timeout (15s)     │ transient timeouts up to 20 cycles.│
└───────────────────────────────────────┴───────────────────┴───────────────────┴────────────────────────────────────┘
```

---

### 2.2 Deep Dive on Specific Deficiencies

#### Gap 1: The "Enrichment Tab Burial" Defect
- **In Current UI**:
  - In `ResultView.tsx`, the component loads the `Providers` tab by default.
  - The `Providers` tab ONLY shows `SourceCard` list items.
  - The screenshot (`WebPreviewCard`), open ports matrix (`HostVulnerabilityMatrix`), infostealer data (`InfostealerExposureCard`), abuse complaints (`AbuseReportsPanel`), and hosting pivot are mounted inside `EnrichmentPanel.tsx`.
  - Unless an analyst clicks the "Enrichment" tab, they believe the tool only checks simple blocklists.
- **The Fix**:
  - Convert `ResultView.tsx` into a **2-Column Layout**.
  - Left side: Providers & Reputation.
  - Right side: Automatically renders the appropriate technical widget (`WebPreviewCard` for domains, `HostVulnerabilityMatrix` for IPs, `InfostealerExposureCard` for credentials).

#### Gap 2: Raw `JSON.stringify` Key-Value Dumps
- **In Current UI**:
  - In `EnrichmentPanel.tsx`:
    ```typescript
    function Section({ title, data, badge }: ...) {
      return entries.map(([key, value]) => (
        <div>
          <span>{key.replace(/_/g, " ")}:</span>
          <span>{formatValue(value)}</span> // JSON.stringify
        </div>
      ))
    }
    ```
  - For DNS records, SSL certificates, and additional context, it outputs raw JSON strings onto the screen.
- **The Fix**:
  - Replace `Section` with typed visual components:
    - DNS records $\rightarrow$ Tabular DNS Record Inspector (Type, Host, Value, TTL).
    - SSL Certificate $\rightarrow$ Cryptographic Certificate Card (Issuer, Subject, Validity Days, SANs pills).
    - Wallet data $\rightarrow$ Financial Crime Balance Card with satoshi/ether formatting.

#### Gap 3: Confusing Navigation Structure
- **In Current UI**:
  - Two conflicting tab headers at the top of the screen:
    - Primary: `[ Home ] [ Lookup ]`
    - Sub-tabs: `[ Lookup ] [ Investigations ] [ Batch ] [ History ]`
  - Clicking `Home` takes the user to `Landing.tsx` (the marketing page). Clicking `Lookup` takes the user to `HomePage.tsx`.
- **The Fix**:
  - As requested, **keep `Landing.tsx`**, but give it a clear name: **`Capabilities & Guide`** or **`Overview`**.
  - Make the top bar a single, unified navigation header:
    `[ Overview & Docs ] | [ Investigation Console ] | [ Batch Triage ] | [ Case Management ] | [ History ]`.
  - Zero duplicate "Lookup" tabs.

#### Gap 4: Search Bar Defanging & Indicator Intelligence
- **In Current UI**:
  - `SearchBar.tsx` requires manual typing. If a user pastes `hxxps://badsite[.]com/login`, it passes defanged characters to the backend unless the backend handles it.
  - Password search is hidden behind a small checkbox without visual security confirmation.
- **The Fix**:
  - Add auto-refanger on paste (immediately transforms `hxxps://` $\rightarrow$ `https://` and `[.]` $\rightarrow$ `.`).
  - Add quick example indicator pills below search (`8.8.8.8`, `google.com`, `CVE-2021-44228`, `WannaCry`).
  - Add clear k-anonymity privacy shield badge when Password mode is active.

---

## Part 3: Step-by-Step UI Execution & Remediation Plan

To execute these fixes with **maximum quality** and without breaking working systems, the remediation is broken down into 4 focused phases:

---

### Phase 1: The Domain-Aware 2-Column Result Dashboard (`ResultView.tsx`)
- **File**: [`ui/src/pages/ResultView.tsx`](file:///d:/visual%20code%20file/Combined%20Project/ioc-platform/ui/src/pages/ResultView.tsx)
- **Actions**:
  1. Replace the single-column tabbed layout with the 55% / 45% responsive 2-column layout.
  2. Implement domain detection:
     - `isDomainOrUrl`: Renders `WebPreviewCard`, `WhoisProvenanceCard`, `HostingPivotCard`, `SubdomainsExplorer` in the right column.
     - `isIp`: Renders `HostVulnerabilityMatrix`, `AbuseReportsPanel`, `GeoIPCard` in the right column.
     - `isCredential`: Renders `InfostealerExposureCard`, `EmailSecurityCard`, `BreachTimeline` in the right column.
     - `isCve`: Renders `CveIntelligenceCard` with CVSS dial and CISA KEV badge in the right column.
  3. Left column hosts the Provider Consensus breakdown, filter buttons (`Flagged`, `Clean`, `All`), and correlated malware URLs/hashes.
  4. Bottom section hosts deep-dive tabs (`RelationshipGraph`, `EvidenceMath`, `RawJSON`).

---

### Phase 2: Threat Hero Banner & Radial Risk Gauge
- **Files**: [`ui/src/components/ScoreRing.tsx`](file:///d:/visual%20code%20file/Combined%20Project/ioc-platform/ui/src/components/ScoreRing.tsx), [`ui/src/components/VerdictBadge.tsx`](file:///d:/visual%20code%20file/Combined%20Project/ioc-platform/ui/src/components/VerdictBadge.tsx)
- **Actions**:
  1. Upgrade `ScoreRing` to render an animated SVG radial dial with color-stop gradients (Emerald $\rightarrow$ Amber $\rightarrow$ Crimson).
  2. Add bold executive SOC recommendations based on verdict.
  3. Integrate Data Provenance badges (Tier 1 RDAP, Newly registered `<30d`, Privacy Protected) directly onto the Hero banner.
  4. Add quick action buttons (`Refresh Live`, `Add to Case`, `Export Report`).

---

### Phase 3: Smart Command Bar & Defanging Engine
- **Files**: [`ui/src/components/SearchBar.tsx`](file:///d:/visual%20code%20file/Combined%20Project/ioc-platform/ui/src/components/SearchBar.tsx)
- **Actions**:
  1. Add automatic clipboard paste defanging (`hxxp` $\rightarrow$ `http`, `[.]` $\rightarrow$ `.`, strip quotes/spaces).
  2. Add indicator type selector dropdown with icons.
  3. Add client-side SHA-1 k-anonymity visual shield for password input.
  4. Add clickable sample indicator pills for instant testing.

---

### Phase 4: Navigation Clean-Up & Technical Inspector Polish
- **Files**: [`ui/src/App.tsx`](file:///d:/visual%20code%20file/Combined%20Project/ioc-platform/ui/src/App.tsx), [`ui/src/components/EnrichmentPanel.tsx`](file:///d:/visual%20code%20file/Combined%20Project/ioc-platform/ui/src/components/EnrichmentPanel.tsx)
- **Actions**:
  1. Keep `Landing.tsx` as `Overview & Capabilities`.
  2. Unify top navigation into a single, clean header: `[ Overview & Capabilities ] [ Investigation Console ] [ Batch Triage ] [ Cases ] [ History ]`.
  3. Eliminate all raw `JSON.stringify` dumps in `EnrichmentPanel` by replacing them with structured telemetry tables and DNS record inspectors.
  4. Verify production build (`npm run build`) and test all 8 indicator types.
