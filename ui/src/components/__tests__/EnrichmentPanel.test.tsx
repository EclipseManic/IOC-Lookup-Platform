import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import EnrichmentPanel from "../EnrichmentPanel";
import type { EnrichmentData } from "../../services/api";

describe("EnrichmentPanel", () => {
  it("shows collection status and preserves nested evidence", () => {
    const enrichment = {
      open_ports: [],
      redirect_chain: [],
      url_preview: {},
      relationships: [],
      completeness: { whois: "ok", passive_dns: "error" },
      extra: { provider: { detail: "available" } },
      passive_dns: { records: [{ hostname: "eclipsemanic.me", address: "185.199.109.153" }] },
    } as EnrichmentData;

    render(<EnrichmentPanel enrichment={enrichment} />);

    expect(screen.getByText("Collection Status")).toBeTruthy();
    expect(screen.getByText(/passive dns/)).toBeTruthy();
    expect(screen.getByText(/185\.199\.109\.153/)).toBeTruthy();
    expect(screen.getByText(/available/)).toBeTruthy();
  });
});
