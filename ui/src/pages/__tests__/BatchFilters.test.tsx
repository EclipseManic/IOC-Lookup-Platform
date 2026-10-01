import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  getBatchStatus: vi.fn(),
  getBatchResult: vi.fn(),
  showToast: vi.fn(),
  ApiError: class ApiError extends Error {
    status: number;
    constructor(message: string, status: number) {
      super(message);
      this.status = status;
    }
  },
}));

vi.mock("../../services/api", () => ({
  ApiError: mocks.ApiError,
  errorMessage: (e: unknown, f = "Request failed") => (e instanceof Error && e.message ? e.message : f),
  startBatch: vi.fn(),
  getBatchStatus: mocks.getBatchStatus,
  getBatchResult: mocks.getBatchResult,
  cancelBatch: vi.fn(),
  uploadBatchFile: vi.fn(),
  saveBatchHistory: vi.fn(),
  buildLookupResponseFromBatch: vi.fn(() => ({}) as never),
}));

vi.mock("../../components/Toast", () => ({ showToast: mocks.showToast }));

// Render a marker per group so filtering is observable, plus the verdict.
vi.mock("../../components/IocAssessmentCard", () => ({
  default: ({ assessment }: { assessment: { ioc: string; final_verdict: string } }) => (
    <div data-testid="card">
      {assessment.ioc}|{assessment.final_verdict}
    </div>
  ),
}));

import Batch from "../Batch";

/** A batch with one IOC per outcome the filters must be able to isolate. */
function makeResult() {
  const base = {
    assessment_domain: "ioc_reputation",
    evidence_strength: 0.5,
    needs_review: false,
    cache_status: "fresh",
    evidence_summary: { expected_providers: 8, evaluated_providers: 8 },
    provider_breakdown: [],
    provider_health: [],
    malicious_sources: [],
    suspicious_sources: [],
    clean_sources: [],
    unknown_sources: [],
    not_found_sources: [],
    rate_limited_sources: [],
    unavailable_sources: [],
    error_sources: [],
    strongest_evidence: [],
    supporting_evidence: [],
    conflicting_evidence: [],
    context: [],
    mitre_attck: [],
    reason: "",
    analyst_review_recommended: false,
  };

  const iocs = [
    { ioc: "bad.example.com", ioc_type: "domain", final_verdict: "malicious", confidence: "high", normalized_score: 90, coverage: 1, freshness: "fresh", malware_families: ["Emotet"], provider_plan: [{ provider: "VirusTotal" }] },
    { ioc: "pwned@example.com", ioc_type: "email", final_verdict: "breached", confidence: "medium", normalized_score: 60, coverage: 1, freshness: "cached", malware_families: [], provider_plan: [{ provider: "HIBP" }] },
    { ioc: "8.8.8.8", ioc_type: "ipv4", final_verdict: "suspicious", confidence: "low", normalized_score: 45, coverage: 0.4, freshness: "live", malware_families: [], provider_plan: [{ provider: "GreyNoise" }] },
    { ioc: "good.example.org", ioc_type: "domain", final_verdict: "clean", confidence: "high", normalized_score: 5, coverage: 1, freshness: "fresh", malware_families: [], provider_plan: [{ provider: "VirusTotal" }] },
  ];

  return {
    batch_id: "b1",
    status: "done",
    progress: 100,
    total: iocs.length,
    completed: iocs.length,
    summary: { malicious: 1, breached: 1, suspicious: 1, clean: 1, unknown: 0, error: 0 },
    results: iocs.map((i) => ({
      ioc: i.ioc,
      ioc_type: i.ioc_type,
      source: i.provider_plan[0].provider,
      verdict: i.final_verdict,
      status: "success",
      execution_state: "success",
    })),
    assessments: iocs.map((i) => ({ ...base, ...i })),
  };
}

function shownCards(): string[] {
  return screen.queryAllByTestId("card").map((n) => n.textContent ?? "");
}

function counter(): string {
  const match = /Showing (\d+) of (\d+) unique IOCs/.exec(document.body.textContent ?? "");
  return match ? `${match[1]}/${match[2]}` : "?";
}

async function renderBatch() {
  sessionStorage.setItem("ioc-platform.active-batch", "b1");
  render(<Batch />);
  await waitFor(() => expect(screen.getAllByTestId("card").length).toBe(4));
}

function select(label: RegExp, value: string) {
  fireEvent.change(screen.getByRole("combobox", { name: label }), { target: { value } });
}

beforeEach(() => {
  sessionStorage.clear();
  mocks.showToast.mockReset();
  mocks.getBatchStatus.mockResolvedValue({
    batch_id: "b1", status: "done", progress: 100, total: 4, completed: 4, subtasks: [],
  });
  mocks.getBatchResult.mockResolvedValue(makeResult());
});

describe("Batch filters", () => {
  it("shows every group before any filter is applied", async () => {
    await renderBatch();
    expect(shownCards()).toHaveLength(4);
    expect(counter()).toBe("4/4");
  });

  it("filters by verdict", async () => {
    await renderBatch();
    select(/verdict/i, "malicious");
    expect(shownCards()).toEqual(["bad.example.com|malicious"]);
    expect(counter()).toBe("1/4");
  });

  it("filters by the breached verdict, which is not malicious", async () => {
    await renderBatch();
    select(/verdict/i, "breached");
    expect(shownCards()).toEqual(["pwned@example.com|breached"]);
  });

  it("filters by IOC type", async () => {
    await renderBatch();
    select(/ioc type/i, "ipv4");
    expect(shownCards()).toEqual(["8.8.8.8|suspicious"]);
  });

  it("filters by provider", async () => {
    await renderBatch();
    select(/provider/i, "HIBP");
    expect(shownCards()).toEqual(["pwned@example.com|breached"]);
  });

  it("filters by confidence", async () => {
    await renderBatch();
    select(/confidence/i, "low");
    expect(shownCards()).toEqual(["8.8.8.8|suspicious"]);
  });

  it("filters by risk band", async () => {
    await renderBatch();
    select(/risk/i, "high");
    expect(shownCards()).toEqual(["bad.example.com|malicious"]);
  });

  it("filters by coverage", async () => {
    await renderBatch();
    select(/coverage/i, "low");
    expect(shownCards()).toEqual(["8.8.8.8|suspicious"]);
  });

  it("filters by malware family", async () => {
    await renderBatch();
    fireEvent.change(screen.getByPlaceholderText(/malware/i), { target: { value: "emotet" } });
    expect(shownCards()).toEqual(["bad.example.com|malicious"]);
  });

  it("filters by free-text search across value and provider", async () => {
    await renderBatch();
    fireEvent.change(screen.getByPlaceholderText(/search/i), { target: { value: "pwned" } });
    expect(shownCards()).toEqual(["pwned@example.com|breached"]);
  });

  it("combines filters rather than replacing them", async () => {
    await renderBatch();
    select(/verdict/i, "malicious");
    select(/ioc type/i, "ipv4");
    expect(shownCards()).toEqual([]);
    expect(counter()).toBe("0/4");
  });

  it("says so when nothing matches", async () => {
    await renderBatch();
    select(/ioc type/i, "cve");
    expect(screen.getByText(/No IOCs match the current filters/i)).toBeTruthy();
  });
});
