import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

const mocks = vi.hoisted(() => ({
  startBatch: vi.fn(),
  getBatchStatus: vi.fn(),
  getBatchResult: vi.fn(),
  cancelBatch: vi.fn(),
  uploadBatchFile: vi.fn(),
  saveBatchHistory: vi.fn(),
  buildLookupResponseFromBatch: vi.fn(() => ({}) as never),
  showToast: vi.fn(),
}));

const { startBatch, getBatchStatus, getBatchResult, showToast } = mocks;

vi.mock("../../services/api", () => ({
  startBatch: mocks.startBatch,
  getBatchStatus: mocks.getBatchStatus,
  getBatchResult: mocks.getBatchResult,
  cancelBatch: mocks.cancelBatch,
  uploadBatchFile: mocks.uploadBatchFile,
  saveBatchHistory: mocks.saveBatchHistory,
  buildLookupResponseFromBatch: mocks.buildLookupResponseFromBatch,
}));

vi.mock("../../components/Toast", () => ({ showToast: mocks.showToast }));

vi.mock("../../components/IocAssessmentCard", () => ({
  default: ({ assessment }: { assessment: { ioc: string } }) => (
    <div data-testid="assessment-card">{assessment.ioc}</div>
  ),
}));

vi.mock("../../components/VerdictBadge", () => ({
  default: ({ verdict }: { verdict: string }) => <span>{verdict}</span>,
}));

import Batch from "../Batch";

const STATUS_DONE = {
  batch_id: "batch-1",
  status: "done",
  progress: 100,
  total: 11,
  completed: 11,
  expected_lookups: 56,
  completed_lookups: 56,
  successful_lookups: 40,
  not_found_lookups: 16,
  rate_limited_lookups: 0,
  timeout_lookups: 0,
  failed_lookups: 0,
  subtasks: [],
};

function makeResult() {
  return {
    batch_id: "batch-1",
    status: "done",
    progress: 100,
    total: 11,
    completed: 11,
    expected_lookups: 56,
    completed_lookups: 56,
    successful_lookups: 40,
    not_found_lookups: 16,
    rate_limited_lookups: 0,
    timeout_lookups: 0,
    failed_lookups: 0,
    not_applicable_lookups: 3,
    batch_deadline_exceeded: 0,
    summary: { malicious: 2, suspicious: 0, clean: 0, unknown: 9, error: 0 },
    assessment_distribution: {},
    execution_health: {},
    relationships: [],
    provider_health: [],
    results: [
      {
        ioc: "coinhive.com",
        ioc_type: "domain",
        source: "VirusTotal",
        verdict: "malicious",
        status: "success",
        execution_state: "success",
        provider_verdict: "malicious",
        normalized_verdict: "malicious",
        raw_score: 0.98,
        confidence: "high",
      },
    ],
    assessments: [
      {
        ioc: "coinhive.com",
        normalized_ioc: "coinhive.com",
        ioc_type: "domain",
        assessment_domain: "ioc_reputation",
        final_verdict: "malicious",
        confidence: "high",
        normalized_score: 88.8,
        evidence_strength: 0.9,
        coverage: 1,
        needs_review: true,
        cache_status: "fresh",
        evidence_summary: { expected_providers: 8, evaluated_providers: 8 },
        provider_breakdown: [],
        provider_health: [],
        malicious_sources: ["VirusTotal"],
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
        malware_families: [],
        mitre_attck: [],
        reason: "Multiple independent sources corroborate malicious evidence.",
        analyst_review_recommended: true,
      },
    ],
  };
}

async function startBatchAndWait() {
  render(<Batch />);
  fireEvent.change(screen.getByRole("textbox"), { target: { value: "domain:coinhive.com" } });
  fireEvent.click(screen.getByRole("button", { name: /analyze/i }));
  await vi.advanceTimersByTimeAsync(1500);
}

describe("Batch polling terminal states", () => {
  beforeEach(() => {
    vi.useFakeTimers({ shouldAdvanceTime: true });
    vi.clearAllMocks();
    startBatch.mockResolvedValue({ batch_id: "batch-1", total: 11, status: "pending" });
    getBatchStatus.mockResolvedValue(STATUS_DONE);
    getBatchResult.mockResolvedValue(makeResult());
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  it("renders results when a finished batch reports done", async () => {
    await startBatchAndWait();

    expect(getBatchStatus).toHaveBeenCalled();
    expect(getBatchResult).toHaveBeenCalled();
    await waitFor(() => {
      expect(screen.getByTestId("assessment-card")).toBeTruthy();
    });
    expect(screen.getByText("coinhive.com")).toBeTruthy();
    expect(screen.queryByRole("button", { name: /cancel batch/i })).toBeNull();
    expect(screen.getByRole("button", { name: /re-scan batch/i })).toBeTruthy();
  });

  it("still shows the progress card while the batch is running", async () => {
    getBatchStatus.mockResolvedValue({ ...STATUS_DONE, status: "running", progress: 42, completed: 5 });
    render(<Batch />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "domain:coinhive.com" } });
    fireEvent.click(screen.getByRole("button", { name: /analyze/i }));
    await vi.advanceTimersByTimeAsync(1500);

    expect(screen.getByRole("button", { name: /cancel batch/i })).toBeTruthy();
    expect(screen.getByText(/Processing 5\/11 IOCs/)).toBeTruthy();
    expect(screen.queryByTestId("assessment-card")).toBeNull();
  });

  it("renders the partial result when a batch is cancelled", async () => {
    getBatchStatus.mockResolvedValue({ ...STATUS_DONE, status: "cancelled" });
    getBatchResult.mockResolvedValue({ ...makeResult(), status: "cancelled" });
    render(<Batch />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "domain:coinhive.com" } });
    fireEvent.click(screen.getByRole("button", { name: /analyze/i }));
    await vi.advanceTimersByTimeAsync(1500);

    await waitFor(() => {
      expect(screen.getByTestId("assessment-card")).toBeTruthy();
    });
    expect(screen.queryByRole("button", { name: /cancel batch/i })).toBeNull();
  });

  it("surfaces a batch error instead of hanging on the progress card", async () => {
    getBatchStatus.mockResolvedValue({ ...STATUS_DONE, status: "error", error: "provider storm" });
    render(<Batch />);
    fireEvent.change(screen.getByRole("textbox"), { target: { value: "domain:coinhive.com" } });
    fireEvent.click(screen.getByRole("button", { name: /analyze/i }));
    await vi.advanceTimersByTimeAsync(1500);

    expect(showToast).toHaveBeenCalledWith("provider storm", "error");
    expect(screen.queryByRole("button", { name: /cancel batch/i })).toBeNull();
  });
});
