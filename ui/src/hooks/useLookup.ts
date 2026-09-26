import { useCallback, useEffect, useRef, useState } from "react";
import type { LookupResponse, StageInfo, TaskResponse } from "../services/api";
import { ApiError, cancelTask, getRecentIOCResult, getStoredLookup, getTaskResult, getTaskStatus, lookupIOC, saveLookup } from "../services/api";

export interface ResultSourceMeta {
  isHistorical?: boolean;
  fromBatch?: boolean;
  batchId?: string;
  historyId?: number;
  scannedAt?: string | null;
}

export type LookupState =
  | { status: "idle" }
  | { status: "loading"; progress: number; stages: StageInfo[]; taskId: string }
  | { status: "done"; result: LookupResponse; meta?: ResultSourceMeta }
  | { status: "error"; error: string };

export function useLookup() {
  const [state, setState] = useState<LookupState>({ status: "idle" });
  const pollingRef = useRef<number | null>(null);
  const pollGenerationRef = useRef(0);
  const activeTaskIdRef = useRef<string | null>(null);

  const stopPolling = useCallback(() => {
    pollGenerationRef.current += 1;
    if (pollingRef.current !== null) {
      clearTimeout(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  useEffect(() => () => stopPolling(), [stopPolling]);

  const loadResult = useCallback((result: LookupResponse, meta?: ResultSourceMeta) => {
    const taskId = activeTaskIdRef.current;
    activeTaskIdRef.current = null;
    stopPolling();
    if (taskId) {
      cancelTask(taskId).catch((error) => console.debug("Task cancellation failed", error));
    }
    setState({ status: "done", result, meta });
  }, [stopPolling]);

  const loadStored = useCallback(async (iocId?: number, iocValue?: string, meta?: ResultSourceMeta) => {
    stopPolling();
    const generation = pollGenerationRef.current;
    try {
      let result: LookupResponse | null = null;
      if (iocId) {
        result = await getRecentIOCResult(iocId);
      } else if (iocValue) {
        result = await getStoredLookup(iocValue);
      }
      if (result && generation === pollGenerationRef.current) {
        setState({
          status: "done",
          result,
          meta: { ...meta, isHistorical: true, scannedAt: meta?.scannedAt || (result as any).created_at },
        });
        return true;
      }
    } catch (e) {
      console.debug("Failed to load stored result, falling back to fresh lookup", e);
    }
    return false;
  }, [stopPolling]);

  const submit = useCallback(async (value: string, iocType?: string, refresh = false) => {
    stopPolling();
    const generation = pollGenerationRef.current;
    try {
      const task: TaskResponse = await lookupIOC(value, iocType, { refresh });
      if (generation !== pollGenerationRef.current) return;
      const taskId = task.task_id;
      activeTaskIdRef.current = taskId;
      setState({
        status: "loading",
        progress: task.progress ?? 0,
        stages: task.stages ?? [],
        taskId,
      });

      let pollFailures = 0;
      const poll = async () => {
        if (generation !== pollGenerationRef.current) return;
        try {
          const result = await getTaskResult(taskId);
          if (generation !== pollGenerationRef.current) return;
          stopPolling();
          activeTaskIdRef.current = null;
          setState({ status: "done", result });
          saveLookup(result.normalized ?? value, iocType, taskId).catch((e) => {
            console.debug("saveLookup failed", e);
          });
        } catch (e: unknown) {
          if (generation !== pollGenerationRef.current) return;
          if (e instanceof ApiError && e.status === 425) {
            pollFailures = 0;
            try {
              const status = await getTaskStatus(taskId);
              if (generation === pollGenerationRef.current) {
                if (status.status === "error" || status.status === "cancelled") {
                  stopPolling();
                  activeTaskIdRef.current = null;
                  setState({
                    status: "error",
                    error: status.error || (status.status === "cancelled" ? "Analysis was cancelled" : "Analysis failed"),
                  });
                  return;
                }
                setState((prev) =>
                  prev.status === "loading"
                    ? {
                        ...prev,
                        progress: status.progress ?? prev.progress,
                        stages: status.stages ?? prev.stages,
                      }
                    : prev
                );
              }
            } catch {
              // ignore poll errors
            }
          } else if (
            e instanceof ApiError &&
            (e.detail === "timeout" || e.status === 0 || e.status === 502 || e.status === 503 || e.status === 504)
          ) {
            // Allow transient poll timeouts or network hiccups while analysis completes
            pollFailures++;
            if (pollFailures > 20) {
              stopPolling();
              activeTaskIdRef.current = null;
              setState({
                status: "error",
                error: "Analysis timed out. The server took too long to complete.",
              });
              return;
            }
          } else {
            stopPolling();
            setState({
              status: "error",
              error:
                e instanceof ApiError && e.detail
                  ? e.detail
                  : e instanceof Error
                  ? e.message
                  : "Lookup failed",
            });
            return;
          }
        }
        if (generation === pollGenerationRef.current) {
          pollingRef.current = window.setTimeout(() => {
            void poll();
          }, 1000);
        }
      };
      pollingRef.current = window.setTimeout(() => {
        void poll();
      }, 1000);
    } catch (e: unknown) {
      if (generation === pollGenerationRef.current) {
        setState({
          status: "error",
          error:
            e instanceof ApiError && e.detail
              ? e.detail
              : e instanceof Error
              ? e.message
              : "Lookup failed",
        });
      }
    }
  }, [stopPolling]);

  const reset = useCallback(() => {
    const taskId = activeTaskIdRef.current;
    activeTaskIdRef.current = null;
    stopPolling();
    if (taskId) {
      cancelTask(taskId).catch((error) => console.debug("Task cancellation failed", error));
    }
    setState({ status: "idle" });
  }, [stopPolling]);

  return { state, submit, reset, loadResult, loadStored };
}
