import { useCallback, useRef, useState } from "react";
import type { LookupResponse, StageInfo, TaskResponse } from "../services/api";
import { getTaskResult, getTaskStatus, lookupIOC } from "../services/api";

export type LookupState =
  | { status: "idle" }
  | { status: "loading"; progress: number; stages: StageInfo[]; taskId: string }
  | { status: "done"; result: LookupResponse }
  | { status: "error"; error: string };

export function useLookup() {
  const [state, setState] = useState<LookupState>({ status: "idle" });
  const pollingRef = useRef<number | null>(null);

  const stopPolling = useCallback(() => {
    if (pollingRef.current !== null) {
      clearInterval(pollingRef.current);
      pollingRef.current = null;
    }
  }, []);

  const submit = useCallback(async (value: string) => {
    stopPolling();
    try {
      const task: TaskResponse = await lookupIOC(value);
      const taskId = task.task_id;
      setState({
        status: "loading",
        progress: task.progress,
        stages: task.stages,
        taskId,
      });

      const interval = window.setInterval(async () => {
        try {
          const result = await getTaskResult(taskId);
          stopPolling();
          setState({ status: "done", result });
        } catch (e: any) {
          if (e.message === "not_ready") {
            try {
              const status = await getTaskStatus(taskId);
              setState((prev) =>
                prev.status === "loading"
                  ? { ...prev, progress: status.progress, stages: status.stages }
                  : prev
              );
            } catch {
              // ignore poll errors
            }
          } else {
            stopPolling();
            setState({ status: "error", error: e.message });
          }
        }
      }, 1000);
      pollingRef.current = interval;
    } catch (e: any) {
      setState({ status: "error", error: e.message });
    }
  }, [stopPolling]);

  const reset = useCallback(() => {
    stopPolling();
    setState({ status: "idle" });
  }, [stopPolling]);

  return { state, submit, reset };
}
