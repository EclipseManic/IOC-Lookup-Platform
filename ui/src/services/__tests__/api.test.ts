import { afterEach, describe, expect, it, vi } from "vitest";
import { lookupIOC } from "../api";

describe("lookupIOC", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it.each(["d41d8cd98f00b204e9800998ecf8427e", "CVE-2024-3094"])(
    "sends %s using the API ioc field",
    async (value) => {
      const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
        new Response(JSON.stringify({ task_id: "task-1", status: "pending" }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        }),
      );

      await lookupIOC(value);

      expect(fetchMock).toHaveBeenCalledOnce();
      const [path, options] = fetchMock.mock.calls[0];
      expect(path).toBe("/api/lookup");
      expect(options?.body).toBe(JSON.stringify({ ioc: value }));
    },
  );
});
