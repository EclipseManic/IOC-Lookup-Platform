import { afterEach, describe, expect, it, vi } from "vitest";
import { lookupIOC, saveLookup } from "../api";

describe("lookupIOC", () => {
  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllEnvs();
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

  it("can explicitly bypass the local cache for a live refresh", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ task_id: "task-refresh", status: "pending" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await lookupIOC("example.com", "domain", { refresh: true });

    const [, options] = fetchMock.mock.calls[0];
    expect(options?.body).toBe(JSON.stringify({ ioc: "example.com", ioc_type: "domain", refresh: true }));
  });

  it("adds the optional deployment API key to requests", async () => {
    vi.stubEnv("VITE_API_KEY", "test-secret");
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ task_id: "task-auth", status: "pending" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await lookupIOC("example.com");

    const [, options] = fetchMock.mock.calls[0];
    expect(new Headers(options?.headers).get("X-API-Key")).toBe("test-secret");
  });
});

describe("saveLookup", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("posts the ioc, type and task_id to /api/save", async () => {
    const fetchMock = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      new Response(JSON.stringify({ status: "saved" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    await saveLookup("evil.example.com", "domain", "task-42");

    expect(fetchMock).toHaveBeenCalledOnce();
    const [path, options] = fetchMock.mock.calls[0];
    expect(path).toBe("/api/save");
    expect(options?.method).toBe("POST");
    expect(options?.body).toBe(
      JSON.stringify({ ioc: "evil.example.com", ioc_type: "domain", task_id: "task-42" }),
    );
  });
});
