import { useCallback, useEffect, useRef, useState } from "react";
import ErrorBoundary from "./components/ErrorBoundary";
import ToastContainer from "./components/Toast";
import Landing from "./pages/Landing";
import HomePage from "./pages/HomePage";

export type Page = "home" | "lookup";
export type Tool = "investigations" | "batch" | "history";

export interface NavigateEvent {
  page: Page;
  tool?: Tool | null;
  ioc?: string;
  batchId?: string;
}

const PRIMARY_TABS: { id: Page; label: string }[] = [
  { id: "home", label: "Home" },
  { id: "lookup", label: "Lookup" },
];

const TOOL_TABS: { id: Tool | "lookup"; label: string }[] = [
  { id: "lookup", label: "Lookup" },
  { id: "investigations", label: "Investigations" },
  { id: "batch", label: "Batch" },
  { id: "history", label: "History" },
];

const VALID_PAGES = new Set<string>(PRIMARY_TABS.map((n) => n.id));
const TOOL_IDS = new Set<string>(["investigations", "batch", "history"]);
const PRIMARY_TAB_IDS = PRIMARY_TABS.map((t) => t.id);
const TOOL_TAB_IDS = TOOL_TABS.map((t) => t.id);

export interface RouteState {
  page: Page;
  tool: Tool | null;
  ioc: string;
  batchId: string;
}

function parseLocation(): RouteState {
  const params = new URLSearchParams(window.location.search);
  const raw = params.get("page") ?? "";
  const toolRaw = params.get("tool") ?? "";
  const ioc = params.get("ioc") ?? "";
  const batchId = params.get("batch") ?? "";
  // Back-compat: legacy `?page=batch`-style deep links map to a Lookup sub-tab.
  if (TOOL_IDS.has(raw)) {
    return { page: "lookup", tool: raw as Tool, ioc, batchId };
  }
  const page: Page = VALID_PAGES.has(raw) ? (raw as Page) : "home";
  const tool: Tool | null = page === "lookup" && TOOL_IDS.has(toolRaw) ? (toolRaw as Tool) : null;
  return { page, tool, ioc, batchId };
}

function useTabsKeyNav(list: readonly string[], active: string, onSelect: (id: string) => void) {
  const listRef = useRef<HTMLDivElement>(null);
  const handleKeyDown = useCallback((e: React.KeyboardEvent) => {
    const idx = list.indexOf(active);
    let nextIdx: number | null = null;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % list.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + list.length) % list.length;
    if (nextIdx === null) return;
    e.preventDefault();
    onSelect(list[nextIdx]);
    const buttons = listRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    buttons?.[nextIdx]?.focus();
  }, [list, active, onSelect]);
  return { listRef, handleKeyDown };
}

export default function App() {
  const [{ page, tool, ioc, batchId }, setRoute] = useState(parseLocation);

  useEffect(() => {
    if (document.activeElement?.closest('[role="tablist"]')) return;
    const id =
      page === "home" ? "page-home" : tool ? `panel-${tool}` : "page-lookup";
    document.getElementById(id)?.focus({ preventScroll: true });
  }, [page, tool]);

  useEffect(() => {
    function onPopState() {
      setRoute(parseLocation());
    }
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback((next: Page, nextTool: Tool | null = null, iocValue = "", nextBatchId = "") => {
    if (next === page && nextTool === tool && iocValue === ioc && nextBatchId === batchId) return;
    const url = new URL(window.location.href);
    const params = url.searchParams;
    if (next === "home") {
      params.delete("page");
      params.delete("tool");
      params.delete("ioc");
      params.delete("batch");
    } else {
      params.set("page", "lookup");
      if (nextTool) {
        params.set("tool", nextTool);
      } else {
        params.delete("tool");
      }
      if (iocValue) {
        params.set("ioc", iocValue);
      } else {
        params.delete("ioc");
      }
      if (nextBatchId) params.set("batch", nextBatchId); else params.delete("batch");
    }
    window.history.pushState({}, "", url.toString());
    setRoute({ page: next, tool: nextTool, ioc: iocValue, batchId: nextBatchId });
  }, [batchId, ioc, page, tool]);

  useEffect(() => {
    function onIocSync(e: Event) {
      const value = (e as CustomEvent<{ value: string }>).detail?.value;
      if (!value || page !== "lookup" || tool !== null) return;
      setRoute((prev) => (prev.ioc === value ? prev : { ...prev, ioc: value }));
      const url = new URL(window.location.href);
      const params = url.searchParams;
      params.set("page", "lookup");
      params.delete("tool");
      params.set("ioc", value);
      window.history.replaceState({}, "", url.toString());
    }
    window.addEventListener("ioc-sync", onIocSync);
    return () => window.removeEventListener("ioc-sync", onIocSync);
  }, [page, tool]);

  useEffect(() => {
    function handler(e: Event) {
      const d = (e as CustomEvent<NavigateEvent>).detail;
      navigate(d.page, d.tool ?? null, d.ioc ?? "", d.batchId ?? "");
    }
    window.addEventListener("navigate", handler);
    return () => window.removeEventListener("navigate", handler);
  }, [navigate]);

  const activeTool: Tool | "lookup" | null = page === "lookup" ? (tool ?? "lookup") : null;

  const primaryOnSelect = useCallback((id: string) => navigate(id as Page), [navigate]);
  const toolOnSelect = useCallback((id: string) => {
    navigate("lookup", id === "lookup" ? null : (id as Tool), ioc);
  }, [navigate, ioc]);
  const primaryKeys = useTabsKeyNav(PRIMARY_TAB_IDS, page, primaryOnSelect);
  const toolKeys = useTabsKeyNav(TOOL_TAB_IDS, activeTool ?? "lookup", toolOnSelect);

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary">
      <div className="scanline-overlay" aria-hidden="true" />
      <nav
        className="sticky top-0 z-50 border-b border-border bg-bg-secondary/85 backdrop-blur px-6 py-3 flex flex-wrap items-center gap-x-6 gap-y-2 relative"
        aria-label="Main navigation"
      >
        <a
          href={`${window.location.pathname}${window.location.search}`}
          onClick={(e) => { e.preventDefault(); navigate("home"); }}
          className="text-lg font-bold bg-gradient-to-r from-accent to-accent-secondary bg-clip-text text-transparent"
          aria-label="Home"
        >
          IOC Platform
        </a>

        <div className="lg:absolute lg:left-1/2 lg:-translate-x-1/2 max-lg:flex-1 max-lg:flex max-lg:justify-center">
          <div
            ref={primaryKeys.listRef}
            onKeyDown={primaryKeys.handleKeyDown}
            className="inline-flex gap-1 p-1 bg-bg-card border border-border rounded-lg"
            role="tablist"
            aria-label="Primary pages"
          >
            {PRIMARY_TABS.map((tab) => (
              <button
                key={tab.id}
                id={`tab-${tab.id}`}
                onClick={() => navigate(tab.id)}
                role="tab"
                aria-selected={page === tab.id}
                aria-controls={`page-${tab.id}`}
                tabIndex={page === tab.id ? 0 : -1}
                className={`px-4 py-1.5 text-sm font-medium rounded-md transition-colors ${
                  page === tab.id
                    ? "text-accent bg-bg-elevated shadow-[0_0_12px_rgba(250,204,21,0.25)]"
                    : "text-text-secondary hover:text-text-primary"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>

        <div className="w-full lg:w-auto lg:ml-auto flex flex-wrap items-center gap-2">
          <div
            ref={toolKeys.listRef}
            onKeyDown={toolKeys.handleKeyDown}
            className="flex flex-wrap md:flex-nowrap gap-1 p-1 bg-bg-card border border-border rounded-lg"
            role="tablist"
            aria-label="Lookup tools"
          >
            {TOOL_TABS.map((tab) => (
              <button
                key={tab.id}
                id={`tab-tool-${tab.id}`}
                onClick={() => navigate("lookup", tab.id === "lookup" ? null : (tab.id as Tool), ioc)}
                role="tab"
                aria-selected={page === "lookup" && activeTool === tab.id}
                aria-controls={page === "lookup" ? `panel-${tab.id}` : undefined}
                tabIndex={
                  page === "lookup" && activeTool === tab.id ? 0 : page === "home" && tab.id === "lookup" ? 0 : -1
                }
                className={`px-3 py-1.5 text-sm font-medium rounded-md transition-colors ${
                  page === "lookup" && activeTool === tab.id
                    ? "text-accent bg-bg-elevated shadow-[0_0_12px_rgba(250,204,21,0.25)]"
                    : "text-text-secondary hover:text-text-primary"
                }`}
              >
                {tab.label}
              </button>
            ))}
          </div>
        </div>
      </nav>

      <main className="px-4 sm:px-6 py-6 max-w-[1500px] mx-auto">
        {page === "home" && (
          <div id="page-home" role="tabpanel" aria-labelledby="tab-home" tabIndex={-1} className="page-enter outline-none">
            <ErrorBoundary>
              <Landing />
            </ErrorBoundary>
          </div>
        )}
        {page === "lookup" && (
          <div id="page-lookup" role="tabpanel" aria-labelledby="tab-lookup" tabIndex={-1} className="outline-none">
            <ErrorBoundary>
              <HomePage initialValue={ioc} tool={tool} initialBatchId={batchId} />
            </ErrorBoundary>
          </div>
        )}
      </main>

      <ToastContainer />
    </div>
  );
}
