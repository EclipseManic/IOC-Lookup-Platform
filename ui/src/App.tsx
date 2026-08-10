import { useCallback, useEffect, useState } from "react";
import ErrorBoundary from "./components/ErrorBoundary";
import ToastContainer from "./components/Toast";
import HomePage from "./pages/HomePage";
import History from "./pages/History";
import Investigations from "./pages/Investigations";
import Batch from "./pages/Batch";

export type Page = "home" | "investigations" | "batch" | "history";

export interface NavigateEvent {
  page: Page;
  ioc?: string;
}

const NAV: { id: Page; label: string }[] = [
  { id: "home", label: "Lookup" },
  { id: "investigations", label: "Investigations" },
  { id: "batch", label: "Batch" },
  { id: "history", label: "History" },
];

const VALID_PAGES = new Set<string>(NAV.map((n) => n.id));

function parseLocation(): { page: Page; ioc: string } {
  const params = new URLSearchParams(window.location.search);
  const raw = params.get("page") ?? "";
  const page: Page = VALID_PAGES.has(raw) ? (raw as Page) : "home";
  const ioc = params.get("ioc") ?? "";
  return { page, ioc };
}

export default function App() {
  const [{ page, ioc }, setRoute] = useState(parseLocation);

  useEffect(() => {
    function onPopState() {
      setRoute(parseLocation());
    }
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);

  const navigate = useCallback((next: Page, iocValue = "") => {
    const url = new URL(window.location.href);
    if (next === "home") {
      url.searchParams.delete("page");
    } else {
      url.searchParams.set("page", next);
    }
    if (iocValue) {
      url.searchParams.set("ioc", iocValue);
    } else {
      url.searchParams.delete("ioc");
    }
    window.history.pushState({}, "", url.toString());
    setRoute({ page: next, ioc: iocValue });
  }, []);

  useEffect(() => {
    function handler(e: Event) {
      const d = (e as CustomEvent<NavigateEvent>).detail;
      navigate(d.page, d.ioc ?? "");
    }
    window.addEventListener("navigate", handler);
    return () => window.removeEventListener("navigate", handler);
  }, [navigate]);

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary">
      <nav className="border-b border-border bg-bg-secondary px-6 py-3 flex items-center gap-6" aria-label="Main navigation">
        <a
          href={`${window.location.pathname}${window.location.search}`}
          onClick={(e) => { e.preventDefault(); navigate("home"); }}
          className="text-lg font-bold bg-gradient-to-r from-accent to-accent-secondary bg-clip-text text-transparent"
          aria-label="Home"
        >
          IOC Platform
        </a>
        <div className="flex gap-4 text-sm text-text-secondary" role="tablist">
          {NAV.map((n) => (
            <button
              key={n.id}
              onClick={() => navigate(n.id)}
              role="tab"
              aria-selected={page === n.id}
              className={`hover:text-text-primary transition-colors ${page === n.id ? "text-text-primary" : ""}`}
            >
              {n.label}
            </button>
          ))}
        </div>
      </nav>

      <main className="p-6 max-w-6xl mx-auto">
        {page === "home" && (
          <ErrorBoundary>
            <HomePage key={`home-${ioc}`} initialValue={ioc} />
          </ErrorBoundary>
        )}
        {page === "investigations" && (
          <ErrorBoundary>
            <Investigations />
          </ErrorBoundary>
        )}
        {page === "batch" && (
          <ErrorBoundary>
            <Batch />
          </ErrorBoundary>
        )}
        {page === "history" && (
          <ErrorBoundary>
            <History />
          </ErrorBoundary>
        )}
      </main>

      <ToastContainer />
    </div>
  );
}
