import { useEffect, useState } from "react";
import ErrorBoundary from "./components/ErrorBoundary";
import ToastContainer from "./components/Toast";
import HomePage from "./pages/HomePage";
import History from "./pages/History";
import Investigations from "./pages/Investigations";
import Batch from "./pages/Batch";

type Page = "home" | "investigations" | "batch" | "history";

const NAV: { id: Page; label: string }[] = [
  { id: "home", label: "Lookup" },
  { id: "investigations", label: "Investigations" },
  { id: "batch", label: "Batch" },
  { id: "history", label: "History" },
];

function getInitialIOC(): string {
  try {
    return new URLSearchParams(window.location.search).get("ioc") || "";
  } catch { return ""; }
}

export default function App() {
  const [page, setPage] = useState<Page>(getInitialIOC() ? "home" : "home");
  const [searchOnLoad, setSearchOnLoad] = useState(getInitialIOC());

  function navigate(p: Page, iocValue?: string) {
    setPage(p);
    setSearchOnLoad(iocValue ?? "");
    if (iocValue) {
      try {
        const u = new URL(window.location.href);
        u.searchParams.set("ioc", iocValue);
        window.history.replaceState({}, "", u.toString());
      } catch {}
    }
  }

  useEffect(() => {
    function handler(e: Event) {
      const d = (e as CustomEvent).detail;
      navigate(d.page as Page, d.ioc);
    }
    window.addEventListener("navigate", handler);
    return () => window.removeEventListener("navigate", handler);
  }, []);

  return (
    <div className="min-h-screen bg-bg-primary text-text-primary">
      <nav className="border-b border-border bg-bg-secondary px-6 py-3 flex items-center gap-6" aria-label="Main navigation">
        <a
          href="#"
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
        <ErrorBoundary>
          <div className="page-enter" key={page}>
            {page === "home" && <HomePage key={searchOnLoad} initialValue={searchOnLoad} />}
            {page === "investigations" && <Investigations />}
            {page === "batch" && <Batch />}
            {page === "history" && <History />}
          </div>
        </ErrorBoundary>
      </main>

      <ToastContainer />
    </div>
  );
}
