import { useRef } from "react";

const TABS = ["Overview", "Evidence", "Sources", "Enrichment", "Relationships", "Export"] as const;
export type TabName = (typeof TABS)[number];

export default function TabBar({ active, onChange }: { active: TabName; onChange: (tab: TabName) => void }) {
  const listRef = useRef<HTMLDivElement>(null);

  function handleKeyDown(e: React.KeyboardEvent) {
    const idx = TABS.indexOf(active);
    let nextIdx: number | null = null;
    if (e.key === "ArrowRight") nextIdx = (idx + 1) % TABS.length;
    else if (e.key === "ArrowLeft") nextIdx = (idx - 1 + TABS.length) % TABS.length;
    if (nextIdx === null) return;
    e.preventDefault();
    onChange(TABS[nextIdx]);
    const buttons = listRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]');
    buttons?.[nextIdx]?.focus();
  }

  return (
    <div
      ref={listRef}
      className="flex gap-1 border-b border-border"
      role="tablist"
      aria-label="Result sections"
      onKeyDown={handleKeyDown}
    >
      {TABS.map((tab) => (
        <button
          key={tab}
          onClick={() => onChange(tab)}
          role="tab"
          aria-selected={active === tab}
          tabIndex={active === tab ? 0 : -1}
          className={`px-4 py-2 text-sm font-medium transition-colors relative ${
            active === tab
              ? "text-accent"
              : "text-text-secondary hover:text-text-primary"
          }`}
        >
          {tab}
          {active === tab && (
            <span className="absolute bottom-0 left-0 right-0 h-0.5 bg-accent rounded-full" />
          )}
        </button>
      ))}
    </div>
  );
}
