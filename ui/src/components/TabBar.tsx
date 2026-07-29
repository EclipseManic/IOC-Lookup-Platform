const TABS = ["Overview", "Sources", "Enrichment", "Relationships", "Export"] as const;
export type TabName = (typeof TABS)[number];

export default function TabBar({ active, onChange }: { active: TabName; onChange: (tab: TabName) => void }) {
  return (
    <div className="flex gap-1 border-b border-border" role="tablist" aria-label="Result sections">
      {TABS.map((tab) => (
        <button
          key={tab}
          onClick={() => onChange(tab)}
          role="tab"
          aria-selected={active === tab}
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
