import { useCallback, useEffect, useRef, useState } from "react";
import * as d3 from "d3";

const NODE_COLORS: Record<string, string> = {
  ipv4: "#3b82f6",
  ipv6: "#60a5fa",
  domain: "#8b5cf6",
  url: "#a855f7",
  md5: "#f97316",
  sha1: "#f59e0b",
  sha256: "#eab308",
  email: "#ec4899",
  cve: "#ef4444",
  default: "#6b7280",
};

function inferType(label: string): string {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(label)) return "ipv4";
  if (/^[0-9a-f]{32}$/i.test(label)) return "md5";
  if (/^[0-9a-f]{40}$/i.test(label)) return "sha1";
  if (/^[0-9a-f]{64}$/i.test(label)) return "sha256";
  if (/^CVE-\d{4}-\d{4,}$/i.test(label)) return "cve";
  if (/^[\w.+-]+@[\w.-]+\.\w{2,}$/.test(label)) return "email";
  if (/^https?:\/\//i.test(label)) return "url";
  if (/^[\w.-]+\.[a-z]{2,}$/i.test(label)) return "domain";
  return "default";
}

interface NodeData extends d3.SimulationNodeDatum {
  id: string;
  label: string;
  type: string;
  score: number;
  isMain: boolean;
}

interface LinkData {
  source: string;
  target: string;
  relationship: string;
  via_source: string;
}

interface Props {
  mainIoc: string;
  relationships: Array<{
    source_ioc: string;
    relationship: string;
    target_ioc: string;
    via_source: string;
  }>;
  onNodeClick?: (value: string) => void;
}

export default function RelationshipGraph({ mainIoc, relationships, onNodeClick }: Props) {
  const svgRef = useRef<SVGSVGElement>(null);
  const [tooltip, setTooltip] = useState<{ x: number; y: number; content: React.ReactNode } | null>(null);
  const [viewMode, setViewMode] = useState<"graph" | "table">("graph");
  const activeTypesRef = useRef<Set<string>>(new Set());

  const buildGraph = useCallback(() => {
    if (!svgRef.current || relationships.length === 0) return;

    const nodesMap = new Map<string, NodeData>();
    activeTypesRef.current = new Set();

    const addNode = (label: string, isMain: boolean) => {
      if (nodesMap.has(label)) return;
      const type = inferType(label);
      activeTypesRef.current.add(type);
      nodesMap.set(label, {
        id: label, label, type,
        score: isMain ? 100 : 50,
        isMain,
      });
    };

    addNode(mainIoc, true);

    const links: LinkData[] = [];
    for (const rel of relationships) {
      addNode(rel.source_ioc, false);
      addNode(rel.target_ioc, false);
      links.push({ source: rel.source_ioc, target: rel.target_ioc, relationship: rel.relationship, via_source: rel.via_source });
    }

    const nodes = Array.from(nodesMap.values());
    const width = svgRef.current.clientWidth || 700;
    const height = 500;

    const svg = d3.select(svgRef.current);
    svg.selectAll("*").remove();
    svg.attr("viewBox", `0 0 ${width} ${height}`);

    const g = svg.append("g");

    svg.call(d3.zoom<SVGSVGElement, unknown>()
      .scaleExtent([0.2, 4])
      .on("zoom", (event) => { g.attr("transform", event.transform); })
    );

    const simulation = d3.forceSimulation(nodes)
      .force("link", d3.forceLink(links).id((d: any) => d.id).distance(120))
      .force("charge", d3.forceManyBody().strength(-300))
      .force("center", d3.forceCenter(width / 2, height / 2))
      .force("collision", d3.forceCollide(30));

    const link = g.append("g")
      .selectAll("line")
      .data(links)
      .join("line")
      .attr("stroke", "#1e293b")
      .attr("stroke-width", 1.5)
      .attr("stroke-opacity", 0.6);

    const linkLabel = g.append("g")
      .selectAll("text")
      .data(links)
      .join("text")
      .attr("text-anchor", "middle")
      .attr("dy", -4)
      .attr("fill", "#94a3b8")
      .attr("font-size", 8)
      .attr("font-family", "monospace")
      .text((d: any) => d.relationship);

    const nodeGroup = g.append("g")
      .selectAll("g")
      .data(nodes)
      .join("g")
      .attr("cursor", "grab")
      .call(d3.drag<any, NodeData>()
        .on("start", (event, d) => {
          if (!event.active) simulation.alphaTarget(0.3).restart();
        })
        .on("drag", (event, d) => { d.x = event.x; d.y = event.y; })
        .on("end", (event) => {
          if (!event.active) simulation.alphaTarget(0);
        }) as any
      );

    nodeGroup.append("circle")
      .attr("r", (d) => d.isMain ? 12 : 6 + (d.score / 100) * 8)
      .attr("fill", (d) => NODE_COLORS[d.type] || NODE_COLORS.default)
      .attr("stroke", (d) => d.isMain ? "#818cf8" : "none")
      .attr("stroke-width", 2);

    nodeGroup.append("text")
      .attr("dy", (d) => d.isMain ? 22 : 16)
      .attr("text-anchor", "middle")
      .attr("fill", "#f1f5f9")
      .attr("font-size", (d) => d.isMain ? 10 : 8)
      .attr("font-family", "monospace")
      .text((d) => d.label.length > 20 ? d.label.slice(0, 18) + "…" : d.label);

    nodeGroup.on("mouseenter", (event, d) => {
      const rect = svgRef.current!.getBoundingClientRect();
      setTooltip({
        x: event.clientX - rect.left,
        y: event.clientY - rect.top - 10,
        content: (
          <>
            <p className="font-semibold text-text-primary mb-0.5">{d.label}</p>
            <p className="text-text-secondary">Type: {d.type}</p>
            {d.isMain && <p className="text-accent text-[10px]">Main IOC</p>}
          </>
        ),
      });
    })
    .on("mouseleave", () => setTooltip(null))
    .on("click", (_event, d) => {
      if (!d.isMain && onNodeClick) onNodeClick(d.label);
    });

    link.on("mouseenter", (event, d: any) => {
      const rect = svgRef.current!.getBoundingClientRect();
      setTooltip({
        x: event.clientX - rect.left,
        y: event.clientY - rect.top - 10,
        content: (
          <>
            <p className="text-text-primary mb-0.5">{d.relationship}</p>
            <p className="text-text-secondary">via {d.via_source}</p>
          </>
        ),
      });
    })
    .on("mouseleave", () => setTooltip(null));

    simulation.on("tick", () => {
      link
        .attr("x1", (d: any) => d.source.x)
        .attr("y1", (d: any) => d.source.y)
        .attr("x2", (d: any) => d.target.x)
        .attr("y2", (d: any) => d.target.y);
      linkLabel
        .attr("x", (d: any) => (d.source.x + d.target.x) / 2)
        .attr("y", (d: any) => (d.source.y + d.target.y) / 2);
      nodeGroup.attr("transform", (d: any) => `translate(${d.x},${d.y})`);
    });

    return () => { simulation.stop(); };
  }, [mainIoc, relationships, onNodeClick]);

  useEffect(() => { buildGraph(); }, [buildGraph]);

  if (relationships.length === 0) return null;

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-semibold text-text-secondary uppercase tracking-wider">Relationships</h3>
        <div className="flex gap-1 bg-bg-elevated rounded-lg p-0.5">
          <button onClick={() => setViewMode("graph")}
            className={`px-3 py-1 text-xs rounded-md transition-colors ${viewMode === "graph" ? "bg-accent text-white" : "text-text-secondary hover:text-text-primary"}`}
          >Graph</button>
          <button onClick={() => setViewMode("table")}
            className={`px-3 py-1 text-xs rounded-md transition-colors ${viewMode === "table" ? "bg-accent text-white" : "text-text-secondary hover:text-text-primary"}`}
          >Table</button>
        </div>
      </div>

      {viewMode === "graph" ? (
        <div className="relative bg-bg-card border border-border rounded-lg overflow-hidden">
          <svg ref={svgRef} className="w-full" style={{ height: 500 }} />
          {tooltip && (
            <div
              className="absolute z-10 bg-bg-elevated border border-border rounded-lg px-3 py-2 text-xs shadow-xl pointer-events-none"
              style={{ left: tooltip.x, top: tooltip.y, transform: "translate(-50%, -100%)" }}
            >{tooltip.content}</div>
          )}
          <div className="absolute bottom-3 left-3 flex flex-wrap gap-2">
            {Array.from(activeTypesRef.current).filter(t => t !== "default").map((type) => (
              <div key={type} className="flex items-center gap-1 text-[10px]">
                <span className="w-2 h-2 rounded-full" style={{ backgroundColor: NODE_COLORS[type] || NODE_COLORS.default }} />
                <span className="text-text-secondary">{type}</span>
              </div>
            ))}
          </div>
        </div>
      ) : (
        <div className="bg-bg-card border border-border rounded-lg overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-text-secondary">
                <th className="text-left py-2 px-3 font-medium">Source</th>
                <th className="text-left py-2 px-3 font-medium">Relationship</th>
                <th className="text-left py-2 px-3 font-medium">Target</th>
                <th className="text-left py-2 px-3 font-medium">Via</th>
              </tr>
            </thead>
            <tbody>
              {relationships.map((rel, i) => (
                <tr key={i} className="border-b border-border/50 hover:bg-bg-elevated/50 transition-colors">
                  <td className="py-2 px-3 font-mono text-xs">{rel.source_ioc}</td>
                  <td className="py-2 px-3">
                    <span className="text-[10px] px-1.5 py-0.5 bg-accent/10 text-accent rounded">{rel.relationship}</span>
                  </td>
                  <td className="py-2 px-3 font-mono text-xs">{rel.target_ioc}</td>
                  <td className="py-2 px-3 text-xs text-text-secondary">{rel.via_source}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  );
}
