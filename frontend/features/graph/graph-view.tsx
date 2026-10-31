"use client";

import { useCallback, useMemo, useState } from "react";
import ReactFlow, {
  Background,
  Controls,
  MarkerType,
  MiniMap,
  type Edge,
  type Node,
  type NodeMouseHandler,
} from "reactflow";
import "reactflow/dist/style.css";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type GraphData } from "@/lib/api";
import { Loader2, Network, RotateCcw } from "lucide-react";

interface Props {
  initialIocId?: string;
}

export function GraphView({ initialIocId }: Props) {
  const router = useRouter();
  const [iocId, setIocId] = useState(initialIocId ?? "ioc:domain:evil.test");
  const [data, setData] = useState<GraphData | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const fetchPivot = useCallback(async (id: string) => {
    const trimmed = id.trim();
    if (!trimmed) {
      setError("Masukkan IOC ID terlebih dahulu.");
      return;
    }
    setLoading(true);
    setError(null);
    try {
      const g = await api.pivotGraph(id, 2);
      setData(g);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
      setData(null);
    } finally {
      setLoading(false);
    }
  }, []);

  const { nodes, edges } = useMemo(() => {
    if (!data) return { nodes: [], edges: [] };

    const rfNodes: Node[] = data.nodes.map((n, i) => {
      const isIoc = n.type === "ioc";
      const isCenter = n.id === iocId;
      const angle = (i / Math.max(1, data.nodes.length)) * 2 * Math.PI;
      const radius = isCenter ? 0 : 250;
      return {
        id: n.id,
        data: { label: n.label, nodeType: n.type, properties: n.properties },
        position: {
          x: 400 + Math.cos(angle) * radius,
          y: 300 + Math.sin(angle) * radius,
        },
        style: {
          background: isIoc ? "hsl(217 91% 15%)" : "hsl(25 95% 15%)",
          color: "hsl(210 40% 98%)",
          border: isCenter
            ? "2px solid hsl(217 91% 60%)"
            : "1px solid hsl(217 33% 30%)",
          borderRadius: 8,
          padding: 8,
          fontSize: 12,
          fontWeight: isIoc ? 600 : 400,
          minWidth: 140,
          textAlign: "center" as const,
        },
        type: "default",
      };
    });

    const rfEdges: Edge[] = data.edges.map((e, i) => ({
      id: `e-${i}-${e.source}-${e.target}`,
      source: e.source,
      target: e.target,
      label: e.type,
      animated: false,
      style: { stroke: "hsl(217 33% 40%)", strokeWidth: 1.5 },
      labelStyle: { fill: "hsl(215 20% 65%)", fontSize: 10 },
      markerEnd: { type: MarkerType.ArrowClosed },
    }));

    return { nodes: rfNodes, edges: rfEdges };
  }, [data, iocId]);

  const onNodeClick: NodeMouseHandler = useCallback(
    (_evt, node) => {
      const nodeType = (node.data as { nodeType: string }).nodeType;
      if (nodeType === "ioc") {
        setIocId(node.id);
        fetchPivot(node.id);
      } else if (nodeType === "evidence") {
        const props = (node.data as { properties: Record<string, unknown> }).properties;
        const caseId = props?.case_id;
        if (typeof caseId === "string" && caseId) {
          router.push(`/cases/${caseId}`);
        }
      }
    },
    [fetchPivot, router],
  );

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Pivot from IOC</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Input
              value={iocId}
              onChange={(e) => setIocId(e.target.value)}
              placeholder="ioc:domain:example.com"
              onKeyDown={(e) => {
                if (e.key === "Enter") fetchPivot(iocId);
              }}
            />
            <Button onClick={() => fetchPivot(iocId)} disabled={loading}>
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Network className="h-4 w-4" />
              )}
              Load
            </Button>
            <Button
              variant="outline"
              onClick={() => {
                setData(null);
                setError(null);
              }}
              disabled={!data || loading}
            >
              <RotateCcw className="h-4 w-4" />
            </Button>
          </div>
          <p className="text-xs text-muted-foreground">
            Tip: klik node IOC untuk pivot ulang, klik node evidence untuk
            buka case-nya.
          </p>
          {error ? (
            <div className="text-xs text-critical">{error}</div>
          ) : null}
        </CardContent>
      </Card>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm">Graph</CardTitle>
          {data ? (
            <div className="flex gap-2 text-xs">
              <Badge variant="info">{data.nodes.length} nodes</Badge>
              <Badge variant="muted">{data.edges.length} edges</Badge>
            </div>
          ) : null}
        </CardHeader>
        <CardContent className="p-0">
          <div style={{ height: 600, width: "100%" }}>
            {data ? (
              <ReactFlow
                nodes={nodes}
                edges={edges}
                onNodeClick={onNodeClick}
                fitView
                proOptions={{ hideAttribution: true }}
              >
                <Background color="#1a2332" gap={20} />
                <Controls />
                <MiniMap
                  nodeColor={(n) =>
                    (n.data as { nodeType: string }).nodeType === "ioc"
                      ? "hsl(217 91% 40%)"
                      : "hsl(25 95% 40%)"
                  }
                  style={{ background: "hsl(222 47% 9%)" }}
                />
              </ReactFlow>
            ) : (
              <div className="h-full grid place-items-center text-sm text-muted-foreground">
                No graph loaded. Enter an IOC node ID and click Load.
              </div>
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}
