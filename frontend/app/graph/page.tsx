import { GraphView } from "@/features/graph/graph-view";

export const dynamic = "force-dynamic";

export default function GraphPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">ThreatGraph</h1>
        <p className="text-sm text-muted-foreground">
          Explore IOC relationships through shared evidence
        </p>
      </div>
      <GraphView />
    </div>
  );
}
