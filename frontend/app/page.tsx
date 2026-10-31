import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import { Activity, FolderSearch, Radar, ShieldAlert } from "lucide-react";

export const dynamic = "force-dynamic";

async function safeHealth(): Promise<
  { ok: true; version: string } | { ok: false; error: string }
> {
  try {
    const h = await api.health();
    return { ok: true, version: h.version };
  } catch (e) {
    return { ok: false, error: e instanceof Error ? e.message : "unknown" };
  }
}

export default async function OverviewPage() {
  const health = await safeHealth();

  let caseCount = 0;
  let caseError: string | null = null;
  try {
    const cases = await api.listCases();
    caseCount = cases.length;
  } catch (e) {
    caseError = e instanceof Error ? e.message : "unknown";
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">
            Unified Threat Intelligence &amp; Investigation Platform
          </p>
        </div>
        <Badge variant={health.ok ? "low" : "critical"}>
          API {health.ok ? "online" : "offline"}
        </Badge>
      </div>

      {health.ok ? (
        <div className="text-xs text-muted-foreground">
          Backend version: <span className="font-mono">{health.version}</span>
        </div>
      ) : (
        <div className="text-xs text-critical">
          Backend unreachable: {health.error}
        </div>
      )}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Cases"
          value={caseCount}
          icon={FolderSearch}
          hint={caseError ? `error: ${caseError}` : "all cases"}
        />
        <StatCard title="Evidence" value="—" icon={ShieldAlert} hint="coming soon" />
        <StatCard title="IOCs" value="—" icon={Radar} hint="coming soon" />
        <StatCard title="Activity" value="—" icon={Activity} hint="coming soon" />
      </div>

      <Card>
        <CardHeader>
          <CardTitle>Getting started</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-1">
          <p>VECTRAID is running. Use the sidebar to navigate.</p>
          <p>
            Create your first case in{" "}
            <a href="/cases" className="text-primary underline">
              Cases
            </a>{" "}
            or analyze an indicator in{" "}
            <a href="/iocs" className="text-primary underline">
              IOC Explorer
            </a>
            .
          </p>
        </CardContent>
      </Card>
    </div>
  );
}

function StatCard({
  title,
  value,
  icon: Icon,
  hint,
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  hint?: string;
}) {
  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
        <CardTitle className="text-sm font-medium text-muted-foreground">
          {title}
        </CardTitle>
        <Icon className="h-4 w-4 text-muted-foreground" />
      </CardHeader>
      <CardContent>
        <div className="text-2xl font-semibold">{value}</div>
        {hint ? (
          <div className="text-xs text-muted-foreground mt-1">{hint}</div>
        ) : null}
      </CardContent>
    </Card>
  );
}
