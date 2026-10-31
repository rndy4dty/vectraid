import Link from "next/link";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type CaseResponse, type EvidenceResponse } from "@/lib/api";
import {
  statusVariant,
  priorityVariant,
  formatRelativeTime,
} from "@/lib/utils";
import {
  Activity,
  FolderSearch,
  Radar,
  ShieldAlert,
  ArrowRight,
} from "lucide-react";

export const dynamic = "force-dynamic";

async function safe<T>(fn: () => Promise<T>, fallback: T): Promise<T> {
  try {
    return await fn();
  } catch {
    return fallback;
  }
}

export default async function OverviewPage() {
  const health = await safe(() => api.health(), null);
  const cases = await safe(() => api.listCases(), [] as CaseResponse[]);
  const evidence = await safe(
    () => api.listEvidence(),
    [] as EvidenceResponse[],
  );

  const openCases = cases.filter(
    (c) => c.status === "new" || c.status === "investigating",
  );
  const criticalCases = cases.filter((c) => c.priority === "critical");
  const recentCases = [...cases]
    .sort((a, b) => {
      const ta = a.history[a.history.length - 1]?.timestamp ?? "";
      const tb = b.history[b.history.length - 1]?.timestamp ?? "";
      return tb.localeCompare(ta);
    })
    .slice(0, 5);

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Overview</h1>
          <p className="text-sm text-muted-foreground">
            Unified Threat Intelligence &amp; Investigation Platform
          </p>
        </div>
        <Badge variant={health ? "low" : "critical"}>
          API {health ? "online" : "offline"}
        </Badge>
      </div>

      {health ? (
        <div className="text-xs text-muted-foreground">
          Backend version: <span className="font-mono">{health.version}</span>
        </div>
      ) : null}

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Cases"
          value={cases.length}
          icon={FolderSearch}
          hint={`${openCases.length} open`}
        />
        <StatCard
          title="Evidence"
          value={evidence.length}
          icon={ShieldAlert}
          hint="all sources"
        />
        <StatCard
          title="Critical"
          value={criticalCases.length}
          icon={Activity}
          hint="priority critical"
        />
        <StatCard
          title="IOC Explorer"
          value="→"
          icon={Radar}
          hint="query indicators"
          href="/iocs"
        />
      </div>

      <Card>
        <CardHeader className="flex flex-row items-center justify-between">
          <CardTitle className="text-sm">Recent cases</CardTitle>
          <Link
            href="/cases"
            className="text-xs text-primary hover:underline inline-flex items-center gap-1"
          >
            View all <ArrowRight className="h-3 w-3" />
          </Link>
        </CardHeader>
        <CardContent>
          {recentCases.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No cases yet.{" "}
              <Link href="/cases" className="text-primary hover:underline">
                Create one
              </Link>
              .
            </p>
          ) : (
            <ul className="divide-y divide-border">
              {recentCases.map((c) => (
                <li key={c.case_id} className="py-2 flex items-center gap-3">
                  <Link
                    href={`/cases/${c.case_id}`}
                    className="font-mono text-xs text-primary hover:underline"
                  >
                    {c.case_id}
                  </Link>
                  <span className="text-sm truncate flex-1">{c.title}</span>
                  <Badge variant={statusVariant(c.status)}>{c.status}</Badge>
                  <Badge variant={priorityVariant(c.priority)}>
                    {c.priority}
                  </Badge>
                  <span className="text-xs text-muted-foreground w-16 text-right">
                    {c.history.length > 0
                      ? formatRelativeTime(
                          c.history[c.history.length - 1].timestamp,
                        )
                      : "—"}
                  </span>
                </li>
              ))}
            </ul>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Getting started</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-1">
          <p>
            New to VECTRAID? Start with{" "}
            <Link href="/iocs" className="text-primary hover:underline">
              IOC Explorer
            </Link>{" "}
            to query an indicator, or{" "}
            <Link href="/cases" className="text-primary hover:underline">
              create a case
            </Link>{" "}
            to track an investigation.
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
  href,
}: {
  title: string;
  value: string | number;
  icon: React.ComponentType<{ className?: string }>;
  hint?: string;
  href?: string;
}) {
  const inner = (
    <Card className={href ? "hover:bg-secondary/50 transition-colors" : ""}>
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
  return href ? <Link href={href}>{inner}</Link> : inner;
}
