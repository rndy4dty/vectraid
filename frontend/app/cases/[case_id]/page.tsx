import Link from "next/link";
import { notFound } from "next/navigation";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type CaseResponse } from "@/lib/api";
import {
  statusVariant,
  priorityVariant,
  formatRelativeTime,
} from "@/lib/utils";
import { ArrowLeft } from "lucide-react";
import { CaseActions } from "@/features/cases/case-actions";
import { ReportViewer } from "@/features/cases/report-viewer";

export const dynamic = "force-dynamic";

const DEFAULT_ANALYST = "analyst@example.com";

export default async function CaseDetailPage({
  params,
}: {
  params: Promise<{ case_id: string }>;
}) {
  const { case_id } = await params;

  let c: CaseResponse;
  try {
    c = await api.getCase(case_id);
  } catch (e) {
    if (e instanceof Error && e.message.startsWith("API 404")) {
      notFound();
    }
    return (
      <div className="p-6">
        <div className="text-critical text-sm">
          Failed to load case: {e instanceof Error ? e.message : "unknown"}
        </div>
      </div>
    );
  }

  return (
    <div className="p-6 space-y-6">
      <Link
        href="/cases"
        className="inline-flex items-center gap-1 text-sm text-muted-foreground hover:text-foreground"
      >
        <ArrowLeft className="h-3 w-3" /> Back to cases
      </Link>

      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="text-xs font-mono text-muted-foreground">
            {c.case_id}
          </div>
          <h1 className="text-2xl font-semibold tracking-tight">{c.title}</h1>
          <div className="mt-2 flex flex-wrap items-center gap-2 text-xs text-muted-foreground">
            <Badge variant={statusVariant(c.status)}>{c.status}</Badge>
            <Badge variant={priorityVariant(c.priority)}>{c.priority}</Badge>
            <span>· created by {c.created_by}</span>
            {c.assignee ? <span>· assigned to {c.assignee}</span> : null}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        <div className="lg:col-span-2 space-y-4">
          <ReportViewer caseId={c.case_id} />

          <Card>
            <CardHeader>
              <CardTitle>Evidence ({c.evidence_ids.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {c.evidence_ids.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No evidence linked yet.
                </p>
              ) : (
                <ul className="text-sm space-y-1 font-mono">
                  {c.evidence_ids.map((id) => (
                    <li key={id}>{id}</li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Decisions ({c.decisions.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {c.decisions.length === 0 ? (
                <p className="text-sm text-muted-foreground">
                  No decisions recorded.
                </p>
              ) : (
                <ul className="space-y-2 text-sm">
                  {c.decisions.map((d, i) => (
                    <li key={i}>
                      <div className="font-medium">
                        <Badge variant="info">{d.outcome}</Badge> by {d.analyst}
                      </div>
                      <div className="text-muted-foreground">{d.rationale}</div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Notes ({c.notes.length})</CardTitle>
            </CardHeader>
            <CardContent>
              {c.notes.length === 0 ? (
                <p className="text-sm text-muted-foreground">No notes yet.</p>
              ) : (
                <ul className="space-y-2 text-sm">
                  {c.notes.map((n, i) => (
                    <li key={i}>
                      <div className="text-xs text-muted-foreground">
                        {n.author} · {formatRelativeTime(n.timestamp)}
                      </div>
                      <div>{n.text}</div>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Audit trail</CardTitle>
            </CardHeader>
            <CardContent>
              <ul className="space-y-2 text-sm">
                {c.history.map((e, i) => (
                  <li key={i} className="flex items-start gap-3">
                    <span className="font-mono text-xs text-muted-foreground shrink-0 w-20">
                      {formatRelativeTime(e.timestamp)}
                    </span>
                    <span className="font-medium">{e.action}</span>
                    <span className="text-muted-foreground">by {e.actor}</span>
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        </div>

        <aside className="space-y-4">
          <CaseActions case_={c} by={DEFAULT_ANALYST} />
        </aside>
      </div>
    </div>
  );
}
