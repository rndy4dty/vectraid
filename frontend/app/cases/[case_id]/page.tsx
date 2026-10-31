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

export const dynamic = "force-dynamic";

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

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        <Card>
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            {c.evidence_ids.length === 0
              ? "No evidence linked yet."
              : `${c.evidence_ids.length} evidence linked.`}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Decisions</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            {c.decisions.length === 0
              ? "No decisions recorded."
              : `${c.decisions.length} decision(s) recorded.`}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Notes</CardTitle>
          </CardHeader>
          <CardContent className="text-sm text-muted-foreground">
            {c.notes.length === 0
              ? "No notes yet."
              : `${c.notes.length} note(s).`}
          </CardContent>
        </Card>
      </div>

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
  );
}
