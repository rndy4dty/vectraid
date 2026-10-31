import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type CaseResponse, type CaseStatus } from "@/lib/api";
import {
  priorityVariant,
  statusVariant,
  formatRelativeTime,
} from "@/lib/utils";
import { NewCaseButton } from "@/features/cases/new-case-button";

export const dynamic = "force-dynamic";

export default async function CasesPage({
  searchParams,
}: {
  searchParams: Promise<{ status?: string }>;
}) {
  const params = await searchParams;
  const statusFilter = params?.status as CaseStatus | undefined;

  let cases: CaseResponse[] = [];
  let error: string | null = null;
  try {
    cases = await api.listCases(
      statusFilter ? { status: statusFilter } : undefined,
    );
  } catch (e) {
    error = e instanceof Error ? e.message : "unknown";
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Cases</h1>
          <p className="text-sm text-muted-foreground">
            Investigations opened by analysts
          </p>
        </div>
        <NewCaseButton />
      </div>

      <FilterBar current={statusFilter} />

      {error ? (
        <Card>
          <CardContent className="p-4 text-critical text-sm">
            Failed to load cases: {error}
          </CardContent>
        </Card>
      ) : cases.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-muted-foreground">
            No cases yet. Click <strong>+ New Case</strong> to create one.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="p-3 font-medium">Case ID</th>
                  <th className="p-3 font-medium">Title</th>
                  <th className="p-3 font-medium">Status</th>
                  <th className="p-3 font-medium">Priority</th>
                  <th className="p-3 font-medium">Assignee</th>
                  <th className="p-3 font-medium">Updated</th>
                </tr>
              </thead>
              <tbody>
                {cases.map((c) => (
                  <tr
                    key={c.case_id}
                    className="border-b border-border last:border-0 hover:bg-secondary/50"
                  >
                    <td className="p-3 font-mono text-xs">
                      <Link
                        href={`/cases/${c.case_id}`}
                        className="text-primary hover:underline"
                      >
                        {c.case_id}
                      </Link>
                    </td>
                    <td className="p-3">{c.title}</td>
                    <td className="p-3">
                      <Badge variant={statusVariant(c.status)}>
                        {c.status}
                      </Badge>
                    </td>
                    <td className="p-3">
                      <Badge variant={priorityVariant(c.priority)}>
                        {c.priority}
                      </Badge>
                    </td>
                    <td className="p-3 text-muted-foreground">
                      {c.assignee ?? "—"}
                    </td>
                    <td className="p-3 text-muted-foreground">
                      {c.history.length > 0
                        ? formatRelativeTime(
                            c.history[c.history.length - 1].timestamp,
                          )
                        : "—"}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </Card>
      )}
    </div>
  );
}

function FilterBar({ current }: { current?: CaseStatus }) {
  const options: Array<{ value?: CaseStatus; label: string }> = [
    { label: "All" },
    { value: "new", label: "New" },
    { value: "investigating", label: "Investigating" },
    { value: "resolved", label: "Resolved" },
    { value: "closed", label: "Closed" },
  ];

  return (
    <div className="flex flex-wrap gap-2">
      {options.map((opt) => {
        const isActive = current === opt.value;
        const href = opt.value ? `/cases?status=${opt.value}` : "/cases";
        return (
          <Link
            key={opt.label}
            href={href}
            className={
              isActive
                ? "px-3 py-1.5 rounded-md text-xs font-medium bg-primary/15 text-primary border border-primary/30"
                : "px-3 py-1.5 rounded-md text-xs font-medium border border-border text-muted-foreground hover:bg-secondary"
            }
          >
            {opt.label}
          </Link>
        );
      })}
    </div>
  );
}
