import Link from "next/link";
import { Card, CardContent } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type EvidenceResponse } from "@/lib/api";
import { formatRelativeTime } from "@/lib/utils";
import { NewEvidenceButton } from "@/features/evidence/new-evidence-button";

export const dynamic = "force-dynamic";

function moduleBadge(module: string): "critical" | "high" | "medium" | "low" | "info" | "muted" | "default" {
  switch (module) {
    case "phishtrace":
      return "info";
    case "maltrace":
      return "critical";
    case "huntscope":
      return "high";
    case "intelfusion":
      return "medium";
    default:
      return "default";
  }
}

export default async function EvidencePage({
  searchParams,
}: {
  searchParams: Promise<{ case_id?: string }>;
}) {
  const params = await searchParams;
  const caseFilter = params?.case_id;

  let evidence: EvidenceResponse[] = [];
  let error: string | null = null;
  try {
    evidence = await api.listEvidence(caseFilter);
  } catch (e) {
    error = e instanceof Error ? e.message : "unknown";
  }

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold tracking-tight">Evidence</h1>
          <p className="text-sm text-muted-foreground">
            All evidence stored across cases
          </p>
        </div>
        <NewEvidenceButton />
      </div>

      {caseFilter ? (
        <div className="text-xs text-muted-foreground">
          Filtered by case: <span className="font-mono">{caseFilter}</span>{" "}
          <Link href="/evidence" className="text-primary hover:underline">
            clear
          </Link>
        </div>
      ) : null}

      {error ? (
        <Card>
          <CardContent className="p-4 text-critical text-sm">
            Failed to load evidence: {error}
          </CardContent>
        </Card>
      ) : evidence.length === 0 ? (
        <Card>
          <CardContent className="p-8 text-center text-sm text-muted-foreground">
            No evidence yet. Evidence is created by analysis modules or
            manually via <strong>+ New Evidence</strong>.
          </CardContent>
        </Card>
      ) : (
        <Card>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-xs uppercase text-muted-foreground">
                <tr>
                  <th className="p-3 font-medium">Evidence ID</th>
                  <th className="p-3 font-medium">Module</th>
                  <th className="p-3 font-medium">Type</th>
                  <th className="p-3 font-medium">Finding</th>
                  <th className="p-3 font-medium">Case</th>
                  <th className="p-3 font-medium">Confidence</th>
                  <th className="p-3 font-medium">Time</th>
                </tr>
              </thead>
              <tbody>
                {evidence.map((e) => (
                  <tr
                    key={e.evidence_id}
                    className="border-b border-border last:border-0 hover:bg-secondary/50"
                  >
                    <td className="p-3 font-mono text-xs">{e.evidence_id}</td>
                    <td className="p-3">
                      <Badge variant={moduleBadge(e.source_module)}>
                        {e.source_module}
                      </Badge>
                    </td>
                    <td className="p-3 text-xs text-muted-foreground">
                      {e.evidence_type}
                    </td>
                    <td className="p-3 max-w-md truncate">{e.finding}</td>
                    <td className="p-3 font-mono text-xs">
                      <Link
                        href={`/cases/${e.case_id}`}
                        className="text-primary hover:underline"
                      >
                        {e.case_id}
                      </Link>
                    </td>
                    <td className="p-3 text-xs">{e.confidence}</td>
                    <td className="p-3 text-xs text-muted-foreground">
                      {formatRelativeTime(e.timestamp)}
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
