"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import { riskColor } from "@/lib/utils";

interface ReportShape {
  investigation: {
    risk: {
      score: number;
      classification: string;
      reasons: string[];
    } | null;
    mitre_mappings: Array<{
      technique_id: string;
      technique_name: string;
      tactic: string;
      confidence: number;
    }>;
    timeline: {
      event_count: number;
      events: Array<{
        timestamp: string;
        description: string;
        severity: string;
      }>;
    } | null;
    summary: {
      evidence_count: number;
      correlation_count: number;
      mitre_technique_count: number;
      risk_score: number;
      risk_classification: string;
    };
  };
}

export function ReportViewer({ caseId }: { caseId: string }) {
  const [report, setReport] = useState<ReportShape | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const r = await api.getReport(caseId);
      setReport(r as ReportShape);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    } finally {
      setLoading(false);
    }
  }

  return (
    <Card>
      <CardHeader className="flex flex-row items-center justify-between">
        <CardTitle className="text-sm">Investigation report</CardTitle>
        <Button size="sm" onClick={load} disabled={loading}>
          {loading ? "Generating…" : "Generate"}
        </Button>
      </CardHeader>
      <CardContent className="space-y-4 text-sm">
        {error ? <div className="text-critical text-xs">{error}</div> : null}
        {!report && !loading ? (
          <p className="text-muted-foreground">
            Click Generate to run the investigation pipeline on this case.
          </p>
        ) : null}
        {report ? (
          <>
            <div className="flex items-center gap-3">
              <span className="text-muted-foreground">Risk:</span>
              <span
                className={`font-semibold ${riskColor(
                  report.investigation.summary.risk_classification,
                )}`}
              >
                {report.investigation.summary.risk_classification} (
                {report.investigation.summary.risk_score.toFixed(1)})
              </span>
            </div>
            <div className="text-xs text-muted-foreground">
              Evidence: {report.investigation.summary.evidence_count} ·
              Correlations: {report.investigation.summary.correlation_count} ·
              Techniques: {report.investigation.summary.mitre_technique_count}
            </div>

            {report.investigation.mitre_mappings.length > 0 ? (
              <div>
                <div className="text-xs uppercase text-muted-foreground mb-1">
                  MITRE ATT&CK
                </div>
                <div className="flex flex-wrap gap-1">
                  {report.investigation.mitre_mappings.map((m) => (
                    <Badge key={m.technique_id} variant="info">
                      {m.technique_id} · {m.tactic}
                    </Badge>
                  ))}
                </div>
              </div>
            ) : null}

            {report.investigation.timeline &&
            report.investigation.timeline.events.length > 0 ? (
              <div>
                <div className="text-xs uppercase text-muted-foreground mb-1">
                  Timeline ({report.investigation.timeline.event_count})
                </div>
                <ul className="space-y-1">
                  {report.investigation.timeline.events.slice(0, 10).map((e, i) => (
                    <li key={i} className="text-xs flex gap-2">
                      <span className="font-mono text-muted-foreground shrink-0">
                        {e.timestamp.slice(11, 19)}
                      </span>
                      <span>{e.description}</span>
                    </li>
                  ))}
                </ul>
              </div>
            ) : null}
          </>
        ) : null}
      </CardContent>
    </Card>
  );
}
