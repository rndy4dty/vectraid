"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { api, type HuntLogsResult } from "@/lib/api";
import { readFileAsText } from "@/lib/file-reader";
import { Loader2, Upload } from "lucide-react";

export function HuntAnalyzer() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<HuntLogsResult | null>(null);
  const [filename, setFilename] = useState("");
  const [iocsText, setIocsText] = useState("");

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const text = await readFileAsText(file);
      const iocs = iocsText
        .split(/[,\s\n]+/)
        .map((s) => s.trim())
        .filter(Boolean);
      const r = await api.huntLogs(text, iocs);
      setResult(r);
    } catch (err) {
      const msg = err instanceof Error ? err.message : "unknown";
      // Extract JSON detail if present
      const match = msg.match(/API \d+ [^:]+: (.*)$/);
      setError(
        match && match[1]
          ? `File tidak valid: ${match[1].slice(0, 200)}`
          : msg,
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle className="text-sm">Upload logs (JSON / NDJSON)</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <div>
            <label className="text-xs text-muted-foreground">IOCs to match (comma or newline separated, optional)</label>
            <Input
              value={iocsText}
              onChange={(e) => setIocsText(e.target.value)}
              placeholder="203.0.113.10, evil.test"
            />
          </div>
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="file"
              accept=".json,.txt,.log"
              onChange={onFile}
              disabled={loading}
              className="block w-full text-sm file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:bg-primary file:text-primary-foreground hover:file:bg-primary/90"
            />
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4 text-muted-foreground" />}
          </label>
          {filename ? <p className="text-xs text-muted-foreground">Selected: {filename}</p> : null}
          {error ? <p className="text-xs text-critical">{error}</p> : null}
        </CardContent>
      </Card>

      {result ? (
        <Card>
          <CardHeader><CardTitle className="text-sm">Hunt Summary</CardTitle></CardHeader>
          <CardContent className="space-y-2 text-sm">
            <div className="flex flex-wrap gap-2">
              <Badge variant="info">{result.report.summary.event_count} events</Badge>
              <Badge variant="high">{result.report.summary.rule_finding_count} findings</Badge>
              <Badge variant="critical">{result.report.summary.ioc_match_count} IOC matches</Badge>
              <Badge variant="muted">{result.report.summary.unique_hosts} hosts</Badge>
              <Badge variant="muted">{result.report.summary.unique_users} users</Badge>
            </div>
            {Object.keys(result.report.summary.severity_breakdown).length > 0 ? (
              <div className="text-xs text-muted-foreground">
                Severity: {Object.entries(result.report.summary.severity_breakdown).map(([k, v]) => `${k}=${v}`).join(", ")}
              </div>
            ) : null}
            {result.report.errors.length > 0 ? (
              <div className="text-xs text-critical">
                Errors: {result.report.errors.join("; ")}
              </div>
            ) : null}
            {result.report.summary.time_range[0] ? (
              <div className="text-xs text-muted-foreground">
                Time range: {result.report.summary.time_range[0]} → {result.report.summary.time_range[1]}
              </div>
            ) : null}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
