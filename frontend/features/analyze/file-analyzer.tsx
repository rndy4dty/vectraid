"use client";

import { useState } from "react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type FileAnalysisResult } from "@/lib/api";
import { readFileAsBase64 } from "@/lib/file-reader";
import { Loader2, Upload } from "lucide-react";

function classVariant(c: string): "critical" | "high" | "medium" | "low" | "muted" {
  switch (c) {
    case "malicious":
      return "critical";
    case "suspicious":
      return "high";
    case "clean":
      return "low";
    default:
      return "muted";
  }
}

export function FileAnalyzer() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<FileAnalysisResult | null>(null);
  const [filename, setFilename] = useState("");

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const b64 = await readFileAsBase64(file);
      const r = await api.analyzeFile(b64, file.name);
      setResult(r);
    } catch (err) {
      setError(err instanceof Error ? err.message : "unknown");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader><CardTitle className="text-sm">Upload file for static analysis</CardTitle></CardHeader>
        <CardContent className="space-y-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="file"
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
        <>
          <Card>
            <CardHeader><CardTitle className="text-sm">Classification</CardTitle></CardHeader>
            <CardContent className="space-y-1">
              <div className="flex items-center gap-2">
                <Badge variant={classVariant(result.classification.classification)}>
                  {result.classification.classification}
                </Badge>
                <span className="text-xs text-muted-foreground">confidence {result.classification.confidence}</span>
              </div>
              {result.classification.reasons.length > 0 ? (
                <ul className="text-xs text-muted-foreground list-disc pl-5 mt-2">
                  {result.classification.reasons.map((r, i) => <li key={i}>{r}</li>)}
                </ul>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Identification</CardTitle></CardHeader>
            <CardContent className="text-sm space-y-1">
              <div><span className="text-muted-foreground">Magic:</span> {result.identification.magic}</div>
              <div><span className="text-muted-foreground">MIME:</span> {result.identification.mime}</div>
              <div><span className="text-muted-foreground">Extension:</span> {result.identification.extension || "—"}</div>
              <div><span className="text-muted-foreground">Size:</span> {result.identification.size} bytes</div>
              {result.identification.extension_mismatch ? (
                <div className="text-critical text-xs">⚠ Extension mismatch</div>
              ) : null}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Hashes</CardTitle></CardHeader>
            <CardContent className="font-mono text-xs space-y-1 break-all">
              <div><span className="text-muted-foreground">MD5:</span> {result.metadata.md5}</div>
              <div><span className="text-muted-foreground">SHA1:</span> {result.metadata.sha1}</div>
              <div><span className="text-muted-foreground">SHA256:</span> {result.metadata.sha256}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">YARA ({result.yara.matches.length})</CardTitle></CardHeader>
            <CardContent>
              {result.yara.error ? (
                <p className="text-xs text-critical">{result.yara.error}</p>
              ) : result.yara.matches.length === 0 ? (
                <p className="text-sm text-muted-foreground">No matches.</p>
              ) : (
                <ul className="space-y-1 text-sm">
                  {result.yara.matches.map((m, i) => (
                    <li key={i} className="flex gap-2 items-center">
                      <Badge variant="high">{String(m.meta.severity ?? "info")}</Badge>
                      <span className="font-mono text-xs">{m.rule_name}</span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </>
      ) : null}
    </div>
  );
}
