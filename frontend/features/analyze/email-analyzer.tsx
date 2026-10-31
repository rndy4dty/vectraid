"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api, type EmailAnalysisResult } from "@/lib/api";
import { readFileAsText } from "@/lib/file-reader";
import { Loader2, Upload } from "lucide-react";

function authVariant(r: string): "low" | "critical" | "muted" {
  if (r === "pass") return "low";
  if (r === "fail" || r === "softfail") return "critical";
  return "muted";
}

export function EmailAnalyzer() {
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<EmailAnalysisResult | null>(null);
  const [filename, setFilename] = useState("");

  async function onFile(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0];
    if (!file) return;
    setFilename(file.name);
    setResult(null);
    setError(null);

    // Validate: only .eml or text-like MIME types
    const lower = file.name.toLowerCase();
    const okExt = lower.endsWith(".eml") || lower.endsWith(".txt");
    const okMime =
      file.type === "message/rfc822" ||
      file.type === "text/plain" ||
      file.type === "";
    if (!okExt && !okMime) {
      setError("Harap upload file .eml (email). File binary akan menghasilkan sampah.");
      return;
    }
    if (file.size > 5 * 1024 * 1024) {
      setError("File terlalu besar (maks 5 MB).");
      return;
    }

    setLoading(true);
    try {
      const text = await readFileAsText(file);
      // Basic email sanity: must contain at least one header
      const looksLikeEmail = /^(From|Subject|Received|Date|To):/m.test(text);
      if (!looksLikeEmail) {
        setError(
          "File tidak terlihat seperti email (tidak ada header From/Subject/Received).",
        );
        setLoading(false);
        return;
      }
      const r = await api.analyzeEmail(text);
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
        <CardHeader>
          <CardTitle className="text-sm">Upload email (.eml)</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <label className="flex items-center gap-2 cursor-pointer">
            <input
              type="file"
              accept=".eml,message/rfc822"
              onChange={onFile}
              disabled={loading}
              className="block w-full text-sm file:mr-3 file:py-1.5 file:px-3 file:rounded-md file:border-0 file:bg-primary file:text-primary-foreground hover:file:bg-primary/90"
            />
            {loading ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4 text-muted-foreground" />}
          </label>
          {filename ? (
            <p className="text-xs text-muted-foreground">Selected: {filename}</p>
          ) : null}
          {error ? <p className="text-xs text-critical">{error}</p> : null}
        </CardContent>
      </Card>

      {result ? (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="text-sm">Header</CardTitle>
            </CardHeader>
            <CardContent className="text-sm space-y-1">
              <div><span className="text-muted-foreground">Subject:</span> {result.parsed.subject ?? "—"}</div>
              <div><span className="text-muted-foreground">From:</span> {result.parsed.from_domain ?? "—"}</div>
              <div><span className="text-muted-foreground">Reply-To:</span> {result.parsed.reply_to_domain ?? "—"}</div>
              <div><span className="text-muted-foreground">Return-Path:</span> {result.parsed.return_path_domain ?? "—"}</div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Authentication</CardTitle></CardHeader>
            <CardContent className="space-y-1 text-sm">
              <div className="flex items-center gap-2">
                <Badge variant={authVariant(result.auth.spf)}>SPF {result.auth.spf}</Badge>
                {result.auth.spf_domain ? <span className="text-muted-foreground text-xs">{result.auth.spf_domain}</span> : null}
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={authVariant(result.auth.dkim)}>DKIM {result.auth.dkim}</Badge>
                {result.auth.dkim_domain ? <span className="text-muted-foreground text-xs">{result.auth.dkim_domain}</span> : null}
              </div>
              <div className="flex items-center gap-2">
                <Badge variant={authVariant(result.auth.dmarc)}>DMARC {result.auth.dmarc}</Badge>
                {result.auth.dmarc_domain ? <span className="text-muted-foreground text-xs">{result.auth.dmarc_domain}</span> : null}
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">IOCs ({result.iocs.length})</CardTitle></CardHeader>
            <CardContent>
              {result.iocs.length === 0 ? (
                <p className="text-sm text-muted-foreground">None found.</p>
              ) : (
                <ul className="space-y-1 text-sm">
                  {result.iocs.map((i, idx) => (
                    <li key={idx} className="flex gap-2 items-center">
                      <Badge variant="muted">{i.ioc_type}</Badge>
                      <span className="font-mono text-xs break-all">{i.value}</span>
                      <span className="text-xs text-muted-foreground ml-auto">{i.source}</span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader><CardTitle className="text-sm">Findings ({result.findings.length})</CardTitle></CardHeader>
            <CardContent>
              {result.findings.length === 0 ? (
                <p className="text-sm text-muted-foreground">None.</p>
              ) : (
                <ul className="space-y-1 text-sm">
                  {result.findings.map((f, idx) => (
                    <li key={idx} className="flex gap-2 items-center">
                      <Badge variant={f.severity === "high" ? "critical" : "medium"}>{f.severity}</Badge>
                      <span className="font-mono text-xs">{f.code}</span>
                      <span className="text-xs text-muted-foreground">{f.detail}</span>
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
