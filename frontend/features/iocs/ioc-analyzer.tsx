"use client";

import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { api } from "@/lib/api";
import { Loader2, Search } from "lucide-react";

interface Enrichment {
  provider: string;
  classification: string;
  confidence: number;
  error: string | null;
}

interface AnalyzeResult {
  indicator: string;
  ioc_type: string;
  enrichment: Enrichment[];
}

const IOC_TYPES = [
  { value: "ipv4", label: "IPv4" },
  { value: "domain", label: "Domain" },
  { value: "url", label: "URL" },
  { value: "md5", label: "MD5" },
  { value: "sha1", label: "SHA1" },
  { value: "sha256", label: "SHA256" },
  { value: "email", label: "Email" },
];

function classificationVariant(
  c: string,
): "critical" | "high" | "medium" | "low" | "info" | "muted" | "default" {
  switch (c) {
    case "malicious":
      return "critical";
    case "suspicious":
      return "high";
    case "clean":
      return "low";
    case "unknown":
      return "muted";
    default:
      return "default";
  }
}

export function IOCAnalyzer() {
  const [indicator, setIndicator] = useState("");
  const [iocType, setIocType] = useState("ipv4");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [result, setResult] = useState<AnalyzeResult | null>(null);

  async function analyze() {
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const r = await api.analyzeIOC(indicator.trim(), iocType);
      setResult(r as AnalyzeResult);
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    } finally {
      setLoading(false);
    }
  }

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Analyze indicator</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-[160px_1fr_auto] gap-2">
            <Select
              value={iocType}
              onChange={(e) => setIocType(e.target.value)}
            >
              {IOC_TYPES.map((t) => (
                <option key={t.value} value={t.value}>
                  {t.label}
                </option>
              ))}
            </Select>
            <Input
              value={indicator}
              onChange={(e) => setIndicator(e.target.value)}
              placeholder="e.g. 8.8.8.8, example.com, or sha256 hash"
              onKeyDown={(e) => {
                if (e.key === "Enter" && indicator.trim()) analyze();
              }}
            />
            <Button
              onClick={analyze}
              disabled={!indicator.trim() || loading}
            >
              {loading ? (
                <Loader2 className="h-4 w-4 animate-spin" />
              ) : (
                <Search className="h-4 w-4" />
              )}
              Analyze
            </Button>
          </div>
          {error ? (
            <div className="text-xs text-critical">{error}</div>
          ) : null}
        </CardContent>
      </Card>

      {result ? (
        <Card>
          <CardHeader>
            <CardTitle className="text-sm">
              Results for{" "}
              <span className="font-mono">{result.indicator}</span>
              <Badge variant="info" className="ml-2">
                {result.ioc_type}
              </Badge>
            </CardTitle>
          </CardHeader>
          <CardContent>
            {result.enrichment.length === 0 ? (
              <p className="text-sm text-muted-foreground">
                No providers queried. Check server configuration.
              </p>
            ) : (
              <div className="space-y-2">
                {result.enrichment.map((e) => (
                  <div
                    key={e.provider}
                    className="flex items-center justify-between border-b border-border last:border-0 pb-2 last:pb-0"
                  >
                    <div className="flex items-center gap-3">
                      <span className="font-medium text-sm capitalize">
                        {e.provider}
                      </span>
                      <Badge variant={classificationVariant(e.classification)}>
                        {e.classification}
                      </Badge>
                    </div>
                    <div className="text-xs text-muted-foreground">
                      {e.error ? (
                        <span className="text-critical">{e.error}</span>
                      ) : (
                        <span>confidence {e.confidence}</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>
      ) : null}
    </div>
  );
}
