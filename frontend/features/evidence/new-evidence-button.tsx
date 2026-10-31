"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api } from "@/lib/api";
import { Plus, X } from "lucide-react";

const MODULES = [
  "phishtrace",
  "maltrace",
  "huntscope",
  "intelfusion",
  "manual",
];

const TYPES = [
  "email_analysis",
  "file_analysis",
  "hunt_finding",
  "ioc_match",
  "threat_intel",
];

export function NewEvidenceButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  const [evidenceId, setEvidenceId] = useState("");
  const [caseId, setCaseId] = useState("");
  const [module, setModule] = useState("manual");
  const [type, setType] = useState("ioc_match");
  const [finding, setFinding] = useState("");
  const [confidence, setConfidence] = useState(80);
  const [iocValue, setIocValue] = useState("");

  function reset() {
    setEvidenceId("");
    setCaseId("");
    setModule("manual");
    setType("ioc_match");
    setFinding("");
    setConfidence(80);
    setIocValue("");
    setError(null);
  }

  async function submit() {
    setError(null);
    try {
      const now = new Date().toISOString().replace("Z", "Z");
      await api.createEvidence({
        evidence_id: evidenceId.trim(),
        case_id: caseId.trim(),
        source_module: module,
        evidence_type: type,
        raw_reference: `raw:${evidenceId.trim()}`,
        finding: finding.trim(),
        timestamp: now,
        confidence,
        provenance: iocValue.trim() ? { ioc_value: iocValue.trim() } : {},
      });
      setOpen(false);
      reset();
      startTransition(() => router.refresh());
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    }
  }

  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" /> New Evidence
      </Button>

      {open && (
        <div
          className="fixed inset-0 z-50 bg-black/60 grid place-items-center p-4 overflow-y-auto"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-md my-8"
            onClick={(e) => e.stopPropagation()}
          >
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>New Evidence</CardTitle>
                <Button
                  variant="ghost"
                  size="icon"
                  onClick={() => setOpen(false)}
                >
                  <X className="h-4 w-4" />
                </Button>
              </CardHeader>
              <CardContent className="space-y-3">
                <div>
                  <label className="text-xs text-muted-foreground">
                    Evidence ID
                  </label>
                  <Input
                    value={evidenceId}
                    onChange={(e) => setEvidenceId(e.target.value)}
                    placeholder="ev-001"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">
                    Case ID
                  </label>
                  <Input
                    value={caseId}
                    onChange={(e) => setCaseId(e.target.value)}
                    placeholder="CASE-2026-0001"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-xs text-muted-foreground">
                      Module
                    </label>
                    <Select
                      value={module}
                      onChange={(e) => setModule(e.target.value)}
                    >
                      {MODULES.map((m) => (
                        <option key={m} value={m}>
                          {m}
                        </option>
                      ))}
                    </Select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">
                      Type
                    </label>
                    <Select
                      value={type}
                      onChange={(e) => setType(e.target.value)}
                    >
                      {TYPES.map((t) => (
                        <option key={t} value={t}>
                          {t}
                        </option>
                      ))}
                    </Select>
                  </div>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">
                    Finding
                  </label>
                  <textarea
                    value={finding}
                    onChange={(e) => setFinding(e.target.value)}
                    placeholder="Short description of what was found"
                    className="flex min-h-16 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
                  />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <label className="text-xs text-muted-foreground">
                      Confidence (0-100)
                    </label>
                    <Input
                      type="number"
                      min={0}
                      max={100}
                      value={confidence}
                      onChange={(e) =>
                        setConfidence(Number(e.target.value))
                      }
                    />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">
                      IOC value (optional)
                    </label>
                    <Input
                      value={iocValue}
                      onChange={(e) => setIocValue(e.target.value)}
                      placeholder="evil.test"
                    />
                  </div>
                </div>
                {error ? (
                  <div className="text-xs text-critical">{error}</div>
                ) : null}
                <div className="flex justify-end gap-2 pt-2">
                  <Button
                    variant="ghost"
                    onClick={() => setOpen(false)}
                    disabled={isPending}
                  >
                    Cancel
                  </Button>
                  <Button
                    onClick={submit}
                    disabled={
                      !evidenceId.trim() ||
                      !caseId.trim() ||
                      !finding.trim() ||
                      isPending
                    }
                  >
                    {isPending ? "Creating…" : "Create"}
                  </Button>
                </div>
              </CardContent>
            </Card>
          </div>
        </div>
      )}
    </>
  );
}
