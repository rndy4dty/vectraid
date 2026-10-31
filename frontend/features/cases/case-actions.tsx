"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  api,
  type CaseResponse,
  type CaseStatus,
} from "@/lib/api";

interface Props {
  case_: CaseResponse;
  by: string;
}

export function CaseActions({ case_, by }: Props) {
  const router = useRouter();
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  const [nextStatus, setNextStatus] = useState<CaseStatus | "">("");
  const [assignee, setAssignee] = useState(case_.assignee ?? "");
  const [note, setNote] = useState("");
  const [outcome, setOutcome] = useState("escalate");
  const [rationale, setRationale] = useState("");

  function refresh() {
    startTransition(() => router.refresh());
  }

  async function doTransition() {
    if (!nextStatus) return;
    setError(null);
    try {
      await api.transitionCase(case_.case_id, nextStatus, by);
      setNextStatus("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    }
  }

  async function doAssign() {
    if (!assignee.trim()) return;
    setError(null);
    try {
      await api.assignCase(case_.case_id, assignee.trim(), by);
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    }
  }

  async function doAddNote() {
    if (!note.trim()) return;
    setError(null);
    try {
      await api.addNote(case_.case_id, note.trim(), by);
      setNote("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    }
  }

  async function doAddDecision() {
    if (!rationale.trim()) return;
    setError(null);
    try {
      await api.addDecision(case_.case_id, outcome, rationale.trim(), by);
      setRationale("");
      refresh();
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    }
  }

  const validTransitions: Record<CaseStatus, CaseStatus[]> = {
    new: ["investigating"],
    investigating: ["resolved", "closed"],
    resolved: ["investigating", "closed"],
    closed: [],
  };

  const options = validTransitions[case_.status] ?? [];

  return (
    <div className="space-y-4">
      {error ? (
        <div className="text-xs text-critical px-1">{error}</div>
      ) : null}

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Transition status</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          {options.length === 0 ? (
            <p className="text-xs text-muted-foreground">
              Case is closed - no further transitions.
            </p>
          ) : (
            <>
              <Select
                value={nextStatus}
                onChange={(e) =>
                  setNextStatus(e.target.value as CaseStatus | "")
                }
              >
                <option value="">Select next status…</option>
                {options.map((s) => (
                  <option key={s} value={s}>
                    {s}
                  </option>
                ))}
              </Select>
              <Button
                size="sm"
                onClick={doTransition}
                disabled={!nextStatus || isPending}
                className="w-full"
              >
                Transition
              </Button>
            </>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Assign analyst</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Input
            value={assignee}
            onChange={(e) => setAssignee(e.target.value)}
            placeholder="analyst@example.com"
          />
          <Button
            size="sm"
            onClick={doAssign}
            disabled={!assignee.trim() || isPending}
            className="w-full"
          >
            Assign
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Add note</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <textarea
            value={note}
            onChange={(e) => setNote(e.target.value)}
            placeholder="Investigation notes…"
            className="flex min-h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
          <Button
            size="sm"
            onClick={doAddNote}
            disabled={!note.trim() || isPending}
            className="w-full"
          >
            Add note
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Record decision</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2">
          <Select
            value={outcome}
            onChange={(e) => setOutcome(e.target.value)}
          >
            <option value="escalate">Escalate</option>
            <option value="false_positive">False positive</option>
            <option value="duplicate">Duplicate</option>
            <option value="resolved">Resolved</option>
            <option value="close">Close</option>
          </Select>
          <textarea
            value={rationale}
            onChange={(e) => setRationale(e.target.value)}
            placeholder="Rationale (required)…"
            className="flex min-h-20 w-full rounded-md border border-input bg-background px-3 py-2 text-sm focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-ring"
          />
          <Button
            size="sm"
            onClick={doAddDecision}
            disabled={!rationale.trim() || isPending}
            className="w-full"
          >
            Record decision
          </Button>
        </CardContent>
      </Card>
    </div>
  );
}
