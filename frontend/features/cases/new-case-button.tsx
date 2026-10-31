"use client";

import { useState, useTransition } from "react";
import { useRouter } from "next/navigation";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select } from "@/components/ui/select";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { api, type CasePriority } from "@/lib/api";
import { Plus, X } from "lucide-react";

export function NewCaseButton() {
  const router = useRouter();
  const [open, setOpen] = useState(false);
  const [title, setTitle] = useState("");
  const [priority, setPriority] = useState<CasePriority>("medium");
  const [createdBy, setCreatedBy] = useState("analyst@example.com");
  const [isPending, startTransition] = useTransition();
  const [error, setError] = useState<string | null>(null);

  async function submit() {
    setError(null);
    try {
      const created = await api.createCase({
        title: title.trim(),
        priority,
        created_by: createdBy.trim(),
      });
      setOpen(false);
      setTitle("");
      startTransition(() => {
        router.push(`/cases/${created.case_id}`);
        router.refresh();
      });
    } catch (e) {
      setError(e instanceof Error ? e.message : "unknown");
    }
  }

  return (
    <>
      <Button onClick={() => setOpen(true)}>
        <Plus className="h-4 w-4" /> New Case
      </Button>

      {open && (
        <div
          className="fixed inset-0 z-50 bg-black/60 grid place-items-center p-4"
          onClick={() => setOpen(false)}
        >
          <div
            className="w-full max-w-md"
            onClick={(e) => e.stopPropagation()}
          >
            <Card>
              <CardHeader className="flex flex-row items-center justify-between">
                <CardTitle>Create Case</CardTitle>
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
                    Title
                  </label>
                  <Input
                    value={title}
                    onChange={(e) => setTitle(e.target.value)}
                    placeholder="e.g. Suspicious phishing email"
                    autoFocus
                  />
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">
                    Priority
                  </label>
                  <Select
                    value={priority}
                    onChange={(e) =>
                      setPriority(e.target.value as CasePriority)
                    }
                  >
                    <option value="low">Low</option>
                    <option value="medium">Medium</option>
                    <option value="high">High</option>
                    <option value="critical">Critical</option>
                  </Select>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground">
                    Created by
                  </label>
                  <Input
                    value={createdBy}
                    onChange={(e) => setCreatedBy(e.target.value)}
                  />
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
                    disabled={!title.trim() || isPending}
                  >
                    {isPending ? "Creating..." : "Create"}
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
