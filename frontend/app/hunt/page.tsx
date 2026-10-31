import { HuntAnalyzer } from "@/features/analyze/hunt-analyzer";

export const dynamic = "force-dynamic";

export default function HuntPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">HuntScope</h1>
        <p className="text-sm text-muted-foreground">
          Threat hunting over security logs - detection rules and IOC matching
        </p>
      </div>
      <HuntAnalyzer />
    </div>
  );
}
