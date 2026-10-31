import { FileAnalyzer } from "@/features/analyze/file-analyzer";

export const dynamic = "force-dynamic";

export default function FileAnalysisPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">MalTrace</h1>
        <p className="text-sm text-muted-foreground">
          Static malware analysis - identify, hash, PE metadata, YARA, classify
        </p>
      </div>
      <FileAnalyzer />
    </div>
  );
}
