import { EmailAnalyzer } from "@/features/analyze/email-analyzer";

export const dynamic = "force-dynamic";

export default function EmailAnalysisPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">PhishTrace</h1>
        <p className="text-sm text-muted-foreground">
          Email forensics - parse headers, extract IOCs, analyze authentication
        </p>
      </div>
      <EmailAnalyzer />
    </div>
  );
}
