import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { IOCAnalyzer } from "@/features/iocs/ioc-analyzer";

export const dynamic = "force-dynamic";

export default function IOCPage() {
  return (
    <div className="p-6 space-y-6">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">
          IOC Explorer
        </h1>
        <p className="text-sm text-muted-foreground">
          Query indicators across threat intelligence providers
        </p>
      </div>

      <IOCAnalyzer />

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">About</CardTitle>
        </CardHeader>
        <CardContent className="text-xs text-muted-foreground space-y-1">
          <p>
            VECTRAID queries three providers: VirusTotal, AbuseIPDB, and
            AlienVault OTX.
          </p>
          <p>
            Results are shown per-provider and never merged. Conflicting
            verdicts are preserved as evidence.
          </p>
          <p>
            Free-tier rate limits apply: VirusTotal 4 req/min, AbuseIPDB
            1000/day, OTX unlimited.
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
