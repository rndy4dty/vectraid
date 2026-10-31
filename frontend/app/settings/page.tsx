import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";

export const dynamic = "force-dynamic";

function envBool(v: string | undefined): boolean {
  return !!v && v.length > 0;
}

export default function SettingsPage() {
  const apiUrl =
    process.env.NEXT_PUBLIC_API_URL ?? "(not set)";
  const hasApiKey = envBool(process.env.NEXT_PUBLIC_API_KEY);

  return (
    <div className="p-6 space-y-6 max-w-3xl">
      <div>
        <h1 className="text-2xl font-semibold tracking-tight">Settings</h1>
        <p className="text-sm text-muted-foreground">
          Runtime configuration (read-only). Edit .env.local on the server to
          change.
        </p>
      </div>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">API Connection</CardTitle>
        </CardHeader>
        <CardContent className="space-y-2 text-sm">
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground w-32">API URL</span>
            <span className="font-mono text-xs">{apiUrl}</span>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-muted-foreground w-32">API Key</span>
            <Badge variant={hasApiKey ? "low" : "muted"}>
              {hasApiKey ? "configured" : "not configured"}
            </Badge>
          </div>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">Threat Intelligence Providers</CardTitle>
        </CardHeader>
        <CardContent className="text-sm space-y-1">
          <p className="text-muted-foreground">
            Provider API keys are configured on the backend via{" "}
            <code className="font-mono text-xs">backend/.env</code>.
          </p>
          <ul className="list-disc pl-5 text-muted-foreground text-xs space-y-0.5">
            <li>VirusTotal — IOC reputation</li>
            <li>AbuseIPDB — IP abuse reports</li>
            <li>AlienVault OTX — pulse intelligence</li>
          </ul>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-sm">About VECTRAID</CardTitle>
        </CardHeader>
        <CardContent className="text-sm text-muted-foreground space-y-1">
          <p>Unified Threat Intelligence &amp; Investigation Platform.</p>
          <p className="text-xs">
            Evidence-first · Relationship-centric · Deterministic detection
          </p>
        </CardContent>
      </Card>
    </div>
  );
}
