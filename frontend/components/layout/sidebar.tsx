"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import {
  LayoutDashboard,
  FolderSearch,
  ShieldAlert,
  Network,
  Mail,
  FileSearch,
  Radar,
  Settings,
  Activity,
} from "lucide-react";
import { cn } from "@/lib/utils";

const nav = [
  { href: "/", label: "Overview", icon: LayoutDashboard },
  { href: "/cases", label: "Cases", icon: FolderSearch },
  { href: "/evidence", label: "Evidence", icon: ShieldAlert },
  { href: "/iocs", label: "IOC Explorer", icon: Radar },
  { href: "/graph", label: "ThreatGraph", icon: Network },
  { href: "/analyze/email", label: "PhishTrace", icon: Mail },
  { href: "/analyze/file", label: "MalTrace", icon: FileSearch },
  { href: "/hunt", label: "HuntScope", icon: Activity },
] as const;

export function Sidebar() {
  const pathname = usePathname();

  return (
    <aside className="w-60 shrink-0 border-r border-border bg-card/50 flex flex-col">
      <div className="px-4 py-5 border-b border-border">
        <Link href="/" className="flex items-center gap-2">
          <div className="h-8 w-8 rounded-md bg-primary/15 text-primary grid place-items-center font-bold">
            V
          </div>
          <div>
            <div className="font-semibold tracking-tight">VECTRAID</div>
            <div className="text-xs text-muted-foreground">
              Threat Intelligence
            </div>
          </div>
        </Link>
      </div>

      <nav className="flex-1 p-2 space-y-1">
        {nav.map((item) => {
          const Icon = item.icon;
          const active =
            pathname === item.href ||
            (item.href !== "/" && pathname.startsWith(item.href));
          return (
            <Link
              key={item.href}
              href={item.href}
              className={cn(
                "flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors",
                active
                  ? "bg-primary/15 text-primary"
                  : "text-muted-foreground hover:bg-secondary hover:text-foreground",
              )}
            >
              <Icon className="h-4 w-4" />
              {item.label}
            </Link>
          );
        })}
      </nav>

      <div className="p-2 border-t border-border">
        <Link
          href="/settings"
          className="flex items-center gap-3 rounded-md px-3 py-2 text-sm text-muted-foreground hover:bg-secondary hover:text-foreground"
        >
          <Settings className="h-4 w-4" />
          Settings
        </Link>
      </div>
    </aside>
  );
}
