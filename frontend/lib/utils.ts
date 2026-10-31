import { clsx, type ClassValue } from "clsx";
import { twMerge } from "tailwind-merge";

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs));
}

export function formatRelativeTime(iso: string): string {
  try {
    const then = new Date(iso).getTime();
    const now = Date.now();
    const diff = Math.floor((now - then) / 1000);
    if (diff < 60) return `${diff}s ago`;
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return `${Math.floor(diff / 86400)}d ago`;
  } catch {
    return iso;
  }
}

export function riskColor(classification: string): string {
  switch (classification.toLowerCase()) {
    case "critical":
      return "text-critical";
    case "high":
      return "text-high";
    case "medium":
      return "text-medium";
    case "low":
      return "text-low";
    case "insufficient_data":
      return "text-muted-foreground";
    default:
      return "text-foreground";
  }
}

export function statusVariant(
  status: string,
): "default" | "critical" | "high" | "medium" | "low" | "info" | "muted" {
  switch (status) {
    case "new":
      return "info";
    case "investigating":
      return "medium";
    case "resolved":
      return "low";
    case "closed":
      return "muted";
    default:
      return "default";
  }
}

export function priorityVariant(
  priority: string,
): "default" | "critical" | "high" | "medium" | "low" | "info" | "muted" {
  switch (priority) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      return "default";
  }
}
