import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2 py-0.5 text-xs font-medium",
  {
    variants: {
      variant: {
        default: "border-border bg-secondary text-secondary-foreground",
        critical: "border-critical/30 bg-critical/10 text-critical",
        high: "border-high/30 bg-high/10 text-high",
        medium: "border-medium/30 bg-medium/10 text-medium",
        low: "border-low/30 bg-low/10 text-low",
        info: "border-info/30 bg-info/10 text-info",
        muted: "border-border bg-muted text-muted-foreground",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps
  extends React.HTMLAttributes<HTMLDivElement>,
    VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return (
    <div className={cn(badgeVariants({ variant }), className)} {...props} />
  );
}
