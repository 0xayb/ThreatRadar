import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";

import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center rounded-md border px-2.5 py-0.5 text-xs font-semibold transition-colors focus:outline-none focus:ring-2 focus:ring-ring focus:ring-offset-2 font-mono",
  {
    variants: {
      variant: {
        default: "border-transparent bg-primary text-primary-foreground hover:bg-primary/80",
        secondary: "border-transparent bg-secondary text-secondary-foreground hover:bg-secondary/80",
        destructive: "border-transparent bg-destructive text-destructive-foreground hover:bg-destructive/80",
        outline: "text-foreground",
        // Threat level variants
        critical: "border-destructive/30 bg-destructive/20 text-destructive",
        high: "border-orange-500/30 bg-orange-500/20 text-orange-400",
        medium: "border-yellow-500/30 bg-yellow-500/20 text-yellow-400",
        low: "border-primary/30 bg-primary/20 text-primary",
        info: "border-accent/30 bg-accent/20 text-accent",
        // IOC type variants
        ip: "border-violet-500/30 bg-violet-500/20 text-violet-400",
        domain: "border-sky-500/30 bg-sky-500/20 text-sky-400",
        hash: "border-amber-500/30 bg-amber-500/20 text-amber-400",
        url: "border-rose-500/30 bg-rose-500/20 text-rose-400",
        email: "border-emerald-500/30 bg-emerald-500/20 text-emerald-400",
        // Status variants
        active: "border-primary/30 bg-primary/20 text-primary",
        inactive: "border-muted-foreground/30 bg-muted text-muted-foreground",
        error: "border-destructive/30 bg-destructive/20 text-destructive",
      },
    },
    defaultVariants: {
      variant: "default",
    },
  },
);

export interface BadgeProps extends React.HTMLAttributes<HTMLDivElement>, VariantProps<typeof badgeVariants> {}

function Badge({ className, variant, ...props }: BadgeProps) {
  return <div className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export { Badge, badgeVariants };
