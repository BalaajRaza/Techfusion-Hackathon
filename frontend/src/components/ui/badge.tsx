import * as React from "react";
import { cva, type VariantProps } from "class-variance-authority";
import { cn } from "@/lib/utils";

const badgeVariants = cva(
  "inline-flex items-center gap-1 rounded-md border px-1.5 py-0.5 text-[11px] font-medium leading-none whitespace-nowrap transition-colors",
  {
    variants: {
      variant: {
        default: "border-slate-700 bg-slate-800 text-slate-200",
        outline: "border-slate-700 text-slate-300",
        p1: "border-rose-500/60 bg-rose-500/20 text-rose-200",
        p2: "border-amber-500/60 bg-amber-500/20 text-amber-100",
        p3: "border-sky-500/60 bg-sky-500/20 text-sky-100",
        p4: "border-slate-500/60 bg-slate-600/40 text-slate-200",
        confirmed: "border-emerald-500/50 bg-emerald-500/15 text-emerald-200",
        suspected: "border-amber-500/50 bg-amber-500/15 text-amber-200",
        insufficient: "border-slate-600 bg-slate-800 text-slate-300",
        cyan: "border-orbit-500/50 bg-orbit-500/10 text-orbit-200",
      },
    },
    defaultVariants: { variant: "default" },
  },
);

export interface BadgeProps extends React.HTMLAttributes<HTMLSpanElement>, VariantProps<typeof badgeVariants> {}

export function Badge({ className, variant, ...props }: BadgeProps) {
  return <span className={cn(badgeVariants({ variant }), className)} {...props} />;
}

export const sevVariant = (s?: string | null) =>
  (({ P1: "p1", P2: "p2", P3: "p3", P4: "p4" }) as Record<string, BadgeProps["variant"]>)[s ?? ""] ?? "outline";
export const tierVariant = (t: string) =>
  (({ CONFIRMED: "confirmed", SUSPECTED: "suspected", INSUFFICIENT_EVIDENCE: "insufficient" }) as Record<string, BadgeProps["variant"]>)[t] ?? "outline";
