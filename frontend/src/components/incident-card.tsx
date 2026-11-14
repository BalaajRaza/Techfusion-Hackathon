"use client";

import { Clock } from "lucide-react";
import { fmtUtc, type Incident } from "@/lib/api";
import { Badge, sevVariant } from "@/components/ui/badge";
import { BorderBeam, usePrefersReducedMotion } from "@/components/effects";
import { cn } from "@/lib/utils";

export const SEV_NAME: Record<string, string> = { P1: "Critical", P2: "High", P3: "Medium", P4: "Low" };

const RULE: Record<string, string> = { P1: "border-l-rose-500", P2: "border-l-amber-500", P3: "border-l-sky-500", P4: "border-l-slate-500" };

export function sevLabel(s?: string | null) {
  return s ? `${s} ${SEV_NAME[s]}` : "Needs review";
}

export function IncidentCard({ inc, selected, onSelect }: { inc: Incident; selected: boolean; onSelect: () => void }) {
  const reduced = usePrefersReducedMotion();
  const card = (
    <button
      type="button"
      onClick={onSelect}
      aria-pressed={selected}
      className={cn(
        "flex h-full w-full flex-col gap-2 rounded-lg border border-l-[3px] bg-slate-900 p-3.5 text-left transition-colors",
        RULE[inc.severity ?? ""] ?? "border-l-slate-600",
        selected ? "border-y-slate-700 border-r-slate-700" : "border-y-slate-800 border-r-slate-800 hover:bg-slate-900/80",
      )}
    >
      <Badge variant={sevVariant(inc.severity)} className="self-start px-2 py-1 font-semibold">{sevLabel(inc.severity)}</Badge>
      <h3 className="line-clamp-3 font-serif text-[15px] leading-snug text-slate-100">{inc.title}</h3>
      <span className="mt-auto flex items-center gap-1.5 text-[11px] text-slate-500">
        <Clock className="h-3 w-3" /> Detected {fmtUtc(inc.detection_time_utc)}
      </span>
    </button>
  );
  if (!selected) return card;
  // the active card glows; red for a P1, blue otherwise
  return (
    <BorderBeam size="pulse-inner" colorVariant={inc.severity === "P1" ? "sunset" : "ocean"} theme="dark" strength={0.9} active={!reduced} className="h-full rounded-lg">
      {card}
    </BorderBeam>
  );
}
