"use client";

import { Check, Cloud, HardDrive, Play, Settings2, ShieldCheck, ShieldHalf } from "lucide-react";
import type { Health, StageEvent } from "@/lib/api";
import { DATASET_INFO, ENGINE_INFO, type Settings } from "@/lib/settings";
import { Button } from "@/components/ui/button";
import { BorderBeam, ThinkingOrb, orbForStage, usePrefersReducedMotion } from "@/components/effects";
import { cn } from "@/lib/utils";

/** Analyst-facing wording for each pipeline stage. */
export const STAGE_COPY: Record<number, string> = {
  1: "Loading telemetry sources...",
  2: "Reading and validating every log line...",
  3: "Aligning time zones to UTC...",
  4: "Mapping users, devices and addresses...",
  5: "Correlating cross-system logs...",
  6: "Filtering approved maintenance noise...",
  7: "Rating severity against the company matrix...",
  8: "Checking for blind spots in log coverage...",
  9: "Separating confirmed facts from suspicions...",
  10: "Building the runbook action plan...",
  11: "Writing and fact-checking the incident report...",
};

export function Splash({ error }: { error?: string | null }) {
  return (
    <div className="fixed inset-0 grid place-items-center bg-slate-950">
      <div className="flex flex-col items-center gap-5 text-center">
        <div className="relative">
          <span className="absolute inset-0 animate-ping rounded-2xl bg-orbit-500/20 motion-reduce:animate-none" />
          <div className="relative grid h-16 w-16 place-items-center rounded-2xl border border-orbit-500/40 bg-orbit-500/10">
            <ShieldHalf className="h-8 w-8 text-orbit-300" />
          </div>
        </div>
        <div>
          <p className="text-sm font-medium text-slate-100">Initializing Orbit SOC Security Platform...</p>
          <p className="mt-1 text-xs text-slate-500">{error ? error : "Checking telemetry feeds"}</p>
        </div>
      </div>
    </div>
  );
}

export function Launchpad({ settings, health, onStart, onSettings }: { settings: Settings; health: Health | null; onStart: () => void; onSettings: () => void }) {
  const reduced = usePrefersReducedMotion();
  const ds = DATASET_INFO[settings.dataset];
  const engineOk = health?.engines?.[settings.engine]?.available;
  const EngineIcon = settings.engine === "local" ? HardDrive : Cloud;
  return (
    <div className="mx-auto mt-10 w-full max-w-2xl sm:mt-20">
      <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-8 text-center shadow-2xl sm:p-10">
        <div className="mx-auto grid h-14 w-14 place-items-center rounded-2xl border border-orbit-500/40 bg-orbit-500/10">
          <ShieldHalf className="h-7 w-7 text-orbit-300" />
        </div>
        <h1 className="mt-6 font-serif text-[40px] font-medium leading-[1.1] text-white">Orbit Logistics Incident Triage</h1>
        <p className="mx-auto mt-3 max-w-[46ch] text-[15px] leading-relaxed text-slate-400">{ds.description}</p>

        <dl className="mx-auto mt-7 grid max-w-lg gap-2 text-left text-sm">
          <Row icon={<EngineIcon className="h-4 w-4" />} k="AI Engine" v={ENGINE_INFO[settings.engine].short}
            note={health && !engineOk ? "unavailable - standard report will be used" : undefined} />
          <Row icon={<ShieldCheck className="h-4 w-4" />} k="Fact verification" v={settings.verifier ? "Enabled" : "Disabled"} warn={!settings.verifier} />
          <Row icon={<Check className="h-4 w-4" />} k="Telemetry" v={`${ds.label} (${ds.sources})`} />
        </dl>

        <div className="mt-8 flex flex-col items-center gap-3">
          <BorderBeam size="pulse-inner" colorVariant="ocean" theme="dark" active={!reduced} style={{ display: "inline-block" }} className="rounded-xl">
            <button type="button" onClick={onStart}
              className="inline-flex h-12 items-center gap-2.5 rounded-xl bg-orbit-600 px-7 text-sm font-semibold text-white transition-colors hover:bg-orbit-500 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-orbit-300">
              <Play className="h-4 w-4" /> Start Incident Triage
            </button>
          </BorderBeam>
          <Button variant="ghost" size="sm" onClick={onSettings}><Settings2 className="h-3.5 w-3.5" /> Change settings</Button>
        </div>
      </div>
    </div>
  );
}

function Row({ icon, k, v, note, warn }: { icon: React.ReactNode; k: string; v: string; note?: string; warn?: boolean }) {
  return (
    <div className="flex items-center gap-3 rounded-lg border border-slate-800 bg-slate-950/60 px-3.5 py-2.5">
      <span className="text-slate-500">{icon}</span>
      <dt className="w-32 text-slate-500">{k}</dt>
      <dd className={cn("flex-1 text-slate-100", warn && "text-amber-300")}>{v}{note && <span className="block text-[11px] text-slate-500">{note}</span>}</dd>
    </div>
  );
}

export function RunningCard({ stages, current, engine }: { stages: Record<number, StageEvent>; current: number | null; engine: Settings["engine"] }) {
  const done = Object.values(stages).filter((s) => s.status === "done").length;
  const stage = current ?? Math.min(11, done + 1);
  const pct = Math.round((done / 11) * 100);
  return (
    <div className="mx-auto mt-10 w-full max-w-xl sm:mt-20">
      <div role="status" aria-live="polite" className="rounded-2xl border border-slate-800 bg-slate-900/60 p-8 shadow-2xl">
        <div className="flex items-center gap-4">
          <ThinkingOrb state={orbForStage(stage)} size={64} theme="dark" aria-hidden="true" style={{ width: 56, height: 56 }} />
          <div className="min-w-0 flex-1">
            <p className="text-base font-medium text-white">{STAGE_COPY[stage]}</p>
            <p className="mt-0.5 text-xs text-slate-500">Step {stage} of 11{stage === 11 && engine === "local" ? ". The private model runs on this machine and can take a few minutes." : ""}</p>
          </div>
        </div>
        <div className="mt-6 h-1.5 overflow-hidden rounded-full bg-slate-800">
          <div className="h-full rounded-full bg-orbit-500 transition-all duration-500" style={{ width: `${Math.max(4, pct)}%` }} />
        </div>
        <ul className="mt-5 grid gap-1.5 text-xs sm:grid-cols-2">
          {Object.entries(STAGE_COPY).map(([n, txt]) => {
            const k = Number(n);
            const isDone = stages[k]?.status === "done";
            return (
              <li key={k} className={cn("flex items-center gap-2", isDone ? "text-slate-300" : k === stage ? "text-white" : "text-slate-600")}>
                <span className={cn("grid h-3.5 w-3.5 place-items-center rounded-full border", isDone ? "border-orbit-500 bg-orbit-500/20" : "border-slate-700")}>
                  {isDone && <Check className="h-2.5 w-2.5 text-orbit-300" />}
                </span>
                {txt.replace("...", "")}
              </li>
            );
          })}
        </ul>
      </div>
    </div>
  );
}
