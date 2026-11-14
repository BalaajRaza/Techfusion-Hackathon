"use client";

import { Cloud, Database, HardDrive, ShieldCheck, ShieldOff } from "lucide-react";
import type { Health } from "@/lib/api";
import { DATASET_INFO, ENGINE_INFO, type Dataset, type Engine, type Settings } from "@/lib/settings";
import { Dialog, DialogContent, DialogDescription, DialogTitle } from "@/components/ui/dialog";
import { Button } from "@/components/ui/button";
import { cn } from "@/lib/utils";

export function SettingsDialog({ open, onOpenChange, settings, update, health, locked }: {
  open: boolean; onOpenChange: (o: boolean) => void; settings: Settings; update: (p: Partial<Settings>) => void; health: Health | null; locked: boolean;
}) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent>
        <div className="border-b border-slate-800 px-6 py-5">
          <DialogTitle className="text-base font-semibold text-white">Settings</DialogTitle>
          <DialogDescription className="mt-1 text-sm text-slate-400">Changes apply to the next triage run and to the Copilot.</DialogDescription>
        </div>

        <div className="space-y-6 px-6 py-5">
          <fieldset disabled={locked}>
            <legend className="mb-2.5 text-xs font-semibold text-slate-500">AI model</legend>
            <div role="radiogroup" aria-label="AI model" className="space-y-2">
              {(["local", "cloud"] as Engine[]).map((e) => {
                const info = ENGINE_INFO[e];
                const avail = health?.engines?.[e]?.available;
                const Icon = e === "local" ? HardDrive : Cloud;
                return (
                  <Option key={e} checked={settings.engine === e} onSelect={() => update({ engine: e })} icon={<Icon className="h-4 w-4" />}
                    title={info.label} description={info.description}
                    status={health ? (avail ? "Ready" : "Not available - the standard written report is used") : undefined} statusOk={!!avail} />
                );
              })}
            </div>
          </fieldset>

          <fieldset disabled={locked}>
            <legend className="mb-2.5 text-xs font-semibold text-slate-500">Telemetry dataset</legend>
            <div role="radiogroup" aria-label="Telemetry dataset" className="space-y-2">
              {(["orbit", "edge_cases"] as Dataset[]).map((d) => (
                <Option key={d} checked={settings.dataset === d} onSelect={() => update({ dataset: d })} icon={<Database className="h-4 w-4" />}
                  title={`${DATASET_INFO[d].label}${d === "orbit" ? ` (${DATASET_INFO[d].sources})` : ""}`} description={DATASET_INFO[d].description}
                  disabled={health ? !health.datasets[d] : false} />
              ))}
            </div>
          </fieldset>

          <div className="flex items-start gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3.5">
            {settings.verifier ? <ShieldCheck className="mt-0.5 h-4 w-4 text-emerald-400" /> : <ShieldOff className="mt-0.5 h-4 w-4 text-amber-400" />}
            <div className="flex-1">
              <p className="text-sm font-medium text-slate-100">Anti-hallucination verifier</p>
              <p className="mt-0.5 text-xs text-slate-400">
                {settings.verifier
                  ? "Every AI-written sentence is checked against the cited log lines. Anything that fails is replaced by the standard report."
                  : "Off: AI-written text is still checked and logged, but it is shown even when the check fails. Not recommended."}
              </p>
            </div>
            <button type="button" role="switch" aria-checked={settings.verifier} aria-label="Anti-hallucination verifier" disabled={locked}
              onClick={() => update({ verifier: !settings.verifier })}
              className={cn("relative mt-0.5 h-5 w-9 shrink-0 rounded-full transition-colors disabled:opacity-50", settings.verifier ? "bg-emerald-500" : "bg-slate-700")}>
              <span className={cn("absolute top-0.5 h-4 w-4 rounded-full bg-white shadow transition-transform", settings.verifier ? "translate-x-4" : "translate-x-0.5")} />
            </button>
          </div>
          {locked && <p className="text-xs text-amber-300">Settings are locked while a triage run is in progress.</p>}
        </div>

        <div className="flex justify-end border-t border-slate-800 px-6 py-4">
          <Button onClick={() => onOpenChange(false)}>Done</Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}

function Option({ checked, onSelect, icon, title, description, status, statusOk, disabled }: {
  checked: boolean; onSelect: () => void; icon: React.ReactNode; title: string; description: string; status?: string; statusOk?: boolean; disabled?: boolean;
}) {
  return (
    <button type="button" role="radio" aria-checked={checked} disabled={disabled} onClick={onSelect}
      className={cn("flex w-full items-start gap-3 rounded-lg border p-3.5 text-left transition-colors disabled:cursor-not-allowed disabled:opacity-50",
        checked ? "border-orbit-500/60 bg-orbit-500/5" : "border-slate-800 bg-slate-900/40 hover:border-slate-700")}>
      <span className={cn("mt-0.5 grid h-4 w-4 shrink-0 place-items-center rounded-full border", checked ? "border-orbit-400" : "border-slate-600")}>
        {checked && <span className="h-2 w-2 rounded-full bg-orbit-400" />}
      </span>
      <span className="flex-1">
        <span className="flex items-center gap-2 text-sm font-medium text-slate-100"><span className="text-slate-400">{icon}</span>{title}</span>
        <span className="mt-0.5 block text-xs text-slate-400">{description}</span>
        {status && <span className={cn("mt-1.5 inline-block text-[11px]", statusOk ? "text-emerald-400" : "text-slate-500")}>{status}</span>}
      </span>
    </button>
  );
}
