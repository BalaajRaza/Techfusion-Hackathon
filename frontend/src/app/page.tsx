"use client";

import { useCallback, useEffect, useRef, useState } from "react";
import { FileClock, RotateCcw, Settings, ShieldHalf } from "lucide-react";
import { api, API_URL, type CaseFile, type Health, type StageEvent } from "@/lib/api";
import { useSettings } from "@/lib/settings";
import { Button } from "@/components/ui/button";
import { EvidenceProvider } from "@/components/evidence";
import { IncidentCard } from "@/components/incident-card";
import { IncidentWorkspace } from "@/components/dossier";
import { Assistant } from "@/components/assistant";
import { SettingsDialog } from "@/components/settings-dialog";
import { AuditSheet } from "@/components/audit-sheet";
import { Launchpad, RunningCard, Splash } from "@/components/launch";

type AppState = "splash" | "ready" | "running" | "triaged";

const SPLASH_MS = 1500;

export default function Home() {
  const { settings, update } = useSettings();
  const [appState, setAppState] = useState<AppState>("splash");
  const [health, setHealth] = useState<Health | null>(null);
  const [backendError, setBackendError] = useState<string | null>(null);
  const [caseFile, setCase] = useState<CaseFile | null>(null);
  const [selected, setSelected] = useState<string | null>(null);
  const [stages, setStages] = useState<Record<number, StageEvent>>({});
  const [current, setCurrent] = useState<number | null>(null);
  const [runError, setRunError] = useState<string | null>(null);
  const [settingsOpen, setSettingsOpen] = useState(false);
  const [auditOpen, setAuditOpen] = useState(false);
  const esRef = useRef<EventSource | null>(null);

  // splash: hold for at least 1.5 s while the telemetry feeds (backend) are checked; never auto-start triage
  useEffect(() => {
    let live = true;
    const started = Date.now();
    const finish = () => {
      const wait = Math.max(0, SPLASH_MS - (Date.now() - started));
      setTimeout(() => live && setAppState("ready"), wait);
    };
    api.health()
      .then((h) => { if (live) setHealth(h); })
      .catch(() => { if (live) setBackendError(`The triage service at ${API_URL} is not responding. Start it, then reload this page.`); })
      .finally(finish);
    return () => { live = false; };
  }, []);

  useEffect(() => () => esRef.current?.close(), []);

  const start = useCallback(() => {
    esRef.current?.close();
    setRunError(null);
    setStages({});
    setCurrent(1);
    setAppState("running");
    const llm = health?.engines?.[settings.engine]?.available ? settings.engine : "off";
    const es = new EventSource(api.streamUrl(settings.dataset, llm, 180, settings.verifier));
    esRef.current = es;
    es.onmessage = async (msg) => {
      const ev = JSON.parse(msg.data) as StageEvent & { detail?: string };
      if (ev.status === "running") setCurrent(ev.stage);
      else if (ev.status === "done") setStages((s) => ({ ...s, [ev.stage]: ev }));
      else if (ev.status === "complete" || ev.status === "error") {
        es.close();
        if (ev.status === "error") { setRunError(ev.detail ?? "Triage failed."); setAppState("ready"); return; }
        try {
          const c = await api.case(settings.dataset);
          setCase(c);
          setSelected(c.incidents[0]?.incident_id ?? null);
          setAppState("triaged");
        } catch (e) {
          setRunError(String((e as Error).message));
          setAppState("ready");
        }
        setCurrent(null);
      }
    };
    es.onerror = () => { es.close(); setCurrent(null); setRunError("Lost connection to the triage service during the run."); setAppState("ready"); };
  }, [health, settings]);

  if (appState === "splash") return <Splash />;

  const inc = caseFile?.incidents.find((i) => i.incident_id === selected) ?? null;

  return (
    <EvidenceProvider dataset={caseFile?.dataset ?? settings.dataset}>
      <div className="flex min-h-screen flex-col">
        <header className="sticky top-0 z-20 border-b border-slate-800/80 bg-slate-950/90 backdrop-blur">
          <div className="mx-auto flex max-w-[1600px] items-center gap-3 px-4 py-3 sm:px-6">
            <div className="grid h-8 w-8 place-items-center rounded-lg border border-orbit-500/40 bg-orbit-500/10"><ShieldHalf className="h-4 w-4 text-orbit-300" /></div>
            <div className="min-w-0">
              <p className="truncate text-sm font-semibold text-white">Orbit SOC</p>
              <p className="truncate text-xs text-slate-500">Incident triage</p>
            </div>
            <span className="ml-4 hidden items-center gap-1.5 text-xs text-slate-400 sm:flex">
              <span className={`h-1.5 w-1.5 rounded-full ${backendError ? "bg-rose-500" : "bg-emerald-400"}`} />{backendError ? "Telemetry offline" : "Telemetry online"}
            </span>
            <div className="ml-auto flex items-center gap-1.5">
              {appState === "triaged" && (
                <>
                  <Button variant="ghost" size="sm" onClick={() => setAuditOpen(true)}><FileClock className="h-4 w-4" /><span className="hidden sm:inline">Audit Logs</span></Button>
                  <Button variant="ghost" size="sm" onClick={start}><RotateCcw className="h-4 w-4" /><span className="hidden sm:inline">Re-run</span></Button>
                </>
              )}
              <Button variant="ghost" size="icon" aria-label="Settings" onClick={() => setSettingsOpen(true)}><Settings className="h-4 w-4" /></Button>
            </div>
          </div>
        </header>

        <main className="mx-auto w-full max-w-[1600px] flex-1 px-4 py-5 sm:px-6">
          {backendError && <p className="mx-auto mb-4 max-w-2xl rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-100">{backendError}</p>}
          {runError && <p className="mx-auto mb-4 max-w-2xl rounded-lg border border-rose-500/30 bg-rose-500/10 p-3 text-sm text-rose-100">{runError}</p>}

          {appState === "ready" && <Launchpad settings={settings} health={health} onStart={start} onSettings={() => setSettingsOpen(true)} />}
          {appState === "running" && <RunningCard stages={stages} current={current} engine={settings.engine} />}

          {appState === "triaged" && caseFile && (
            <div className="grid grid-cols-1 gap-6 lg:grid-cols-12 reveal">
              <div className="min-w-0 space-y-5 lg:col-span-7">
                <section aria-label="Incidents">
                  <div className="mb-2.5 flex items-baseline justify-between">
                    <h2 className="text-[15px] font-semibold text-slate-100">Active incidents</h2>
                    <span className="text-xs text-slate-500">{caseFile.incidents.length} incidents, {caseFile.exclusions.length} maintenance events suppressed</span>
                  </div>
                  <div className="grid grid-cols-2 gap-3 xl:grid-cols-4">
                    {caseFile.incidents.map((i) => <IncidentCard key={i.incident_id} inc={i} selected={i.incident_id === selected} onSelect={() => setSelected(i.incident_id)} />)}
                  </div>
                </section>
                {inc
                  ? <IncidentWorkspace key={inc.incident_id} inc={inc} report={caseFile.reports[inc.incident_id]} caseFile={caseFile} />
                  : <p className="rounded-xl border border-slate-800 p-6 text-sm text-slate-400">No incidents were found in this telemetry.</p>}
              </div>
              <aside className="lg:col-span-5">
                <div className="lg:sticky lg:top-[76px] lg:h-[calc(100vh-100px)]">
                  <Assistant settings={settings} ready />
                </div>
              </aside>
            </div>
          )}
        </main>
      </div>

      <SettingsDialog open={settingsOpen} onOpenChange={setSettingsOpen} settings={settings} update={update} health={health} locked={appState === "running"} />
      {caseFile && <AuditSheet open={auditOpen} onOpenChange={setAuditOpen} caseFile={caseFile} incident={inc} />}
    </EvidenceProvider>
  );
}
