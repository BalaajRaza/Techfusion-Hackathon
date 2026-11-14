"use client";

import { useEffect, useMemo, useState } from "react";
import { BellRing, CheckCircle2, CircleAlert, Clock, Phone, Server, ShieldCheck, Sparkles, User } from "lucide-react";
import { fmtLocal, fmtUtc, type CaseFile, type Claim, type Exclusion, type Incident, type Report, type Tier } from "@/lib/api";
import { Badge, sevVariant } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Citations } from "@/components/evidence";
import { MetalBadge, MetalFx, usePrefersReducedMotion } from "@/components/effects";
import { sevLabel } from "@/components/incident-card";
import { cn } from "@/lib/utils";

/* ----------------------------------------------------------- vocabulary */
const PHASE: Record<string, { label: string; tone: string; hex: string }> = {
  Reconnaissance: { label: "Reconnaissance", tone: "bg-slate-400", hex: "#94a3b8" },
  Delivery: { label: "Delivery", tone: "bg-violet-400", hex: "#a78bfa" },
  Click: { label: "Initial access", tone: "bg-orange-400", hex: "#fb923c" },
  "Credential use": { label: "Initial access", tone: "bg-orange-400", hex: "#fb923c" },
  "Remote session": { label: "Initial access", tone: "bg-orange-400", hex: "#fb923c" },
  "Office logon": { label: "Account activity", tone: "bg-orange-300", hex: "#fdba74" },
  Attack: { label: "Exploitation", tone: "bg-orange-400", hex: "#fb923c" },
  "Internal access": { label: "Discovery", tone: "bg-amber-400", hex: "#fbbf24" },
  "Privileged access": { label: "Privileged access", tone: "bg-amber-400", hex: "#fbbf24" },
  Impact: { label: "Exfiltration", tone: "bg-rose-500", hex: "#f43f5e" },
  "Session end": { label: "Session ends", tone: "bg-slate-400", hex: "#94a3b8" },
  Persistence: { label: "Persistence", tone: "bg-fuchsia-400", hex: "#e879f9" },
  Aftermath: { label: "Impact", tone: "bg-rose-400", hex: "#fb7185" },
  "Attack on tooling": { label: "Attack on tooling", tone: "bg-rose-400", hex: "#fb7185" },
  Detection: { label: "Detection", tone: "bg-orbit-400", hex: "#8c97fb" },
};
const phaseOf = (p: string) => PHASE[p] ?? { label: p || "Activity", tone: "bg-slate-400", hex: "#94a3b8" };

const LEDGER: { tier: Tier; title: string; blurb: string; dot: string; rule: string; head: string }[] = [
  { tier: "CONFIRMED", title: "Confirmed facts", blurb: "Stated directly by a log line or reference table.", dot: "bg-emerald-400", rule: "border-emerald-500/60", head: "text-emerald-300" },
  { tier: "SUSPECTED", title: "Suspected activity", blurb: "Fits an attack pattern, but joins two facts with an assumption that is written out.", dot: "bg-amber-400", rule: "border-amber-500/60", head: "text-amber-300" },
  { tier: "INSUFFICIENT_EVIDENCE", title: "Unobserved or missing logs", blurb: "The logs are silent or the source is not collected. Never filled with a guess.", dot: "bg-slate-500", rule: "border-slate-600", head: "text-slate-300" },
];

const RUNBOOK_NAME: Record<string, string> = {
  "RB-PHISH-01": "Phishing response", "RB-CRED-02": "Credential compromise", "RB-WEB-03": "Web application attack",
  "RB-EXFIL-04": "Data exfiltration", "RB-SCAN-05": "Scanning and reconnaissance",
};

function SectionTitle({ children, aside }: { children: React.ReactNode; aside?: React.ReactNode }) {
  return (
    <div className="mb-3 flex items-baseline justify-between gap-3">
      <h3 className="text-[15px] font-semibold text-slate-100">{children}</h3>
      {aside}
    </div>
  );
}

/* ----------------------------------------------------------- main */
export function IncidentWorkspace({ inc, report, caseFile }: { inc: Incident; report: Report; caseFile: CaseFile }) {
  const claims = useMemo(() => Object.fromEntries(inc.claims.map((c) => [c.claim_id, c])), [inc]);
  const v = report.verifier;
  const aiWritten = report.summary_source !== "template";
  return (
    <section aria-label="Incident analysis and action plan" className="rounded-lg border border-slate-800 bg-slate-900/50">
      <header className="border-b border-slate-800 px-6 pb-5 pt-5">
        <div className="flex flex-wrap items-center gap-3">
          {inc.severity === "P1"
            ? <span className="inline-flex items-center gap-2"><MetalBadge>P1</MetalBadge><span className="text-sm font-semibold text-rose-200">Critical</span></span>
            : <Badge variant={sevVariant(inc.severity)} className="px-2 py-1 font-semibold">{sevLabel(inc.severity)}</Badge>}
          {inc.status === "NEEDS_REVIEW" && <Badge variant="suspected"><CircleAlert className="h-3 w-3" /> Analyst review needed</Badge>}
          <span className="ml-auto flex items-center gap-1.5 text-xs text-slate-500">
            {v.passed ? <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" /> : <CircleAlert className="h-3.5 w-3.5 text-amber-400" />}
            {v.passed ? `Fact-checked: ${v.citations_checked} source references verified` : "Fact-check found issues. Open Audit Logs."}
          </span>
        </div>
        <h2 className="mt-3 max-w-[40ch] font-serif text-[28px] font-medium leading-[1.15] text-white">{inc.title}</h2>
        <p className="mt-2 text-sm text-slate-400">{inc.incident_type}. The SOC first saw it at <span className="tabular-nums text-slate-200">{fmtUtc(inc.detection_time_utc, true)}</span>.</p>
      </header>

      <Tabs defaultValue="overview" className="px-6 pb-6">
        <TabsList>
          <TabsTrigger value="overview">Overview and timeline</TabsTrigger>
          <TabsTrigger value="actions">Runbook actions and SLA</TabsTrigger>
          <TabsTrigger value="ledger">Evidence ledger</TabsTrigger>
          <TabsTrigger value="noise">Suppressed noise</TabsTrigger>
        </TabsList>

        <TabsContent value="overview" className="space-y-9">
          <section>
            <SectionTitle aside={aiWritten ? <span className="flex items-center gap-1 text-xs text-orbit-300"><Sparkles className="h-3 w-3" /> AI-written, fact-checked</span> : null}>
              Executive summary
            </SectionTitle>
            <ul className="max-w-[68ch] space-y-3.5">
              {inc.summary.map((s, i) => {
                const used = s.claim_ids.map((id) => claims[id]).filter(Boolean) as Claim[];
                const tier: Tier = used.some((c) => c.status === "INSUFFICIENT_EVIDENCE") ? "INSUFFICIENT_EVIDENCE" : used.some((c) => c.status === "SUSPECTED") ? "SUSPECTED" : "CONFIRMED";
                return (
                  <li key={i} className={cn("border-l-2 pl-4 font-serif text-[17px] leading-[1.75] text-slate-200", LEDGER.find((l) => l.tier === tier)?.rule)}>
                    {cleanSummary(s.text)} <Citations items={used.flatMap((c) => c.citations)} />
                  </li>
                );
              })}
            </ul>
            <p className="mt-3 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
              <Key dot="bg-emerald-400" label="Confirmed" />
              <Key dot="bg-amber-400" label="Suspected" />
              <Key dot="bg-slate-500" label="Not visible in the logs" />
            </p>
          </section>

          <Timeline inc={inc} caseFile={caseFile} />
          <Impacted inc={inc} />
        </TabsContent>

        <TabsContent value="actions" className="space-y-9">
          <ActionPlan inc={inc} />
          <Escalation inc={inc} />
        </TabsContent>

        <TabsContent value="ledger" className="space-y-8">
          {LEDGER.map((l) => {
            const rows = inc.claims.filter((c) => c.status === l.tier);
            return (
              <section key={l.tier}>
                <div className="mb-1 flex items-center gap-2">
                  <span className={cn("h-2 w-2 rounded-full", l.dot)} />
                  <h3 className={cn("text-[15px] font-semibold", l.head)}>{l.title}</h3>
                  <span className="text-xs text-slate-500">{rows.length}</span>
                </div>
                <p className="mb-3 text-xs text-slate-500">{l.blurb}</p>
                {rows.length === 0 && <p className="text-sm text-slate-500">None for this incident.</p>}
                <ul className="space-y-3">
                  {rows.map((c) => (
                    <li key={c.claim_id} className={cn("border-l-2 pl-4", l.rule)}>
                      <p className="max-w-[72ch] text-sm leading-relaxed text-slate-200">{c.text} <Citations items={c.citations} /></p>
                      {c.rule && <p className="mt-1 max-w-[72ch] text-xs leading-relaxed text-slate-500"><span className="font-medium text-slate-400">{l.tier === "SUSPECTED" ? "Assumption: " : "Why: "}</span>{c.rule}</p>}
                    </li>
                  ))}
                </ul>
              </section>
            );
          })}
        </TabsContent>

        <TabsContent value="noise">
          <SuppressedNoise items={caseFile.exclusions} />
        </TabsContent>
      </Tabs>
    </section>
  );
}

function Key({ dot, label }: { dot: string; label: string }) {
  return <span className="inline-flex items-center gap-1.5"><span className={cn("h-1.5 w-1.5 rounded-full", dot)} />{label}</span>;
}

/** Template summaries are already plain; this also removes any stray claim tags. */
function cleanSummary(t: string) {
  return t.replace(/\s*\((?:C\d+(?:,\s*)?)+\)/g, "").replace(/\s*(?:\[C\d+\])+/g, "").trim();
}

/* ----------------------------------------------------------- the ribbon */
const tm = (iso: string) => new Date(iso).getTime();
const hhmm = (ms: number) => new Date(ms).toISOString().slice(11, 16);

/**
 * Every event on one true time axis: when it happened, when the SOC clock
 * started, and where the logs go dark. Distances are real, so a 90 minute
 * silence looks like one.
 */
function IncidentRibbon({ inc, onPick }: { inc: Incident; onPick: (i: number) => void }) {
  const model = useMemo(() => {
    const pts = inc.timeline.map((t) => ({ a: tm(t.ts_utc), b: t.ts_end_utc ? tm(t.ts_end_utc) : tm(t.ts_utc) }));
    if (!pts.length) return null;
    const lo0 = Math.min(...pts.map((p) => p.a));
    const hi0 = Math.max(...pts.map((p) => p.b));
    const span0 = Math.max(hi0 - lo0, 60_000);
    const pad = span0 * 0.04;
    const lo = lo0 - pad, hi = hi0 + pad, span = hi - lo;
    const pct = (ms: number) => Math.min(100, Math.max(0, ((ms - lo) / span) * 100));
    const gaps = inc.gaps.map((g) => ({ ...g, a: Math.max(lo, tm(g.start_utc)), b: Math.min(hi, tm(g.end_utc)) })).filter((g) => g.b > g.a);
    const clock = inc.detection_time_utc ? tm(inc.detection_time_utc) : null;
    const ticks = Array.from({ length: 5 }, (_, i) => lo + (span * i) / 4);
    return { pts, pct, gaps, clock, ticks, lo, hi };
  }, [inc]);
  if (!model) return null;
  const { pts, pct, gaps, clock, ticks } = model;
  return (
    <figure aria-label="Incident ribbon: each event on a true time axis" className="mb-6">
      <div className="relative h-16 rounded-md bg-slate-950/70 ring-1 ring-slate-800">
        {gaps.map((g, i) => (
          <div key={i} className="gap-hatch absolute inset-y-0 rounded-sm" style={{ left: `${pct(g.a)}%`, width: `${Math.max(0.8, pct(g.b) - pct(g.a))}%` }}
            title={`No ${g.source.toLowerCase()} logs from ${hhmm(tm(g.start_utc))} to ${hhmm(tm(g.end_utc))} UTC`} />
        ))}
        {clock !== null && clock >= model.lo && clock <= model.hi && (
          <div className="absolute inset-y-0 z-10 w-px bg-orbit-300" style={{ left: `${pct(clock)}%` }} title={`SOC clock starts ${hhmm(clock)} UTC`}>
            <span className="absolute -top-0.5 left-1 whitespace-nowrap rounded-sm bg-slate-950 px-1 text-[10px] font-medium text-orbit-300">SOC clock</span>
          </div>
        )}
        {inc.timeline.map((t, i) => {
          const p = phaseOf(t.phase);
          const left = pct(pts[i].a), width = Math.max(0, pct(pts[i].b) - left);
          return (
            <button key={i} type="button" onClick={() => onPick(i)} aria-label={`${hhmm(pts[i].a)} UTC, ${t.label}`}
              title={`${hhmm(pts[i].a)} UTC  ${t.label}`}
              className="absolute bottom-2 top-5 z-20 -translate-x-1/2 rounded-sm outline-none transition-transform hover:scale-y-110 focus-visible:ring-2 focus-visible:ring-orbit-300"
              style={{ left: `${left + width / 2}%`, width: `max(5px, ${width}%)`, backgroundColor: p.hex, opacity: t.status === "SUSPECTED" ? 0.6 : 1 }} />
          );
        })}
      </div>
      <div className="relative mt-1 h-4 text-[11px] tabular-nums text-slate-500" aria-hidden="true">
        {ticks.map((ms, i) => (
          <span key={i} className={cn("absolute", i === 0 ? "" : i === ticks.length - 1 ? "-translate-x-full" : "-translate-x-1/2")} style={{ left: `${pct(ms)}%` }}>{hhmm(ms)}</span>
        ))}
      </div>
      <figcaption className="mt-1.5 flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-slate-500">
        <span>Times are UTC. Select a bar to jump to that event.</span>
        {gaps.length > 0 && <span className="inline-flex items-center gap-1.5"><span className="gap-hatch inline-block h-2.5 w-4 rounded-sm ring-1 ring-slate-700" />No logs from that source</span>}
      </figcaption>
    </figure>
  );
}

/* ----------------------------------------------------------- overview parts */
function Timeline({ inc, caseFile }: { inc: Incident; caseFile: CaseFile }) {
  const { local_tz_hours: h, local_tz_label: lab } = caseFile.company;
  const [flash, setFlash] = useState<number | null>(null);
  // IDS alerts are shown inside the phase they interrupt; only attack phases open a new group
  const heads = useMemo(() => {
    let last: string | null = null;
    return inc.timeline.map((t) => {
      if (t.phase === "Detection") return null;
      const l = phaseOf(t.phase).label;
      const show = l !== last;
      last = l;
      return show ? l : null;
    });
  }, [inc]);
  const pick = (i: number) => {
    document.getElementById(`tl-${i}`)?.scrollIntoView({ block: "center", behavior: "smooth" });
    setFlash(null);
    requestAnimationFrame(() => setFlash(i));
  };
  return (
    <section>
      <SectionTitle aside={<span className="text-xs text-slate-500">Local time ({lab}) in grey</span>}>Attack timeline</SectionTitle>
      <IncidentRibbon inc={inc} onPick={pick} />
      <ol className="space-y-0">
        {inc.timeline.map((t, i) => {
          const p = phaseOf(t.phase);
          const detection = t.phase === "Detection";
          return (
            <li key={i}>
              {heads[i] && (
                <div className="mb-1 mt-5 flex items-center gap-2 first:mt-0">
                  <span className={cn("h-2 w-2 rounded-full", p.tone)} />
                  <span className="text-sm font-semibold text-slate-100">{heads[i]}</span>
                  <span className="h-px flex-1 bg-slate-800" />
                </div>
              )}
              <div id={`tl-${i}`} onAnimationEnd={() => setFlash(null)}
                className={cn("grid grid-cols-[5.5rem_1fr] gap-x-4 rounded-sm py-1.5 pl-4", flash === i && "flash-entry")}>
                <div className="text-right text-xs leading-5 tabular-nums">
                  <p className="text-slate-200">{fmtUtc(t.ts_utc).replace(" UTC", "")}</p>
                  <p className="text-slate-600">{fmtLocal(t.ts_utc, h, lab).replace(` ${lab}`, "")}</p>
                </div>
                <div className="min-w-0">
                  <p className={cn("text-sm leading-5", detection ? "text-orbit-200" : "text-slate-100")}>
                    {t.label} {t.status === "SUSPECTED" && <Badge variant="suspected" className="ml-1">Suspected</Badge>} <Citations items={t.citations} />
                  </p>
                  {!detection && t.detail && <p className="mt-0.5 break-words font-mono text-[11px] leading-relaxed text-slate-500">{t.detail}</p>}
                </div>
              </div>
            </li>
          );
        })}
      </ol>
    </section>
  );
}

function Impacted({ inc }: { inc: Incident }) {
  const crit = (c?: string | null) => (c === "Critical" ? "p1" : c === "High" ? "p2" : c === "Medium" ? "p3" : "p4") as "p1" | "p2" | "p3" | "p4";
  return (
    <section className="grid gap-x-10 gap-y-8 md:grid-cols-2">
      <div>
        <SectionTitle>Impacted systems</SectionTitle>
        <ul className="divide-y divide-slate-800/80">
          {inc.affected_assets.map((a) => (
            <li key={a.hostname} className="flex gap-3 py-3 first:pt-0">
              <Server className="mt-0.5 h-4 w-4 shrink-0 text-slate-600" />
              <div className="min-w-0 flex-1">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-sm text-slate-100">{a.hostname}</span>
                  {a.criticality ? <Badge variant={crit(a.criticality)}>{a.criticality}</Badge> : <Badge variant="suspected">Not in inventory</Badge>}
                </div>
                <p className={cn("mt-1 text-xs", a.reached ? "text-rose-300" : "text-slate-500")}>
                  {a.reached ? "Accessed by the attacker" : a.reached === false ? "Contacted, no logon on the server" : "Targeted"}
                </p>
                <p className="mt-0.5 text-xs text-slate-500">{a.type}</p>
              </div>
              <Citations items={a.citations} />
            </li>
          ))}
          {inc.affected_assets.length === 0 && <li className="text-sm text-slate-500">No inventory system is tied to this incident.</li>}
        </ul>
      </div>
      <div>
        <SectionTitle>Impacted users</SectionTitle>
        <ul className="divide-y divide-slate-800/80">
          {inc.affected_accounts.map((u) => (
            <li key={u.username} className="flex gap-3 py-3 first:pt-0">
              <User className="mt-0.5 h-4 w-4 shrink-0 text-slate-600" />
              <div className="min-w-0 flex-1">
                <p className="text-sm text-slate-100">{u.full_name ?? u.username} <span className="font-mono text-xs text-slate-500">{u.username}</span></p>
                <p className="mt-0.5 text-xs text-slate-500">{u.role_in_company}</p>
                <p className="mt-1 text-xs text-slate-400">{u.roles[0]}</p>
              </div>
              <Citations items={u.citations} />
            </li>
          ))}
          {inc.attacker_ips.length > 0 && (
            <li className="flex gap-3 py-3">
              <CircleAlert className="mt-0.5 h-4 w-4 shrink-0 text-rose-400" />
              <div><p className="text-xs text-slate-400">Activity came from</p><p className="font-mono text-sm text-rose-200">{inc.attacker_ips.join(", ")}</p></div>
            </li>
          )}
          {inc.affected_accounts.length === 0 && inc.attacker_ips.length === 0 && <li className="text-sm text-slate-500">No user account is involved.</li>}
        </ul>
      </div>
    </section>
  );
}

/* ----------------------------------------------------------- actions & SLA */
function ActionPlan({ inc }: { inc: Incident }) {
  const [done, setDone] = useState<Record<string, boolean>>({});
  if (!inc.actions.length) {
    return <p className="max-w-[60ch] text-sm leading-relaxed text-slate-400">No approved runbook covers this type of incident. Escalate it for an analyst decision. No improvised actions are suggested.</p>;
  }
  const groups = new Map<string, Incident["actions"]>();
  inc.actions.forEach((a) => groups.set(a.runbook_id, [...(groups.get(a.runbook_id) ?? []), a]));
  const completed = Object.values(done).filter(Boolean).length;
  return (
    <section>
      <SectionTitle aside={<span className="text-xs text-slate-500">{completed} of {inc.actions.length} steps done</span>}>Runbook action plan</SectionTitle>
      <div className="space-y-7">
        {[...groups.entries()].map(([rb, steps]) => (
          <div key={rb}>
            <p className="font-serif text-lg text-slate-100">{RUNBOOK_NAME[rb] ?? rb} <span className="font-sans text-xs text-slate-500">{rb}</span></p>
            {steps[0].opened_because && <p className="mb-1 mt-0.5 text-xs text-slate-500">Opened because {steps[0].opened_because}.</p>}
            <ul className="divide-y divide-slate-800/80">
              {steps.map((a) => {
                const key = `${rb}-${a.step_no}`;
                const isDone = !!done[key];
                return (
                  <li key={key} className={cn("py-3 transition-opacity", isDone && "opacity-50")}>
                    <label className="flex cursor-pointer gap-3">
                      <input type="checkbox" checked={isDone} onChange={(e) => setDone((d) => ({ ...d, [key]: e.target.checked }))} className="mt-1 h-4 w-4 shrink-0 accent-orbit-500" />
                      <span className="min-w-0 flex-1">
                        <span className={cn("block text-sm leading-relaxed text-slate-100", isDone && "line-through")}><span className="font-medium text-orbit-300">Step {a.step_no}.</span> {a.text}</span>
                        {a.context && <span className="mt-1 block max-w-[72ch] text-xs leading-relaxed text-slate-500">{a.context}</span>}
                      </span>
                      <Citations items={[a.citation, ...a.context_citations]} />
                    </label>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </section>
  );
}

function fmtLeft(ms: number) {
  const s = Math.floor(Math.abs(ms) / 1000);
  const d = Math.floor(s / 86400), hh = Math.floor((s % 86400) / 3600), mm = Math.floor((s % 3600) / 60), ss = s % 60;
  const txt = d ? `${d}d ${hh}h` : hh ? `${hh}h ${String(mm).padStart(2, "0")}m` : `${String(mm).padStart(2, "0")}:${String(ss).padStart(2, "0")}`;
  return ms < 0 ? `Overdue ${txt}` : `${txt} left`;
}

function Escalation({ inc }: { inc: Incident }) {
  const [mode, setMode] = useState<"replay" | "live">("replay");
  const [t0] = useState(() => Date.now());
  const [tick, setTick] = useState(() => Date.now());
  const [triggered, setTriggered] = useState<string | null>(null);
  const reduced = usePrefersReducedMotion();
  useEffect(() => { const id = setInterval(() => setTick(Date.now()), 1000); return () => clearInterval(id); }, []);
  const base = inc.detection_time_utc ? new Date(inc.detection_time_utc).getTime() : t0;
  const now = mode === "replay" ? base + (tick - t0) : tick;

  if (!inc.contacts.length) {
    return <section><SectionTitle>Escalation and SLA</SectionTitle><p className="max-w-[60ch] text-sm leading-relaxed text-slate-400">This incident has no severity in the company matrix, so the escalation sheet does not name anyone. Escalate it for an analyst decision.</p></section>;
  }
  return (
    <section>
      <SectionTitle aside={
        <div className="flex overflow-hidden rounded-md border border-slate-800 text-xs">
          {(["replay", "live"] as const).map((m) => (
            <button key={m} type="button" onClick={() => setMode(m)} className={cn("px-2.5 py-1", mode === m ? "bg-slate-800 text-white" : "text-slate-500 hover:text-slate-300")}>
              {m === "replay" ? "Replay from detection" : "Real time"}
            </button>
          ))}
        </div>
      }>Escalation and SLA</SectionTitle>
      <p className="mb-4 flex flex-wrap items-center gap-1.5 text-xs text-slate-500"><Clock className="h-3.5 w-3.5" /> Deadlines count from {fmtUtc(inc.detection_time_utc, true)}, when the SOC first saw the incident. <Citations items={inc.detection_citations} /></p>
      <div className="grid gap-3 sm:grid-cols-2">
        {inc.contacts.map((c) => {
          const left = c.deadline_utc ? new Date(c.deadline_utc).getTime() - now : null;
          const urgent = left !== null && left < 5 * 60_000;
          return (
            <div key={c.role} className={cn("rounded-lg border bg-slate-950/50 p-4", urgent ? "border-rose-500/40" : "border-slate-800")}>
              <div className="flex items-start justify-between gap-2">
                <div>
                  <p className="text-xs text-slate-500">{c.role}</p>
                  <p className="mt-0.5 font-serif text-lg leading-tight text-slate-100">{c.name ?? "SOC queue"}</p>
                </div>
                <Citations items={c.citations} />
              </div>
              <p className="mt-2 flex items-center gap-1.5 font-mono text-xs text-slate-300"><Phone className="h-3 w-3 text-slate-500" />{c.contact ?? "Contact details not in the files"}</p>
              <div className="mt-3 flex items-end justify-between gap-2 border-t border-slate-800 pt-3">
                <div className="text-xs text-slate-500">{c.how.split(",")[0]} within <span className="text-slate-300">{c.time_limit}</span>{c.deadline_utc && <span className="block tabular-nums">by {fmtUtc(c.deadline_utc)}</span>}</div>
                {left !== null && <span className={cn("text-base font-semibold tabular-nums", left < 0 ? "text-rose-300" : urgent ? "text-amber-300" : "text-emerald-300")}>{fmtLeft(left)}</span>}
              </div>
              {c.note && <p className="mt-2 text-xs leading-relaxed text-slate-500">{c.note}</p>}
              {triggered && <p className="mt-2 flex items-center gap-1 text-xs text-emerald-300"><CheckCircle2 className="h-3 w-3" /> Escalation started</p>}
            </div>
          );
        })}
      </div>
      {inc.severity === "P1" && (
        <div className="mt-5 flex flex-wrap items-center gap-4">
          <MetalFx variant="button" preset="chromatic" theme="dark" strength={0.9} paused={reduced} disableGlow={reduced}>
            <button type="button" onClick={() => setTriggered(new Date().toISOString())}
              style={{ height: 42, padding: "0 20px", borderRadius: 999, display: "inline-flex", alignItems: "center", gap: 8, fontWeight: 600, fontSize: 13, color: "#fff" }}>
              <BellRing className="h-4 w-4" /> Trigger immediate incident escalation
            </button>
          </MetalFx>
          <span className="max-w-[46ch] text-xs leading-relaxed text-slate-500">{triggered ? `Escalation started at ${fmtUtc(triggered)}. Call each person above before their deadline.` : "Marks the escalation as started for this shift. It does not place calls or send email."}</span>
        </div>
      )}
    </section>
  );
}

/* ----------------------------------------------------------- noise */
export function SuppressedNoise({ items }: { items: Exclusion[] }) {
  return (
    <section>
      <SectionTitle aside={<Badge variant="confirmed">{items.length} suppressed, records kept</Badge>}>Suppressed maintenance noise</SectionTitle>
      <p className="mb-5 max-w-[64ch] text-sm leading-relaxed text-slate-400">
        These alerts matched an approved change on all five checks: approval, time window, systems, who did it, and type of work. They were closed without paging anyone. Nothing was deleted.
      </p>
      {items.length === 0 && <p className="text-sm text-slate-500">No activity matched an approved change.</p>}
      <ul className="divide-y divide-slate-800/80">
        {items.map((x) => (
          <li key={x.id} className="py-5 first:pt-0">
            <div className="flex flex-wrap items-start justify-between gap-2">
              <div>
                <p className="font-serif text-lg text-slate-100">{x.description}</p>
                <p className="mt-0.5 text-xs tabular-nums text-slate-500">Approved change {x.change_id}, window {fmtUtc(x.start_utc)} to {fmtUtc(x.end_utc)}</p>
              </div>
              <Badge variant="confirmed"><ShieldCheck className="h-3 w-3" /> Approved activity</Badge>
            </div>
            <p className="mt-2 text-sm text-slate-400">{x.title}</p>
            <div className="mt-3 flex flex-wrap gap-1.5">
              {x.criteria.map((c) => (
                <span key={c.name} title={c.detail} className={cn("inline-flex items-center gap-1 rounded-full border px-2 py-0.5 text-xs",
                  c.ok ? "border-emerald-500/30 text-emerald-200" : "border-rose-500/30 text-rose-200")}>
                  {c.ok ? <CheckCircle2 className="h-3 w-3" /> : <CircleAlert className="h-3 w-3" />}{c.label}
                </span>
              ))}
            </div>
            <p className="mt-3 flex flex-wrap items-center gap-x-2 gap-y-1 text-xs text-slate-500">
              Approved by the change calendar <Citations items={[x.change_citation]} /> Suppressed log lines <Citations items={[...x.events, ...x.alerts]} />
            </p>
          </li>
        ))}
      </ul>
    </section>
  );
}
