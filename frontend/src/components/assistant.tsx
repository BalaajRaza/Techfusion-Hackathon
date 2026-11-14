"use client";

import { useEffect, useRef, useState } from "react";
import { ArrowUp, ShieldAlert } from "lucide-react";
import { api, type AskAnswer, type Tier } from "@/lib/api";
import type { Settings } from "@/lib/settings";
import { Citations } from "@/components/evidence";
import { BorderBeam, BotAvatar, usePrefersReducedMotion } from "@/components/effects";
import { cn } from "@/lib/utils";

const QUICK = ["Who clicked the phishing link?", "What data was transferred?", "Who do we notify for P1?", "Why was the RDP session suppressed?", "Which logs are missing?"];

const TIER_STYLE: Record<Tier, { dot: string; label: string }> = {
  CONFIRMED: { dot: "bg-emerald-400", label: "Confirmed" },
  SUSPECTED: { dot: "bg-amber-400", label: "Suspected" },
  INSUFFICIENT_EVIDENCE: { dot: "bg-slate-500", label: "Not in the logs" },
};

type Turn = { id: number; question: string; answer?: AskAnswer; error?: string };

/** Strip the internal record prefixes so answers read as plain sentences. */
function tidy(text: string) {
  return text
    .replace(/^People to inform for INC-\d+-\d+ \(severity (P\d)\): /, "$1 escalation: ")
    .replace(/^Recommended action for INC-\d+-\d+: /, "")
    .replace(/^Affected asset in INC-\d+-\d+: /, "Affected system: ")
    .replace(/^Log line [^ ]+ at /, "Log entry at ")
    .replace(/ \((Guess \/ rule|Basis): /, " — $1: ")
    .replace(/\bINC-(\d{8})-(\d{2})\b/g, "incident $2");
}

export function Assistant({ settings, ready }: { settings: Settings; ready: boolean }) {
  const [q, setQ] = useState("");
  const [busy, setBusy] = useState(false);
  const [turns, setTurns] = useState<Turn[]>([]);
  const reduced = usePrefersReducedMotion();
  const endRef = useRef<HTMLDivElement>(null);
  const nextId = useRef(1);

  useEffect(() => { endRef.current?.scrollIntoView({ behavior: reduced ? "auto" : "smooth", block: "end" }); }, [turns, busy, reduced]);

  async function ask(question: string) {
    const text = question.trim();
    if (!text || busy || !ready) return;
    const id = nextId.current++;
    setTurns((t) => [...t, { id, question: text }]);
    setQ("");
    setBusy(true);
    try {
      const a = await api.ask(text, settings.dataset, settings.engine, settings.verifier);
      setTurns((t) => t.map((x) => (x.id === id ? { ...x, answer: a } : x)));
    } catch (e) {
      setTurns((t) => t.map((x) => (x.id === id ? { ...x, error: String((e as Error).message ?? e) } : x)));
    } finally {
      setBusy(false);
    }
  }

  return (
    <section aria-label="Orbit SOC Copilot" className="flex h-full min-h-[560px] flex-col overflow-hidden rounded-xl border border-slate-800 bg-slate-900/60">
      <header className="flex items-center gap-3 border-b border-slate-800 px-4 py-3">
        <BotAvatar type="mech" state={busy ? "working" : "default"} size={32} aria-hidden="true" />
        <div>
          <h2 className="text-sm font-semibold text-white">Orbit SOC Copilot</h2>
          <p className="text-[11px] text-slate-500">Grounded in verified telemetry, zero hallucinations</p>
        </div>
      </header>

      <div className="flex-1 space-y-4 overflow-y-auto px-4 py-4">
        {turns.length === 0 && (
          <div className="rounded-xl border border-dashed border-slate-800 p-4 text-sm text-slate-400">
            Ask anything about today&apos;s incidents. Every answer comes from the verified case file and links to the exact log lines behind it.
            {!ready && <span className="mt-2 block text-xs text-slate-500">Available once triage has run.</span>}
          </div>
        )}
        {turns.map((t) => (
          <div key={t.id} className="space-y-3">
            <div className="flex justify-end">
              <p className="max-w-[85%] rounded-2xl rounded-br-md bg-orbit-600/90 px-3.5 py-2 text-sm text-white">{t.question}</p>
            </div>
            <div className="flex items-start gap-2">
              <div className="max-w-[92%] rounded-2xl rounded-bl-md border border-slate-800 bg-slate-950/70 px-3.5 py-3">
                {!t.answer && !t.error && <p role="status" className="text-sm text-slate-500">Searching verified evidence...</p>}
                {t.error && <p className="text-sm text-rose-300">Could not answer: {t.error}</p>}
                {t.answer && <AnswerBody a={t.answer} />}
              </div>
            </div>
          </div>
        ))}
        <div ref={endRef} />
      </div>

      <div className="space-y-2.5 border-t border-slate-800 p-3">
        <div className="flex flex-wrap gap-1.5">
          {QUICK.map((p) => (
            <button key={p} type="button" onClick={() => ask(p)} disabled={busy || !ready}
              className="rounded-full border border-slate-800 bg-slate-950/60 px-2.5 py-1 text-[11px] text-slate-400 transition-colors hover:border-slate-600 hover:text-slate-100 disabled:opacity-40">
              {p}
            </button>
          ))}
        </div>
        <form onSubmit={(e) => { e.preventDefault(); ask(q); }}>
          <BorderBeam size="line" colorVariant="ocean" theme="dark" active={busy && !reduced} className="rounded-xl">
            <div className="flex items-center gap-2 rounded-xl border border-slate-700 bg-slate-950 py-1.5 pl-3.5 pr-1.5">
              <input value={q} onChange={(e) => setQ(e.target.value)} maxLength={600} aria-busy={busy} disabled={!ready}
                placeholder={ready ? "Ask the Copilot about this triage..." : "Run triage to start the conversation"}
                className="h-8 flex-1 bg-transparent text-sm text-slate-100 placeholder:text-slate-600 focus:outline-none disabled:cursor-not-allowed" />
              <button type="submit" disabled={busy || !q.trim() || !ready} aria-label="Send"
                className="grid h-8 w-8 place-items-center rounded-lg bg-orbit-600 text-white transition-colors hover:bg-orbit-500 disabled:bg-slate-800 disabled:text-slate-500">
                <ArrowUp className="h-4 w-4" />
              </button>
            </div>
          </BorderBeam>
        </form>
      </div>
    </section>
  );
}

function AnswerBody({ a }: { a: AskAnswer }) {
  const [more, setMore] = useState(false);
  const shown = more ? a.sentences : a.sentences.slice(0, 3);
  return (
    <div className="space-y-2.5">
      {a.injection_signatures.length > 0 && (
        <p className="flex items-center gap-1.5 text-[11px] text-amber-300"><ShieldAlert className="h-3 w-3" /> Your question contained instruction-like text. I answered from the evidence only.</p>
      )}
      {shown.map((s, i) => {
        const st = TIER_STYLE[s.tier];
        return (
          <div key={i} className="text-sm leading-relaxed text-slate-200">
            <span className="mb-0.5 flex items-center gap-1.5 text-[10px] font-medium text-slate-500">
              <span className={cn("h-1.5 w-1.5 rounded-full", st.dot)} />{st.label}
            </span>
            {tidy(s.text)} <Citations items={s.citations} />
          </div>
        );
      })}
      {a.sentences.length > 3 && (
        <button type="button" onClick={() => setMore((m) => !m)} className="text-xs text-orbit-400 hover:text-orbit-300">
          {more ? "Show less" : `Show ${a.sentences.length - 3} more related findings`}
        </button>
      )}
    </div>
  );
}
