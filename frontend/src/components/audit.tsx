"use client";

import { fmtUtc, type CaseFile } from "@/lib/api";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { CitationBadge, Citations } from "@/components/evidence";

export function AuditPanel({ c }: { c: CaseFile }) {
  const pa = c.parsing_audit;
  return (
    <div className="grid gap-4 lg:grid-cols-2">
      <Card>
        <CardHeader><CardTitle>Parsing audit</CardTitle><Badge variant={pa.quarantined.length ? "suspected" : "confirmed"}>{pa.parsed}/{pa.total_lines} parsed, {pa.quarantined.length} quarantined</Badge></CardHeader>
        <CardContent className="space-y-3 text-xs">
          <table className="w-full">
            <thead className="text-left text-[10px] text-slate-500"><tr><th className="py-1">File</th><th>Format</th><th>Lines</th><th>Time zone</th></tr></thead>
            <tbody>
              {pa.files.map((f) => (
                <tr key={f.file} className="border-t border-slate-800/60">
                  <td className="py-1 font-mono text-slate-300">{f.file}</td><td className="text-slate-400">{f.format}</td>
                  <td className="font-mono text-slate-400">{f.parsed}/{f.lines}</td>
                  <td className={f.tz_assumed ? "text-amber-300" : "text-slate-400"}>{f.tz_policy}{f.tz_assumed ? " (assumed)" : ""}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {pa.quarantined.map((q) => (
            <div key={q.ref} className="rounded border border-amber-500/30 bg-amber-500/5 p-2">
              <CitationBadge c={{ file: q.ref.split(":")[0], locator: q.ref.split(":")[1] }} /> <span className="text-amber-100">{q.reason}</span>
              <pre className="mt-1 overflow-x-auto font-mono text-[11px] text-slate-400">{q.raw}</pre>
            </div>
          ))}
          {pa.injection_hits.map((h) => (
            <div key={h.ref} className="rounded border border-rose-500/30 bg-rose-500/5 p-2 text-rose-100">
              Prompt injection: <CitationBadge c={{ file: h.ref.split(":")[0], locator: h.ref.split(":")[1] }} /> {h.signatures.join(", ")} - quarantined from the model, reported as a finding.
            </div>
          ))}
          {pa.duplicates.length > 0 && <p className="text-slate-500">Duplicate lines kept and citable, ignored by detectors: {pa.duplicates.join(", ")}</p>}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle>Time normalisation & coverage</CardTitle></CardHeader>
        <CardContent className="space-y-3 text-xs">
          <p className="text-slate-300">{c.time_normalization.clock_skew.verdict}</p>
          <ul className="space-y-1">
            {c.time_normalization.sources.map((s) => (
              <li key={s.file} className="flex flex-wrap items-center gap-2">
                <span className="font-mono text-slate-300">{s.file}</span>
                <span className="text-slate-500">{s.policy}{s.logged_at ? `, logged at ${s.logged_at}` : ""}</span>
                {s.example && <span className="font-mono text-slate-600">{s.example.original} → {fmtUtc(s.example.utc)}</span>}
                {s.citation && <CitationBadge c={s.citation} compact />}
              </li>
            ))}
          </ul>
          <div>
            <p className="mb-1 text-[10px] text-slate-500">Log gaps</p>
            {c.coverage.gaps.map((g, i) => (
              <p key={i} className="text-slate-400">No {g.source.toLowerCase()} logs {fmtUtc(g.start_utc, true)} → {fmtUtc(g.end_utc, true)} <CitationBadge c={g.citation} compact /></p>
            ))}
          </div>
          <div>
            <p className="mb-1 text-[10px] text-slate-500">Not collected</p>
            {c.coverage.missing_sources.map((m) => <p key={m.citation.locator} className="text-slate-400">{m.text} <CitationBadge c={m.citation} compact /></p>)}
          </div>
        </CardContent>
      </Card>

      <Card className="lg:col-span-2">
        <CardHeader><CardTitle>IDS alert dispositions</CardTitle></CardHeader>
        <CardContent className="overflow-x-auto">
          <table className="w-full min-w-[640px] text-left text-xs">
            <tbody>
              {c.alert_dispositions.map((a) => (
                <tr key={a.ref} className="border-b border-slate-800/60 last:border-0">
                  <td className="py-1.5 pr-2"><CitationBadge c={{ file: a.ref.split(":")[0], locator: a.ref.split(":")[1] }} compact /></td>
                  <td className="pr-2 font-mono text-slate-400">{fmtUtc(a.ts)}</td>
                  <td className="pr-2 text-slate-300">{a.description}</td>
                  <td className="pr-2"><Badge variant={a.disposition === "INCIDENT" ? "p2" : a.disposition.startsWith("CLOSED") ? "confirmed" : "suspected"}>{a.disposition.replace("CLOSED_AS_HARMLESS:", "suppressed: ")}</Badge></td>
                  <td><Citations items={a.trigger_events.map((r) => ({ file: r.split(":")[0], locator: r.split(":")[1] }))} max={3} /></td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardContent>
      </Card>
    </div>
  );
}
