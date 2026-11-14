"use client";

import { createContext, useCallback, useContext, useEffect, useRef, useState, type ReactNode } from "react";
import { FileText, Hash, ShieldCheck, ShieldAlert, Loader2, Link2 } from "lucide-react";
import { api, fmtUtc, type Citation, type SourceContext } from "@/lib/api";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";
import { Badge, sevVariant } from "@/components/ui/badge";
import { cn } from "@/lib/utils";

type Ctx = { open: (c: Citation) => void; dataset: string };
const EvidenceCtx = createContext<Ctx>({ open: () => {}, dataset: "orbit" });
export const useEvidence = () => useContext(EvidenceCtx);

/** One clickable `file:locator` pill. */
export function CitationBadge({ c, compact = false }: { c: Citation; compact?: boolean }) {
  const { open } = useEvidence();
  const short = c.file.replace(/\.md$/, "").replace(/^(\d\d)_.*$/, "$1");
  return (
    <button
      type="button"
      onClick={(e) => { e.stopPropagation(); open(c); }}
      title={c.text ? `${c.file}:${c.locator}\n${c.text}` : `${c.file}:${c.locator}`}
      className="inline-flex items-center gap-1 rounded border border-orbit-500/30 bg-orbit-500/5 px-1 py-px align-middle font-mono text-[10px] leading-tight text-orbit-300 transition-colors hover:border-orbit-400 hover:bg-orbit-500/15 hover:text-orbit-100"
    >
      <Link2 className="h-2.5 w-2.5 opacity-70" />
      {compact ? `${short}:${c.locator}` : `${c.file}:${c.locator}`}
    </button>
  );
}

const pillLabel = (c: Citation) => `${c.file.replace(/\.md$/, "")}:${c.locator}`;

/**
 * Grouped citation pill: `[11_vpn_auth_log:L7 +3]`. The main part opens the
 * first (primary) source; `+3` opens a small list of the others. Log lines are
 * listed before reference rows, so the pill leads with direct evidence.
 * `max` is kept for call-site compatibility and ignored.
 */
export function Citations({ items }: { items: Citation[]; max?: number; compact?: boolean }) {
  const { open } = useEvidence();
  const [expanded, setExpanded] = useState(false);
  const ref = useRef<HTMLSpanElement>(null);
  const seen = new Set<string>();
  const uniq = items.filter((c) => { const k = `${c.file}:${c.locator}`; if (seen.has(k)) return false; seen.add(k); return true; });
  const ordered = [...uniq.filter((c) => /^L\d+$/.test(c.locator)), ...uniq.filter((c) => !/^L\d+$/.test(c.locator))];

  useEffect(() => {
    if (!expanded) return;
    const close = (e: MouseEvent) => { if (!ref.current?.contains(e.target as Node)) setExpanded(false); };
    const esc = (e: KeyboardEvent) => e.key === "Escape" && setExpanded(false);
    document.addEventListener("mousedown", close);
    document.addEventListener("keydown", esc);
    return () => { document.removeEventListener("mousedown", close); document.removeEventListener("keydown", esc); };
  }, [expanded]);

  if (!ordered.length) return null;
  const [first, ...rest] = ordered;
  return (
    <span ref={ref} className="relative inline-flex shrink-0 self-start align-middle">
      <span className="inline-flex items-stretch overflow-hidden rounded-md border border-orbit-500/30 bg-orbit-500/5 font-mono text-[10px] leading-none text-orbit-300">
        <button type="button" onClick={(e) => { e.stopPropagation(); open(first); }} title={first.text ? `${first.file}:${first.locator}\n${first.text}` : `${first.file}:${first.locator}`}
          className="inline-flex items-center gap-1 px-1.5 py-[3px] transition-colors hover:bg-orbit-500/15 hover:text-orbit-100">
          <Link2 className="h-2.5 w-2.5 opacity-70" />{pillLabel(first)}
        </button>
        {rest.length > 0 && (
          <button type="button" aria-expanded={expanded} aria-label={`${rest.length} more sources`} onClick={(e) => { e.stopPropagation(); setExpanded((x) => !x); }}
            className="border-l border-orbit-500/20 px-1.5 py-[3px] text-orbit-400/80 transition-colors hover:bg-orbit-500/15 hover:text-orbit-100">
            +{rest.length}
          </button>
        )}
      </span>
      {expanded && (
        <span className="absolute left-0 top-full z-30 mt-1 flex max-h-64 w-max max-w-[22rem] flex-col overflow-y-auto rounded-md border border-slate-700 bg-slate-900 p-1 shadow-xl">
          {ordered.map((c) => (
            <button key={`${c.file}:${c.locator}`} type="button" onClick={(e) => { e.stopPropagation(); setExpanded(false); open(c); }}
              className="rounded px-2 py-1 text-left hover:bg-slate-800">
              <span className="block font-mono text-[10px] text-orbit-300">{pillLabel(c)}</span>
              {c.text && <span className="block truncate text-[10px] text-slate-500">{c.text}</span>}
            </button>
          ))}
        </span>
      )}
    </span>
  );
}

export function EvidenceProvider({ dataset, children }: { dataset: string; children: ReactNode }) {
  const [cite, setCite] = useState<Citation | null>(null);
  const [data, setData] = useState<SourceContext | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);
  const targetRef = useRef<HTMLDivElement>(null);

  const open = useCallback((c: Citation) => setCite(c), []);

  useEffect(() => {
    if (!cite) return;
    let live = true;
    setLoading(true);
    setErr(null);
    api.context(cite.file, cite.locator, dataset, 8)
      .then((d) => { if (live) setData(d); })
      .catch((e) => { if (live) { setErr(String(e.message ?? e)); setData(null); } })
      .finally(() => live && setLoading(false));
    return () => { live = false; };
  }, [cite, dataset]);

  useEffect(() => {
    if (data) requestAnimationFrame(() => targetRef.current?.scrollIntoView({ block: "center", behavior: "smooth" }));
  }, [data]);

  const p = data?.parser;
  return (
    <EvidenceCtx.Provider value={{ open, dataset }}>
      {children}
      <Sheet open={!!cite} onOpenChange={(o) => !o && setCite(null)}>
        <SheetContent>
          <div className="border-b border-slate-800 px-5 py-4 pr-12">
            <SheetTitle className="text-[11px] font-semibold text-slate-500">Evidence inspector</SheetTitle>
            <SheetDescription className="mt-1.5 flex flex-wrap items-center gap-2 font-mono text-sm text-slate-100">
              <FileText className="h-4 w-4 text-orbit-400" />
              <span>{cite?.file}</span>
              <span className="text-slate-500">|</span>
              <span className="text-orbit-300">{data ? (data.kind === "log" ? `Line ${data.target_line}` : data.locator) : cite?.locator}</span>
              {data && (
                data.integrity === "VERIFIED"
                  ? <Badge variant="confirmed"><ShieldCheck className="h-3 w-3" /> SHA-256 verified</Badge>
                  : <Badge variant="p1"><ShieldAlert className="h-3 w-3" /> changed since ingest</Badge>
              )}
            </SheetDescription>
            {data && <p className="mt-1 text-xs text-slate-500">{data.title}</p>}
          </div>

          <div className="flex-1 overflow-y-auto">
            {loading && <div className="flex items-center gap-2 p-6 text-sm text-slate-400"><Loader2 className="h-4 w-4 animate-spin" /> Fetching source...</div>}
            {err && <div className="m-5 rounded-md border border-rose-500/40 bg-rose-500/10 p-3 text-sm text-rose-200">Could not load the cited line: {err}</div>}
            {data && !loading && (
              <>
                <div className="border-b border-slate-800 bg-black/40 py-2 font-mono text-[12px] leading-relaxed">
                  {data.lines.map((l) => (
                    <div
                      key={l.label}
                      ref={l.is_target ? targetRef : undefined}
                      className={cn(
                        "grid grid-cols-[3.5rem_1fr] gap-3 px-3",
                        l.is_target ? "evidence-target relative border-l-2 border-orbit-400 bg-orbit-500/10 text-orbit-50" : "border-l-2 border-transparent text-slate-400",
                      )}
                    >
                      <span className={cn("select-none text-right tabular-nums", l.is_target ? "text-orbit-300" : "text-slate-600")}>
                        {l.is_target ? "▸" : ""}{data.kind === "log" ? l.line : l.label}
                      </span>
                      <span className="whitespace-pre-wrap break-words py-px">{l.text || " "}</span>
                    </div>
                  ))}
                </div>

                <div className="space-y-4 p-5 text-sm">
                  {p && (
                    <section>
                      <h4 className="mb-2 text-[11px] font-semibold text-slate-500">Parser metadata</h4>
                      {p.parse_status === "quarantined" && (
                        <div className="mb-2 rounded border border-amber-500/40 bg-amber-500/10 p-2 text-xs text-amber-100">Quarantined: {p.quarantine_reason}. Kept and cited, never dropped.</div>
                      )}
                      {p.flags?.includes("PROMPT_INJECTION") && (
                        <div className="mb-2 rounded border border-rose-500/40 bg-rose-500/10 p-2 text-xs text-rose-100">Prompt-injection signature detected. This text is never passed to the language model.</div>
                      )}
                      <dl className="grid grid-cols-[9rem_1fr] gap-x-3 gap-y-1 font-mono text-xs">
                        <Meta k="Normalised UTC" v={p.ts_utc ? fmtUtc(p.ts_utc, true) : null} />
                        {p.ts_start_utc && p.ts_start_utc !== p.ts_utc && <Meta k="Session start (UTC)" v={fmtUtc(p.ts_start_utc, true)} />}
                        <Meta k="Original timestamp" v={p.ts_original} />
                        <Meta k="Time-zone source" v={p.tz_source + (p.tz_assumed ? "  (ASSUMED)" : "")} />
                        <Meta k="Source type" v={p.source_type} />
                        <Meta k="Action / outcome" v={`${p.action} / ${p.outcome}`} />
                        <Meta k="User" v={p.user} />
                        <Meta k="Source IP" v={p.ip_source} />
                        <Meta k="Destination IP" v={p.ip_dest} />
                        <Meta k="Host" v={p.host} />
                        {Object.entries(p.fields).filter(([k]) => !["description", "_fallback", "user", "src_ip", "dst_ip", "result", "host", "account", "client"].includes(k)).slice(0, 10).map(([k, v]) => (
                          <Meta key={k} k={k} v={typeof v === "object" ? JSON.stringify(v) : String(v)} />
                        ))}
                      </dl>
                    </section>
                  )}
                  {data.used_in.length > 0 && (
                    <section>
                      <h4 className="mb-2 text-[11px] font-semibold text-slate-500">Cited by</h4>
                      <div className="flex flex-wrap gap-1.5">
                        {data.used_in.map((u, i) => u.incident_id
                          ? <Badge key={i} variant={sevVariant(u.severity)}>{u.incident_id}, {u.claims} claim{u.claims === 1 ? "" : "s"}</Badge>
                          : <Badge key={i} variant="confirmed">Suppressed maintenance {u.closed_as_harmless}</Badge>)}
                      </div>
                    </section>
                  )}
                  <section className="rounded-md border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
                    <div className="flex items-start gap-2"><Hash className="mt-0.5 h-3.5 w-3.5 shrink-0" /><span className="break-all font-mono">{data.file_sha256}</span></div>
                    <p className="mt-2">{data.line_convention}</p>
                  </section>
                </div>
              </>
            )}
          </div>
        </SheetContent>
      </Sheet>
    </EvidenceCtx.Provider>
  );
}

function Meta({ k, v }: { k: string; v?: string | null }) {
  if (v === null || v === undefined || v === "") return null;
  return (<><dt className="text-slate-500">{k}</dt><dd className="break-all text-slate-200">{v}</dd></>);
}
