"use client";

import { useMemo, useState } from "react";
import ReactMarkdown from "react-markdown";
import remarkGfm from "remark-gfm";
import { Download, Fingerprint } from "lucide-react";
import { api, type CaseFile, type Incident } from "@/lib/api";
import { Sheet, SheetContent, SheetDescription, SheetTitle } from "@/components/ui/sheet";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Button } from "@/components/ui/button";
import { useEvidence } from "@/components/evidence";
import { AuditPanel } from "@/components/audit";
import { StageTrace } from "@/components/pipeline";

export function AuditSheet({ open, onOpenChange, caseFile, incident }: { open: boolean; onOpenChange: (o: boolean) => void; caseFile: CaseFile; incident: Incident | null }) {
  return (
    <Sheet open={open} onOpenChange={onOpenChange}>
      <SheetContent className="sm:max-w-4xl">
        <div className="border-b border-slate-800 px-6 py-4 pr-12">
          <SheetTitle className="text-base font-semibold text-white">Audit Logs</SheetTitle>
          <SheetDescription className="mt-0.5 text-xs text-slate-500">Full incident report, data-quality checks and processing record for this triage run.</SheetDescription>
        </div>
        <div className="flex-1 overflow-y-auto px-6 pb-6">
          <Tabs defaultValue="report">
            <TabsList>
              <TabsTrigger value="report">Incident report</TabsTrigger>
              <TabsTrigger value="quality">Data quality</TabsTrigger>
              <TabsTrigger value="steps">Processing steps</TabsTrigger>
            </TabsList>
            <TabsContent value="report">{incident ? <ReportView caseFile={caseFile} inc={incident} /> : <p className="text-sm text-slate-500">Select an incident.</p>}</TabsContent>
            <TabsContent value="quality"><AuditPanel c={caseFile} /></TabsContent>
            <TabsContent value="steps" className="space-y-4">
              <StageTrace stages={Object.fromEntries(caseFile.pipeline_trace.map((s) => [s.stage, s]))} />
              <div className="rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
                <p className="flex items-center gap-1.5 text-slate-300"><Fingerprint className="h-3.5 w-3.5 text-emerald-400" /> Evidence integrity ({caseFile.integrity.algorithm})</p>
                <p className="mt-1 break-all font-mono text-slate-200">{caseFile.integrity.evidence_integrity_digest}</p>
                <p className="mt-2">Raw files {caseFile.integrity.raw_files_sha256} and parsed events {caseFile.integrity.parsed_events_sha256} and case file {caseFile.integrity.case_file_sha256}</p>
              </div>
            </TabsContent>
          </Tabs>
        </div>
      </SheetContent>
    </Sheet>
  );
}

function ReportView({ caseFile, inc }: { caseFile: CaseFile; inc: Incident }) {
  const { open } = useEvidence();
  const report = caseFile.reports[inc.incident_id];
  const [showAttempts, setShowAttempts] = useState(false);
  const md = useMemo(() => report.markdown.replace(/\[([A-Za-z0-9_.\-]+\.md):([A-Za-z0-9_.\-]+)\]/g, (_m, f, l) => `[${f.replace(/\.md$/, "")}:${l}](#cite:${f}:${l})`), [report.markdown]);
  const v = report.verifier;
  const attempts = v.llm?.attempts ?? [];
  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center gap-3 rounded-lg border border-slate-800 bg-slate-900/60 p-3 text-xs text-slate-400">
        <span className={v.passed ? "text-emerald-300" : "text-rose-300"}>{v.passed ? "Fact-check passed" : "Fact-check failed"}</span>
        <span>{v.lines_checked} statements, {v.citations_checked} source references checked, {v.downgrades.length} wording corrections</span>
        {attempts.length > 0 && <button type="button" onClick={() => setShowAttempts((s) => !s)} className="text-orbit-400 hover:text-orbit-300">{showAttempts ? "Hide" : "Show"} AI drafts ({attempts.length})</button>}
        <Button variant="outline" size="sm" asChild className="ml-auto"><a href={api.reportUrl(inc.incident_id, caseFile.dataset)} target="_blank" rel="noreferrer"><Download className="h-3.5 w-3.5" /> Download report</a></Button>
        {showAttempts && (
          <ul className="w-full space-y-1 font-mono text-[11px] text-slate-500">
            {attempts.map((a) => <li key={a.attempt}>Draft {a.attempt}: {a.verifier ? (a.verifier.passed ? "accepted" : `rejected - ${a.verifier.errors.slice(0, 2).join("; ")}`) : "no response from the model"}</li>)}
            {v.llm?.fell_back_to_template && <li className="text-amber-200/80">The standard written summary was used instead.</li>}
          </ul>
        )}
      </div>
      <article className="report-md text-sm">
        <ReactMarkdown remarkPlugins={[remarkGfm]} components={{
          a: ({ href, children }) => {
            if (href?.startsWith("#cite:")) {
              const [, file, loc] = href.match(/^#cite:(.+):([^:]+)$/) ?? [];
              return <button type="button" onClick={() => open({ file, locator: loc })} className="mx-0.5 rounded border border-orbit-500/30 bg-orbit-500/5 px-1 font-mono text-[10px] text-orbit-300 hover:bg-orbit-500/15">{children}</button>;
            }
            return <a href={href} className="text-orbit-300 underline">{children}</a>;
          },
        }}>{md}</ReactMarkdown>
      </article>
    </div>
  );
}
