export const API_URL = (process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000").replace(/\/$/, "");

export type Tier = "CONFIRMED" | "SUSPECTED" | "INSUFFICIENT_EVIDENCE";
export const TIER_LABEL: Record<Tier, string> = {
  CONFIRMED: "Confirmed",
  SUSPECTED: "Suspected",
  INSUFFICIENT_EVIDENCE: "Not enough evidence",
};

export interface Citation { file: string; locator: string; text?: string }
export interface Claim { claim_id: string; text: string; status: Tier; rule?: string | null; citations: Citation[]; entities: string[]; topic: string }
export interface TimelineEntry { ts_utc: string; ts_end_utc?: string | null; label: string; detail: string; phase: string; status: Tier; citations: Citation[] }
export interface SeverityPart { part: string; matrix_row?: string | null; driving_asset?: string | null; criticality?: string | null; result?: string | null; steps: string[]; citations: Citation[]; note?: string | null }
export interface RunbookAction { runbook_id: string; step_no: number; text: string; citation: Citation; context?: string | null; context_citations: Citation[]; status: string; opened_because?: string | null; opened_citations: Citation[] }
export interface Contact { severity: string; role: string; name?: string | null; contact?: string | null; time_limit: string; time_limit_minutes?: number | null; how: string; deadline_utc?: string | null; deadline_alt_utc?: string | null; citations: Citation[]; condition?: string | null; condition_met?: boolean | null; note?: string | null }
export interface AssetRef { hostname: string; tag?: string | null; type?: string | null; criticality?: string | null; owner?: string | null; in_inventory: boolean; roles: string[]; reached: boolean | null; basis: string[]; citations: Citation[] }
export interface AccountRef { username: string; full_name?: string | null; role_in_company?: string | null; in_directory: boolean; roles: string[]; citations: Citation[] }

export interface Incident {
  incident_id: string; title: string; incident_type: string; severity: "P1" | "P2" | "P3" | "P4" | null; confidence: string; status: string;
  summary: { text: string; claim_ids: string[] }[]; summary_source: string; kill_chain: string[];
  highest_criticality_asset?: string | null; detection_time_utc?: string | null; detection_basis: string; detection_citations: Citation[];
  severity_reached_utc?: string | null; severity_reached_basis: string; severity_parts: SeverityPart[]; severity_steps: string[];
  timeline: TimelineEntry[]; claims: Claim[]; affected_assets: AssetRef[]; affected_accounts: AccountRef[]; attacker_ips: string[];
  gaps: { kind: string; source: string; start_utc: string; end_utc: string; reason: string; citation: Citation }[];
  actions: RunbookAction[]; contacts: Contact[]; flags: string[]; heuristics: string[];
}

export interface Exclusion {
  id: string; change_id: string; change_citation: Citation; title: string; description: string; events: Citation[]; alerts: Citation[]; context: Citation[];
  criteria: { name: string; label: string; ok: boolean; passed: number; total: number; detail: string }[]; reason: string; rule_citations: Citation[]; start_utc: string; end_utc: string;
}

export interface Report { markdown: string; verifier_passed: boolean; summary_source: string; report_sha256: string;
  verifier: { passed: boolean; lines_checked: number; citations_checked: number; errors: string[]; warnings: string[]; downgrades: string[]; checks: string[];
    llm?: { used: boolean; fell_back_to_template: boolean; reason?: string; attempts?: { attempt: number; provider?: string; model?: string; verifier?: { passed: boolean; errors: string[] } }[] } } }

export interface StageEvent { stage: number; name: string; status: "running" | "done" | "complete" | "error"; ms?: number; detail?: string; stats?: Record<string, unknown> }

export interface CaseFile {
  dataset: string; generated_at: string; line_convention: string;
  company: { local_tz_label: string; local_tz_hours: number; log_date: string };
  files: { filename: string; title: string; file_type: string; source_type: string; total_lines: number; sha256: string }[];
  parsing_audit: { total_lines: number; parsed: number; quarantined: { ref: string; reason: string; raw: string }[]; duplicates: string[]; injection_hits: { ref: string; signatures: string[]; source_type: string }[];
    files: { file: string; format: string; lines: number; parsed: number; tz_policy: string; tz_assumed: boolean }[] };
  time_normalization: { sources: { file: string; policy: string; logged_at?: string | null; tz_assumed: boolean; citation?: Citation | null; example?: { ref: string; original: string; utc: string; source: string } | null }[];
    clock_skew: { verdict: string; summary: { pair: string; samples: number; min_s: number; max_s: number; flagged: boolean }[] } };
  entity_graph: { stats: { nodes: number; edges: number }; vpn_sessions: { session: string; user: string; src_ip: string; geo: string; assigned_ip: string; start: string; end?: string | null }[];
    dhcp_leases: { ip: string; hostname: string; start: string; end?: string | null; citation: Citation }[] };
  incidents: Incident[]; exclusions: Exclusion[];
  alert_dispositions: { alert_id: string; ref: string; ts: string; description: string; disposition: string; trigger_events: string[] }[];
  coverage: { gaps: { source: string; start_utc: string; end_utc: string; kind: string; reason: string; citation: Citation }[]; missing_sources: { text: string; citation: Citation }[] };
  reports: Record<string, Report>;
  integrity: { algorithm: string; raw_files_sha256: string; parsed_events_sha256: string; case_file_sha256: string; evidence_integrity_digest: string };
  llm: Health["llm"]; pipeline_trace: StageEvent[];
  stats: { files: number; events: number; incidents: number; exclusions: number; alerts: number; total_ms: number; claims: Record<Tier, number> };
}

export interface Health { status: string; llm: { mode: string; available: boolean; provider: string; model?: string | null; local: boolean; pseudonymize: boolean; note?: string | null; ollama_models: string[] };
  engines: Record<"local" | "cloud", { available: boolean; provider: string; model?: string | null; note?: string | null }>;
  supabase: { configured: boolean }; datasets: Record<string, boolean> }

export interface SourceContext {
  file: string; title: string; file_type: string; locator: string; target_line: number; kind: string; total_lines: number;
  lines: { line: number; label: string; text: string; is_target: boolean }[]; file_sha256: string; integrity: string;
  parser?: { parse_status: string; quarantine_reason?: string | null; ts_utc?: string | null; ts_start_utc?: string | null; ts_end_utc?: string | null; ts_original: string; tz_source: string; tz_assumed: boolean;
    source_type: string; action: string; outcome: string; user?: string | null; ip_source?: string | null; ip_dest?: string | null; host?: string | null; flags: string[]; fields: Record<string, unknown> } | null;
  used_in: { incident_id?: string; severity?: string; claims?: number; closed_as_harmless?: string }[]; line_convention: string;
}

export interface AskAnswer { question: string; source: string; injection_signatures: string[];
  sentences: { text: string; tier: Tier; citations: Citation[] }[]; facts: { id: string; kind: string; tier: Tier; text: string; citations: Citation[] }[] }

async function j<T>(path: string, init?: RequestInit): Promise<T> {
  const r = await fetch(`${API_URL}${path}`, { cache: "no-store", ...init });
  if (!r.ok) {
    let detail = `${r.status} ${r.statusText}`;
    try { detail = (await r.json()).detail ?? detail; } catch { /* keep status text */ }
    throw new Error(detail);
  }
  return r.json() as Promise<T>;
}

export const api = {
  health: () => j<Health>("/api/health"),
  case: (dataset: string) => j<CaseFile>(`/api/case?dataset=${dataset}`),
  context: (file: string, locator: string, dataset: string, radius = 6) =>
    j<SourceContext>(`/api/source-context?file=${encodeURIComponent(file)}&locator=${encodeURIComponent(locator)}&radius=${radius}&dataset=${dataset}`),
  ask: (question: string, dataset: string, engine: string, verify: boolean, llm = true) =>
    j<AskAnswer>("/api/ask", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ question, dataset, llm, engine, verify }) }),
  streamUrl: (dataset: string, llm: string, paceMs: number, verify: boolean) =>
    `${API_URL}/api/triage/stream?dataset=${dataset}&llm=${llm}&pace_ms=${paceMs}&verify=${verify}`,
  reportUrl: (id: string, dataset: string) => `${API_URL}/api/incidents/${id}/report.md?dataset=${dataset}`,
};

export const fmtUtc = (iso?: string | null, withDate = false) => {
  if (!iso) return "-";
  const d = new Date(iso);
  const s = d.toISOString();
  return (withDate ? s.slice(0, 10) + " " : "") + s.slice(11, 19) + " UTC";
};
export const fmtLocal = (iso: string | null | undefined, hours: number, label: string) => {
  if (!iso) return "";
  const d = new Date(new Date(iso).getTime() + hours * 3600_000);
  return d.toISOString().slice(11, 19) + " " + label;
};
