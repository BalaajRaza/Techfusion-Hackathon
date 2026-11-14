"""The 11-stage pipeline. Stages 1-10 are deterministic code that produces the
case file; the language model appears only inside stage 11 and its output is
discarded unless the code verifier accepts it.
"""
from __future__ import annotations

import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable, Optional

from .. import config
from ..llm.gateway import LLMGateway
from ..llm.prose import write_prose
from ..models import SEV_RANK, Citation, Event, Incident
from ..security import integrity
from . import parsers, timeutil as tu
from .assemble import Builder
from .detectors import Ctx, run_detectors
from .entities import EntityGraph
from .ingest import LINE_CONVENTION, load_dataset
from .noise import apply_noise_filter, cluster
from .references import build_references
from .report import render_incident
from .response import actions as build_actions
from .response import contacts as build_contacts
from .response import derive_severity, detection
from .verifier import ClaimVerifier

STAGES = [
    (1, "Ingest & classify"), (2, "Parse & quarantine"), (3, "UTC time normalisation"), (4, "Temporal entity resolution"),
    (5, "Detection & clustering"), (6, "Noise filter (change calendar)"), (7, "Severity derivation"), (8, "Coverage & gap analysis"),
    (9, "Evidence ledger"), (10, "Runbooks & escalation"), (11, "Report & claim verifier"),
]


class Runtime:
    """Everything the API needs after a run (kept in memory)."""

    def __init__(self) -> None:
        self.case: dict[str, Any] = {}
        self.files: dict[str, Any] = {}
        self.refs: Any = None
        self.ctx: Optional[Ctx] = None
        self.verifier: Optional[ClaimVerifier] = None
        self.incidents: list[Incident] = []
        self.gateway: Optional[LLMGateway] = None


def _clock_skew(ctx: Ctx, alert_links: dict[str, dict[str, Any]]) -> dict[str, Any]:
    """Compare the same activity as seen by two systems. A consistent offset
    larger than CLOCK_SKEW_FLAG_S would mean one clock is off."""
    pairs: list[dict[str, Any]] = []
    for ref, link in alert_links.items():
        a = ctx.by_id[ref]
        prior = [ctx.by_id[t] for t in link["trigger_events"] if ctx.by_id[t].ts_utc <= a.ts_utc]
        if prior:
            src = max(prior, key=lambda e: e.ts_utc)
            pairs.append(dict(a=src.id, b=ref, a_source=src.source_type, b_source="ids", delta_s=(a.ts_utc - src.ts_utc).total_seconds(),
                              what=f"{link['alert_id']} raised after the event it describes"))
    for dc in ctx.ev("dc"):
        if not dc.ip_source:
            continue
        for fw in ctx.ev("fw_int"):
            if fw.ip_source == dc.ip_source and fw.start and abs((fw.start - dc.ts_utc).total_seconds()) <= 15:
                pairs.append(dict(a=dc.id, b=fw.id, a_source="dc", b_source="fw_int", delta_s=(fw.start - dc.ts_utc).total_seconds(),
                                  what="domain-controller event vs derived start of the internal-firewall session"))
    first_web: dict[str, Event] = {}
    for w in ctx.ev("web"):
        first_web.setdefault(w.ip_source or "", w)
    for ip, w in first_web.items():
        for fw in ctx.ev("fw_edge"):
            if fw.ip_source == ip and abs((w.ts_utc - fw.ts_utc).total_seconds()) <= 15:
                pairs.append(dict(a=fw.id, b=w.id, a_source="fw_edge", b_source="web", delta_s=(w.ts_utc - fw.ts_utc).total_seconds(),
                                  what="perimeter-firewall connection vs first web request"))
    by_pair: dict[str, list[float]] = {}
    for p in pairs:
        by_pair.setdefault(f"{p['a_source']} -> {p['b_source']}", []).append(p["delta_s"])
    summary = [dict(pair=k, samples=len(v), min_s=min(v), max_s=max(v), flagged=min(abs(x) for x in v) > config.CLOCK_SKEW_FLAG_S) for k, v in by_pair.items()]
    flagged = [s["pair"] for s in summary if s["flagged"]]
    verdict = (f"Clock skew suspected between: {', '.join(flagged)}." if flagged else
               f"No clock skew found: {len(pairs)} cross-system event pairs agree within {max((abs(p['delta_s']) for p in pairs), default=0):.0f} s "
               f"(flag threshold {config.CLOCK_SKEW_FLAG_S} s, heuristic).")
    return dict(pairs=pairs, summary=summary, verdict=verdict)


def _coverage_stats(ctx: Ctx) -> list[dict[str, Any]]:
    """Observed first/last event and largest silence per source (informational heuristic)."""
    out = []
    by_file: dict[str, list[Event]] = {}
    for e in ctx.events:
        by_file.setdefault(e.source_file, []).append(e)
    for file, evs in by_file.items():
        ts = sorted(e.ts_utc for e in evs)
        gaps = [(b - a).total_seconds() for a, b in zip(ts, ts[1:])]
        out.append(dict(file=file, events=len(evs), first_utc=ts[0], last_utc=ts[-1], largest_silence_s=max(gaps) if gaps else 0))
    return out


def run_pipeline(dataset: str = "orbit", llm_mode: Optional[str] = None, on_stage: Optional[Callable[[dict[str, Any]], None]] = None,
                 pace_ms: int = 0, data_dir: Optional[Path] = None, verify: bool = True) -> Runtime:
    rt = Runtime()
    trace: list[dict[str, Any]] = []
    t_run = time.perf_counter()

    def emit(no: int, ms: float, detail: str, status: str = "done") -> None:
        ev = dict(stage=no, name=dict(STAGES)[no], ms=round(ms, 2), detail=detail, status=status)
        if status == "done":
            trace.append(ev)
        if on_stage:
            on_stage(ev)
        if pace_ms and status == "done":
            time.sleep(pace_ms / 1000)

    def start(no: int) -> float:
        if on_stage:
            on_stage(dict(stage=no, name=dict(STAGES)[no], status="running"))
        return time.perf_counter()

    ms = lambda t0: (time.perf_counter() - t0) * 1000  # noqa: E731

    # ---- 1 ingest ---------------------------------------------------------
    t0 = start(1)
    files = load_dataset(data_dir or config.DATASETS[dataset])
    refs = build_references(files)
    kinds = {k: sum(1 for f in files.values() if f.file_type == k) for k in ("log", "reference", "runbook")}
    emit(1, ms(t0), f"{len(files)} files: {kinds['log']} log, {kinds['reference']} reference, {kinds['runbook']} runbook")

    # ---- 2 parse ----------------------------------------------------------
    t0 = start(2)
    events: list[Event] = []
    audits: list[dict[str, Any]] = []
    for f in files.values():
        if f.source_type == "log":
            evs, audit = parsers.parse_log_file(f, refs)
        elif f.source_type == "ids":
            evs, audit = parsers.parse_ids_file(f, refs)
        else:
            continue
        f.source_type = audit["format"] if f.source_type == "log" else f.source_type
        events += evs
        audits.append(audit)
    quarantined = [q for a in audits for q in a["quarantined"]]
    injected = [e for e in events if "PROMPT_INJECTION" in e.flags]
    emit(2, ms(t0), f"{sum(a['parsed'] for a in audits)} of {sum(a['lines'] for a in audits)} lines parsed, {len(quarantined)} quarantined, {len(injected)} prompt-injection hit(s)")

    # ---- 3 time -----------------------------------------------------------
    t0 = start(3)
    tz_table = []
    for a in audits:
        sample = next((e for e in events if e.source_file == a["file"] and e.ts_utc), None)
        pol = refs.tz_policies.get(a["file"])
        tz_table.append(dict(file=a["file"], policy=pol.label if pol else "not in the coverage sheet", logged_at=pol.logged_at if pol else None,
                             citation=pol.citation.model_dump() if pol and pol.citation else None, tz_assumed=a["tz_assumed"],
                             example=dict(ref=sample.id, original=sample.ts_original, utc=sample.ts_utc, source=sample.tz_source) if sample else None))
    assumed = [a["file"] for a in audits if a["tz_assumed"]]
    emit(3, ms(t0), f"{len(tz_table)} sources normalised to UTC" + (f"; ZONE ASSUMED for {', '.join(assumed)}" if assumed else "; no zone had to be assumed"))

    # ---- 4 entities -------------------------------------------------------
    t0 = start(4)
    graph = EntityGraph(refs, events)
    ctx = Ctx(files, refs, events, graph)
    emit(4, ms(t0), f"graph: {graph.g.number_of_nodes()} nodes, {graph.g.number_of_edges()} edges, {len(graph.leases)} DHCP leases, {len(graph.sessions)} VPN sessions (time-bounded)")

    # ---- 5 detect ---------------------------------------------------------
    t0 = start(5)
    findings, alert_links = run_detectors(ctx)
    skew = _clock_skew(ctx, alert_links)
    emit(5, ms(t0), f"{len(findings)} findings from {len(ctx.events)} events; {len(alert_links)} IDS alerts linked to raw events")

    # ---- 6 noise ----------------------------------------------------------
    t0 = start(6)
    open_findings, exclusions, near = apply_noise_filter(ctx, findings, alert_links)
    groups, loose = cluster(open_findings)
    emit(6, ms(t0), f"{len(exclusions)} activity group(s) closed as harmless ({', '.join(x.change_id for x in exclusions) or 'none'}); {len(groups)} incident(s) remain")

    # ---- 7-10 per incident (timed per stage) ------------------------------
    for no in (7, 8, 9, 10):
        start(no)
    buckets = {7: 0.0, 8: 0.0, 9: 0.0, 10: 0.0}
    drafts: list[dict[str, Any]] = []
    for g in groups:
        t0 = time.perf_counter()
        built = Builder(ctx, g, alert_links, near).build()
        buckets[9] += ms(t0)
        t0 = time.perf_counter()
        sev = derive_severity(ctx, built)
        det = detection(ctx, built)
        buckets[7] += ms(t0)
        t0 = time.perf_counter()
        acts, notes = build_actions(ctx, built)
        people = build_contacts(ctx, built, sev["overall"], sev, det)
        buckets[10] += ms(t0)
        drafts.append(dict(built=built, sev=sev, det=det, actions=acts, notes=notes, contacts=people, findings=g))
    drafts.sort(key=lambda d: (SEV_RANK.get(d["sev"]["overall"] or "", 9), d["built"]["start"] or datetime.max.replace(tzinfo=timezone.utc)))
    date_tag = (refs.log_date or "").replace("-", "") or "X"
    incidents: list[Incident] = []
    for n, d in enumerate(drafts, 1):
        b, sev, det = d["built"], d["sev"], d["det"]
        suspected_only = any(c.get("suspected_only") for c in b["facts"].get("cred", [])) and not any(k in ("mfa_fatigue", "large_transfer", "web_attack") for k in {f.kind for f in d["findings"]})
        driving = next((p for p in sev["parts"] if p.part == sev["driving_part"]), None)
        incidents.append(Incident(
            incident_id=f"INC-{date_tag}-{n:02d}", title=b["title"], incident_type=(driving.matrix_row if driving and driving.matrix_row else (b["parts"][0]["label"] if b["parts"] else "Unclassified")),
            severity=sev["overall"], confidence="SUSPECTED_ONLY" if suspected_only else "CONFIRMED", status="NEEDS_REVIEW" if suspected_only or not sev["overall"] else "TRIAGED",
            summary=b["summary"], kill_chain=b["kill_chain"], highest_criticality_asset=sev["driving_asset"],
            detection_time_utc=det["ts"], detection_basis=det["basis"], detection_citations=det["citations"],
            severity_reached_utc=sev["reached_at"], severity_reached_basis=sev["reached_basis"], severity_parts=sev["parts"], severity_steps=sev["steps"] + d["notes"],
            timeline=b["timeline"], claims=b["claims"], affected_assets=[dict(a, citations=[c.model_dump() for c in a["citations"]]) for a in b["assets"]],
            affected_accounts=[dict(a, citations=[c.model_dump() for c in a["citations"]]) for a in b["accounts"]], attacker_ips=b["attacker_ips"],
            gaps=b["gaps"], actions=d["actions"], contacts=d["contacts"], alerts=b["alerts"], finding_ids=[f.id for f in d["findings"]], flags=b["flags"],
            heuristics=b["heuristics"], window_start_utc=b["start"], window_end_utc=b["end"]))
    sev_txt = ", ".join(f"{i.incident_id}={i.severity or 'n/a'}" for i in incidents) or "no incidents"
    emit(7, buckets[7], f"matrix lookup per part: {sev_txt}")
    emit(8, buckets[8] + 0.01, f"{len(refs.gaps)} coverage gap(s), {len(refs.missing_sources)} log source(s) not collected; {sum(len(i.gaps) for i in incidents)} gap(s) overlap an incident")
    n_claims = {s: sum(1 for i in incidents for c in i.claims if c.status == s) for s in ("CONFIRMED", "SUSPECTED", "INSUFFICIENT_EVIDENCE")}
    emit(9, buckets[9], f"{n_claims['CONFIRMED']} confirmed, {n_claims['SUSPECTED']} suspected, {n_claims['INSUFFICIENT_EVIDENCE']} not-enough-evidence claims")
    emit(10, buckets[10], f"{sum(len(i.actions) for i in incidents)} runbook steps, {sum(len(i.contacts) for i in incidents)} people to inform")

    # ---- 11 report + verifier --------------------------------------------
    t0 = start(11)
    verifier = ClaimVerifier(files, refs)
    gw = LLMGateway(llm_mode)
    reports: dict[str, Any] = {}
    for inc in incidents:
        claims = {c.claim_id: c.status for c in inc.claims}
        template_summary = list(inc.summary)
        prose = write_prose(gw, f"Summarise this security incident for the SOC shift lead. Incident title: {inc.title}. Severity: {inc.severity}.",
                            inc.claims, refs, verifier, verify=verify)
        note = ""
        if prose["sentences"]:
            inc.summary, inc.summary_source = prose["sentences"], prose["source"]
            note = (f"Summary prose written by {prose['source']} from the verified claims below; every sentence passed the code verifier." if verify else
                    f"Summary prose written by {prose['source']} with the verifier gate DISABLED by the analyst; it was checked but not blocked.")
        md = render_incident(inc, refs, exclusions, LINE_CONVENTION, note)
        md, vlog = verifier.verify_markdown(md, claims)
        vlog["gate_enabled"] = verify
        fell_back = False
        if verify and not vlog["passed"] and prose["sentences"]:
            # the model-written summary broke grounding in the rendered report: fall back to the template
            inc.summary, inc.summary_source, fell_back = template_summary, "template", True
            md = render_incident(inc, refs, exclusions, LINE_CONVENTION, "")
            md, vlog = verifier.verify_markdown(md, claims)
        vlog["llm"] = dict(prose["log"], used=bool(prose["sentences"]) and not fell_back, fell_back_to_template=fell_back or not prose["sentences"])
        reports[inc.incident_id] = dict(markdown=md, verifier=vlog, verifier_passed=vlog["passed"], summary_source=inc.summary_source,
                                        report_sha256=integrity.sha256_text(md))
    passed = sum(1 for r in reports.values() if r["verifier_passed"])
    n_cit = sum(r["verifier"]["citations_checked"] for r in reports.values())
    used = sum(1 for r in reports.values() if r["verifier"]["llm"]["used"])
    emit(11, ms(t0), f"{passed}/{len(reports)} reports passed the verifier ({n_cit} citations checked); summary prose: {used} by model, {len(reports) - used} by template")

    # ---- case file --------------------------------------------------------
    event_dump = [e.model_dump(mode="json") for e in sorted(events, key=lambda e: (e.source_file, e.line_no))]
    incidents_dump = [i.model_dump(mode="json") for i in incidents]
    exclusions_dump = [x.model_dump(mode="json") for x in exclusions]
    for link in alert_links.values():
        link.setdefault("disposition", "UNLINKED - needs analyst review")
    file_hashes = {f.filename: f.sha256 for f in files.values()}
    content = dict(incidents=incidents_dump, exclusions=exclusions_dump)
    case = dict(
        dataset=dataset, generated_at=datetime.now(timezone.utc).isoformat(), line_convention=LINE_CONVENTION,
        company=dict(local_tz_label=refs.local_tz_label, local_tz_hours=refs.local_tz_hours, log_date=refs.log_date,
                     local_tz_citation=refs.local_tz_citation.model_dump() if refs.local_tz_citation else None),
        files=[dict(filename=f.filename, title=f.title, file_type=f.file_type, source_type=f.source_type, total_lines=f.total_lines, sha256=f.sha256) for f in files.values()],
        parsing_audit=dict(files=audits, total_lines=sum(a["lines"] for a in audits), parsed=sum(a["parsed"] for a in audits), quarantined=quarantined,
                           duplicates=[d for a in audits for d in a["duplicates"]],
                           injection_hits=[dict(ref=e.id, signatures=e.fields.get("injection_signatures", []), source_type=e.source_type) for e in injected]),
        time_normalization=dict(sources=tz_table, clock_skew=skew, sort_order="timestamp (UTC), then source priority, then line number"),
        entity_graph=dict(graph.export(), stats=dict(nodes=graph.g.number_of_nodes(), edges=graph.g.number_of_edges())),
        incidents=incidents_dump, exclusions=exclusions_dump, near_misses=near,
        observations=[dict(finding_id=f.id, kind=f.kind, title=f.title, events=[ctx.cite(i).model_dump() for i in f.event_ids],
                           note="Supporting observation with no link to an incident; not escalated.") for f in loose],
        alert_dispositions=sorted(([dict(v, ts=v["ts"].isoformat()) for v in alert_links.values()]), key=lambda v: v["ts"]),
        coverage=dict(rows=[c.model_dump(mode="json") for c in refs.coverage], gaps=[g.model_dump(mode="json") for g in refs.gaps],
                      missing_sources=[m.model_dump(mode="json") for m in refs.missing_sources], observed=_coverage_stats(ctx)),
        change_calendar=[c.model_dump(mode="json") for c in refs.changes],
        reports=reports,
        security=dict(sandbox="Evidence reaches a model only inside <untrusted_evidence_data> boundaries, never in instructions.",
                      pseudonymization=config.LLM_PSEUDONYMIZE, injection_findings=len(injected),
                      data_minimisation="The model receives verified claims, never raw log lines."),
        integrity=integrity.evidence_digest(file_hashes, event_dump, content),
        llm=gw.status(), pipeline_trace=trace,
        stats=dict(files=len(files), events=len(ctx.events), incidents=len(incidents), exclusions=len(exclusions), claims=n_claims,
                   alerts=len(alert_links), total_ms=round(ms(t_run), 1)),
    )
    rt.case, rt.files, rt.refs, rt.ctx, rt.verifier, rt.incidents, rt.gateway = case, files, refs, ctx, verifier, incidents, gw
    rt.events_dump = event_dump  # type: ignore[attr-defined]
    return rt
