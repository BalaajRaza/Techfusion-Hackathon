"""Stage 11a - report rendering.

The deterministic template below always works (no model needed) and follows
the section list of security rule 7. If a model wrote the Summary, only that
block differs - and only after the verifier accepted it.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Iterable, Optional

from ..models import TIER_LABEL, Citation, Incident
from . import timeutil as tu
from .noise import Exclusion
from .references import References


def cites(cs: Iterable[Citation], limit: Optional[int] = None) -> str:
    seen: list[str] = []
    for c in cs:
        if c.ref not in seen:
            seen.append(c.ref)
    if limit:
        seen = seen[:limit]
    return " ".join(f"[{r}]" for r in seen)


def _dt(v: Any) -> Any:
    return datetime.fromisoformat(v) if isinstance(v, str) else v


def esc(text: str) -> str:
    return str(text).replace("|", "\\|").replace("\n", " ")


def render_incident(inc: Incident, refs: References, exclusions: list[Exclusion], line_convention: str, llm_note: str = "") -> str:
    h, lab = refs.local_tz_hours, refs.local_tz_label
    loc = lambda dt: tu.fmt_local(dt, h, lab)  # noqa: E731
    claims = {c.claim_id: c for c in inc.claims}
    L: list[str] = []
    sev = inc.severity or "no matrix severity"
    L.append(f"# {inc.incident_id} - {inc.title}")
    L.append("")
    L.append(f"**Severity:** {sev} | **Type:** {inc.incident_type} | **Status:** {inc.status}"
             + (" | **Confidence:** suspected only" if inc.confidence == "SUSPECTED_ONLY" else ""))
    L.append("")
    tzc = f" {cites([refs.local_tz_citation])}" if refs.local_tz_citation else ""
    L.append(f"_All times are UTC; company local time ({lab}, UTC{h:+g}) is shown in brackets.{tzc}_")
    L.append("")
    L.append(f"_{line_convention}_")
    L.append("")

    L.append("## Summary")
    if llm_note:
        L.append(f"_{llm_note}_")
        L.append("")
    for s in inc.summary:
        ids = [c for c in s["claim_ids"] if c in claims]
        cs = [ct for c in ids for ct in claims[c].citations]
        tag = f" ({', '.join(ids)})" if ids else ""
        L.append(f"- {s['text']}{tag} {cites(cs, 14)}".rstrip())
    L.append("")

    L.append("## Timeline (UTC)")
    L.append(f"| Time (UTC) | {lab} | What happened | Label | Evidence |")
    L.append("|---|---|---|---|---|")
    for t in inc.timeline:
        when = tu.fmt_utc(t.ts_utc)[:-4] + (f" - {tu.fmt_utc(t.ts_end_utc)[:-4]}" if t.ts_end_utc else "")
        L.append(f"| {when} | {loc(t.ts_utc)[:-len(lab) - 1]} | **{esc(t.label)}** - {esc(t.detail)} | {TIER_LABEL[t.status]} | {cites(t.citations, 8)} |")
    L.append("")

    L.append("## Affected assets and accounts")
    for a in inc.affected_assets:
        reach = {True: "counted as reached (confirmed login or session)", False: "not counted as reached", None: "targeted"}[a.get("reached")]
        meta = f"{a['tag']}, {a['type']}, criticality {a['criticality']}, owner: {a['owner']}" if a.get("in_inventory") else "NOT in the asset inventory - criticality cannot be assigned"
        L.append(f"- **{a['hostname']}** ({meta}) - {'; '.join(a['roles'])}. {reach.capitalize()}: {'; '.join(a['basis'])}. {cites([Citation(**c) if isinstance(c, dict) else c for c in a['citations']], 6)}")
    for u in inc.affected_accounts:
        who = f"{u['full_name']}, {u['role_in_company']}" if u.get("in_directory") else "not in the user directory"
        L.append(f"- **Account {u['username']}** ({who}) - {'; '.join(u['roles'])}. {cites([Citation(**c) if isinstance(c, dict) else c for c in u['citations']], 6)}")
    if inc.attacker_ips:
        L.append(f"- Source address(es) of the activity: {', '.join(inc.attacker_ips)}. {cites([c for cl in inc.claims if cl.status == 'CONFIRMED' for c in cl.citations if any(ip in c.text for ip in inc.attacker_ips)], 8)}")
    L.append("")

    L.append("## Severity")
    drv = refs.asset_by_name(inc.highest_criticality_asset)
    L.append(f"**Result: {sev}**" + (f" - driven by {inc.highest_criticality_asset} {cites([drv.citation]) if drv else ''}" if inc.highest_criticality_asset else ""))
    L.append("")
    for p in inc.severity_parts:
        L.append(f"**Part: {p.part} -> {p.result or 'no matrix result'}** {cites(p.citations, 8)}")
        for i, s in enumerate(p.steps, 1):
            L.append(f"{i}. {s}")
        L.append("")
    for s in inc.severity_steps:
        L.append(f"- {s}")
    if inc.detection_time_utc:
        L.append(f"- SOC clock start: {tu.fmt_utc(inc.detection_time_utc)} ({loc(inc.detection_time_utc)}). {inc.detection_basis} {cites(inc.detection_citations)}")
    if inc.severity_reached_utc and inc.detection_time_utc and inc.severity_reached_utc > inc.detection_time_utc:
        L.append(f"- The conditions for {sev} were first visible at {tu.fmt_utc(inc.severity_reached_utc)} ({inc.severity_reached_basis}).")
    for hnote in inc.heuristics:
        L.append(f"- Heuristic used: {hnote}")
    L.append("")

    for status, heading in (("CONFIRMED", "Confirmed"), ("SUSPECTED", "Suspected"), ("INSUFFICIENT_EVIDENCE", "Not enough evidence in the logs")):
        L.append(f"## {heading}")
        rows = [c for c in inc.claims if c.status == status]
        if not rows:
            L.append("- None.")
        for c in rows:
            line = f"- **{c.claim_id}** {c.text}"
            if c.rule:
                line += f" _{'Guess / rule' if status == 'SUSPECTED' else 'Basis'}: {c.rule}_"
            L.append(f"{line} {cites(c.citations)}")
        L.append("")

    L.append("## Missing log sources")
    if inc.gaps:
        for g in inc.gaps:
            s, e = datetime.fromisoformat(g["start_utc"]) if isinstance(g["start_utc"], str) else g["start_utc"], datetime.fromisoformat(g["end_utc"]) if isinstance(g["end_utc"], str) else g["end_utc"]
            L.append(f"- **Gap inside this incident's time window:** no {g['source'].lower()} logs from {tu.fmt_utc(s)} to {tu.fmt_utc(e)} ({loc(e)}). {g['reason']} [{g['citation']['file']}:{g['citation']['locator']}]")
    for m in refs.missing_sources:
        L.append(f"- Not collected: {m.text} {cites([m.citation])}")
    for g in refs.gaps:
        if not any(x["source"] == g.source and _dt(x["start_utc"]) == g.start_utc for x in inc.gaps):
            L.append(f"- Outside this incident's window: no {g.source.lower()} logs from {tu.fmt_utc(g.start_utc, True)} to {tu.fmt_utc(g.end_utc, True)}. {cites([g.citation])}")
    L.append("")

    L.append("## Closed as harmless")
    if not exclusions:
        L.append("- Nothing was closed as approved activity.")
    for x in exclusions:
        L.append(f"- **{x.change_id}** - {x.title}. {x.reason} {cites([x.change_citation] + x.events + x.alerts + x.rule_citations)}")
    L.append("")

    L.append("## Recommended actions")
    if not inc.actions:
        L.append("- No approved runbook applies to this incident type. No action is recommended from the runbooks; escalate per the escalation sheet.")
    current = None
    for a in inc.actions:
        if a.runbook_id != current:
            current = a.runbook_id
            L.append(f"**{a.runbook_id}**" + (f" - opened because {a.opened_because}. {cites(a.opened_citations)}" if a.opened_because else ""))
        line = f"- {a.runbook_id} step {a.step_no}: {a.text}"
        if a.context:
            line += f" _Evidence: {a.context}_"
        L.append(f"{line} {cites([a.citation] + a.context_citations, 12)}")
    L.append("")

    L.append("## People to inform")
    if not inc.contacts:
        L.append("- No escalation row applies (no matrix severity). Escalate for a human decision.")
    else:
        L.append("| Who | Name | Contact | Time limit | Deadline (UTC) | How | Source |")
        L.append("|---|---|---|---|---|---|---|")
        for c in inc.contacts:
            dl = tu.fmt_utc(c.deadline_utc, True) if c.deadline_utc else c.time_limit
            note = f" {c.note}" if c.note else ""
            L.append(f"| {esc(c.role)} | {esc(c.name or '-')} | {esc(c.contact or 'not in the files')} | {esc(c.time_limit)} | {dl} | {esc(c.how)}{esc(note)} | {cites(c.citations)} |")
        alt = [c for c in inc.contacts if c.deadline_alt_utc]
        if alt and inc.severity_reached_utc:
            L.append("")
            L.append(f"- Deadlines above count from the SOC clock start ({tu.fmt_utc(inc.detection_time_utc)}). Counted instead from the moment the {sev} conditions were first visible "
                     f"({tu.fmt_utc(inc.severity_reached_utc)}, {inc.severity_reached_basis}) they would be: "
                     + "; ".join(f"{c.role} {tu.fmt_utc(c.deadline_alt_utc)}" for c in alt) + ".")
    L.append("")
    return "\n".join(L)
