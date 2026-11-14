"""Stage 6 - noise suppression against the change calendar.

Suppress  <=>  approval AND time window AND asset scope AND actor AND activity

All five conditions are evaluated per EVENT, so:
  * an approved scanner outside its window, or against an out-of-scope asset,
    is NOT harmless and stays escalated;
  * activity that only partly fits a window is split - the covered part is
    closed, the rest stays;
  * an unfamiliar actor inside a maintenance window is kept and flagged
    RESIDUAL_ANOMALY_DURING_MAINTENANCE.
Suppressed activity is never deleted: it is reported under "Closed as harmless"
with the change ID and the five checks.
"""
from __future__ import annotations

import ipaddress
import re
from typing import Any, Optional

from pydantic import BaseModel, Field

from ..models import Citation, Event, Finding
from . import timeutil as tu
from .detectors import Ctx
from .references import ChangeEntry

ACTIVITY_WORDS = {
    "scan": r"scan|vulnerability|reconnaissance|discovery",
    "remote_desktop": r"remote desktop|rdp|remote session",
    "data_transfer": r"backup|transfer|copy|migration|replication|restore",
    "vpn_login": r"vpn (login|access|test)",
    "web_attack": r"penetration test|pentest|web application test",
}
CHECKS = ["approval", "time", "asset", "actor", "activity"]
CHECK_LABEL = {"approval": "Approval status", "time": "Time window", "asset": "Asset scope", "actor": "Actor / tool", "activity": "Activity type"}


class Exclusion(BaseModel):
    id: str
    change_id: str
    change_citation: Citation
    title: str
    description: str
    finding_ids: list[str]
    events: list[Citation]
    alerts: list[Citation]
    context: list[Citation] = Field(default_factory=list)
    criteria: list[dict[str, Any]]
    reason: str
    rule_citations: list[Citation] = Field(default_factory=list)
    start_utc: Optional[Any] = None
    end_utc: Optional[Any] = None


def _in_cidrs(ip: Optional[str], cidrs: list[str]) -> bool:
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c, strict=False) for c in cidrs)
    except ValueError:
        return False


def evaluate(ctx: Ctx, finding: Finding, e: Event, entry: ChangeEntry) -> dict[str, dict[str, Any]]:
    """The five checks for one event against one calendar entry."""
    r = ctx.refs
    hrs, lab = r.local_tz_hours, r.local_tz_label
    res: dict[str, dict[str, Any]] = {}

    # 1 approval
    res["approval"] = dict(ok=entry.approved, detail=f"status is '{entry.status}'")

    # 2 time window (the calendar is in local time; compared in UTC)
    start, end = e.start, e.end or e.start
    if entry.start_utc and entry.end_utc and start:
        inside = entry.start_utc <= start and end <= entry.end_utc
        overlap = start <= entry.end_utc and end >= entry.start_utc
        win = f"{tu.fmt_utc(entry.start_utc)[:-4]}-{tu.fmt_utc(entry.end_utc)} on {entry.start_utc:%Y-%m-%d} ({entry.window_text} {lab})"
        when = tu.fmt_utc(start) if start == end else f"{tu.fmt_utc(start)[:-4]}-{tu.fmt_utc(end)}"
        res["time"] = dict(ok=inside, partial=overlap and not inside, start=start, end=end,
                           detail=f"{when} is {'inside' if inside else ('only partly inside' if overlap else 'outside')} the window {win}")
    else:
        res["time"] = dict(ok=False, partial=False, start=start, end=end, detail="the calendar window could not be read")

    # 3 asset scope
    targets = ctx.target_assets(e)
    t_ips = [ip for a in targets for ip in a.ips] + ([e.ip_dest] if e.ip_dest else [])
    t_names = [a.hostname for a in targets]
    ok_asset = any(n in entry.scope_hosts for n in t_names) or any(_in_cidrs(ip, entry.scope_cidrs) for ip in t_ips)
    shown = ", ".join(dict.fromkeys(t_names)) or (e.ip_dest or "unknown target")
    res["asset"] = dict(ok=ok_asset, targets=t_names or t_ips, detail=f"target {shown} is {'in' if ok_asset else 'NOT in'} scope '{entry.system_target}'")

    # 4 actor / tool  (the source address is resolved AT THE TIME of the event)
    hosts: set[str] = set()
    users: set[str] = set()
    ips: set[str] = set()
    if e.ip_source:
        ips.add(e.ip_source)
        who = ctx.graph.resolve(e.ip_source, start)
        if who.hostname and not who.ambiguous:
            hosts.add(who.hostname)
        if who.user:
            users.add(who.user)
    if e.user_account:
        users.add(e.user_account)
    ok_actor = bool(hosts & set(entry.actor_hosts) or ips & set(entry.actor_ips) or users & set(entry.actor_users))
    actor_txt = ", ".join(sorted(hosts | users) or sorted(ips) or ["unknown"])
    res["actor"] = dict(ok=ok_actor, actors=sorted(hosts | users | ips), detail=f"actor {actor_txt} {'matches' if ok_actor else 'does NOT match'} 'performed by {entry.performed_by}'")

    # 5 activity type
    pat = ACTIVITY_WORDS.get(finding.activity)
    ok_act = bool(pat and re.search(pat, entry.description, re.I))
    res["activity"] = dict(ok=ok_act, detail=f"activity '{finding.activity.replace('_', ' ')}' {'fits' if ok_act else 'does NOT fit'} the description '{entry.description}'")
    return res


def _aggregate(per_event: list[dict[str, dict[str, Any]]]) -> list[dict[str, Any]]:
    out = []
    for name in CHECKS:
        oks = [pe[name]["ok"] for pe in per_event]
        details = list(dict.fromkeys(pe[name]["detail"] for pe in per_event))
        if name == "time" and len(per_event) > 1:
            starts = [pe["time"]["start"] for pe in per_event if pe["time"].get("start")]
            ends = [pe["time"]["end"] for pe in per_event if pe["time"].get("end")]
            if starts and ends:
                tail = details[0].split(" is ", 1)[1] if " is " in details[0] and len(set(d.split(" is ", 1)[-1] for d in details)) == 1 else None
                if tail:
                    details = [f"{tu.fmt_utc(min(starts))[:-4]}-{tu.fmt_utc(max(ends))} (all {len(per_event)} events) is {tail}"]
        out.append(dict(name=name, label=CHECK_LABEL[name], ok=all(oks), passed=sum(oks), total=len(oks), detail="; ".join(details[:4])))
    return out


def apply_noise_filter(ctx: Ctx, findings: list[Finding], alert_links: dict[str, dict[str, Any]]) -> tuple[list[Finding], list[Exclusion], list[dict[str, Any]]]:
    """Returns (findings still open, exclusions, near-miss log)."""
    r = ctx.refs
    open_findings: list[Finding] = []
    closed: dict[str, list[tuple[Finding, list[Event], list[dict]]]] = {}
    near: list[dict[str, Any]] = []

    for f in findings:
        evs = [ctx.by_id[i] for i in f.event_ids if ctx.by_id[i].source_type != "ids"]
        if not evs or not r.changes or f.activity not in ACTIVITY_WORDS:
            open_findings.append(f)
            continue
        table = {c.change_id: [evaluate(ctx, f, e, c) for e in evs] for c in r.changes}
        # per event: which entry (if any) satisfies all five?
        covered: dict[str, str] = {}
        for idx, e in enumerate(evs):
            for c in r.changes:
                if all(table[c.change_id][idx][k]["ok"] for k in CHECKS):
                    covered[e.id] = c.change_id
                    break
        for c in r.changes:
            agg = _aggregate(table[c.change_id])
            passed = sum(1 for a in agg if a["ok"])
            relevant = any(a["ok"] for a in agg if a["name"] in ("asset", "actor")) and passed >= 2
            if passed < 5 and (relevant or passed >= 3):
                near.append(dict(finding_id=f.id, finding_title=f.title, change_id=c.change_id, passed=passed, criteria=agg,
                                 failed=[a["label"] for a in agg if not a["ok"]], citation=c.citation.model_dump()))
            ok = {a["name"]: a for a in agg}
            if not covered and ok["approval"]["ok"] and ok["activity"]["ok"]:
                if ok["actor"]["ok"] and ok["asset"]["ok"] and not ok["time"]["ok"]:
                    f.flags.append(f"APPROVED_ACTOR_OUTSIDE_WINDOW:{c.change_id}")
                elif ok["actor"]["ok"] and ok["time"]["ok"] and not ok["asset"]["ok"]:
                    f.flags.append(f"APPROVED_ACTOR_OUT_OF_SCOPE_TARGET:{c.change_id}")
                elif ok["time"]["ok"] and ok["asset"]["ok"] and not ok["actor"]["ok"]:
                    f.flags.append(f"RESIDUAL_ANOMALY_DURING_MAINTENANCE:{c.change_id}")
        if not covered:
            open_findings.append(f)
            continue
        for cid in dict.fromkeys(covered.values()):
            part = [e for e in evs if covered.get(e.id) == cid]
            idxs = [evs.index(e) for e in part]
            closed.setdefault(cid, []).append((f, part, [table[cid][i] for i in idxs]))
        residual = [e for e in evs if e.id not in covered]
        if residual:
            # split: the covered part is closed, the remainder stays escalated
            keep = {e.id for e in residual}
            f.event_ids = [i for i in f.event_ids if i in keep]
            for key in ("denied", "allowed", "requests"):
                if isinstance(f.data.get(key), list):
                    f.data[key] = [x for x in f.data[key] if x.get("event") in keep]
            f.data["target_ips"] = sorted({e.ip_dest for e in residual if e.ip_dest})
            f.data["targets"] = sorted({a.hostname for e in residual for a in ctx.target_assets(e)})
            f.start, f.end = min(e.start for e in residual), max(e.end or e.start for e in residual)
            for cid in dict.fromkeys(covered.values()):
                c = next(c for c in r.changes if c.change_id == cid)
                agg = _aggregate([evaluate(ctx, f, e, c) for e in residual])
                bad = [a["label"].lower() for a in agg if not a["ok"]]
                f.flags.append(f"PARTLY_COVERED_BY:{cid} (remaining events fail: {', '.join(bad)})")
            open_findings.append(f)

    exclusions: list[Exclusion] = []
    rule_cites = [r.rules[k] for k in ("3.1", "3.2") if k in r.rules]
    rule_cites += [c for c in r.matrix_notes if re.search(r"approved activity", c.text, re.I)]
    for n, (cid, items) in enumerate(sorted(closed.items()), 1):
        c = next(c for c in r.changes if c.change_id == cid)
        evs = sorted({e.id: e for _, part, _ in items for e in part}.values(), key=lambda e: (e.start, e.source_file, e.line_no))
        closed_ids = {e.id for e in evs}
        alerts = [ctx.by_id[ref] for ref, link in alert_links.items() if link["trigger_events"] and all(t in closed_ids for t in link["trigger_events"])]
        for a in alerts:
            alert_links[a.id]["disposition"] = f"CLOSED_AS_HARMLESS:{cid}"
        agg = _aggregate([pe for _, _, pes in items for pe in pes])
        context: list[Citation] = []
        for f, _, _ in items:
            if f.data.get("session_auth"):
                context.append(ctx.cite(f.data["session_auth"]))
        actors = sorted({a for _, _, pes in items for pe in pes for a in pe["actor"]["actors"] if not re.match(r"^\d", a)})
        targets = sorted({str(t) for _, _, pes in items for pe in pes for t in pe["asset"]["targets"]})
        start, end = min(e.start for e in evs), max(e.end or e.start for e in evs)
        reason = (f"All five checks pass against {cid} ({c.description}, {c.status}): {len(evs)} log line(s) by {', '.join(actors) or c.performed_by} "
                  f"against {', '.join(targets)} between {tu.fmt_utc(start)[:-4]} and {tu.fmt_utc(end)} fall inside the approved window "
                  f"{c.window_text} {c.tz_label}. Closed as approved activity - not escalated, no severity.")
        exclusions.append(Exclusion(
            id=f"EXC-{n:02d}", change_id=cid, change_citation=c.citation, title="; ".join(dict.fromkeys(f.title for f, _, _ in items)),
            description=c.description, finding_ids=[f.id for f, _, _ in items], events=[e.cite() for e in evs], alerts=[a.cite() for a in alerts],
            context=context, criteria=agg, reason=reason, rule_citations=rule_cites, start_utc=start, end_utc=end))
    return open_findings, exclusions, near


def cluster(findings: list[Finding]) -> tuple[list[list[Finding]], list[Finding]]:
    """Group findings into incidents by shared ACTOR evidence (attacker address,
    used account, VPN session, message ID). A shared target is not shared
    evidence, so two unrelated attackers hitting the same server stay separate
    (security rule 4.3). Supporting findings never start an incident."""
    primary = [f for f in findings if f.primary]
    parent = {f.id: f.id for f in primary}

    def find(x: str) -> str:
        while parent[x] != x:
            parent[x] = parent[parent[x]]
            x = parent[x]
        return x

    owner: dict[str, str] = {}
    for f in primary:
        for a in f.actors:
            if a in owner:
                parent[find(f.id)] = find(owner[a])
            else:
                owner[a] = f.id
    groups: dict[str, list[Finding]] = {}
    for f in primary:
        groups.setdefault(find(f.id), []).append(f)
    loose: list[Finding] = []
    for f in findings:
        if f.primary:
            continue
        home = next((g for g in groups.values() if any(a in x.actors for x in g for a in f.actors)), None)
        if home is not None:
            home.append(f)
        else:
            loose.append(f)
    ordered = sorted(groups.values(), key=lambda g: min(x.start for x in g if x.start))
    return ordered, loose
