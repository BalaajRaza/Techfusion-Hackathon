"""Stages 7 and 10 - severity derivation, runbook-constrained actions, and the
escalation clock.

* Severity is a pure table lookup (matrix row x criticality of the most
  critical asset actually reached) and every step is written out.
* Actions can only be steps that exist in a runbook file; each carries its
  runbook ID + step citation. Code adds what the evidence already says about
  the step, never a new action.
* People to inform come only from the escalation sheet.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Callable, Optional

from ..models import CRIT_RANK, SEV_RANK, Citation, Contact, RunbookAction, SeverityPart
from . import timeutil as tu
from .assemble import uniq
from .detectors import Ctx
from .references import is_internal_ip


# ------------------------------------------------------------------ severity
def derive_severity(ctx: Ctx, built: dict[str, Any]) -> dict[str, Any]:
    r = ctx.refs
    assets = {a["hostname"]: a for a in built["assets"]}
    parts: list[SeverityPart] = []
    rules = [r.rules[k] for k in ("4.1", "4.2") if k in r.rules]
    for p in built["parts"]:
        row = r.matrix_row(p["key"])
        sp = SeverityPart(part=p["label"], matrix_row=row.label if row else None, matrix_citation=row.citation if row else None,
                          citations=uniq(p["citations"] + ([row.citation] if row else [])), note=p.get("note"))
        if row is None:
            sp.steps.append(f"Incident type '{p['label']}' has no row in the severity matrix: no severity can be assigned by lookup - escalate for a human decision.")
            parts.append(sp)
            continue
        sp.steps.append(f"Incident type -> matrix row \"{row.label}\" [{row.citation.ref}]")
        counted = []
        for h in p["hosts"]:
            inv = r.asset_by_name(h)
            a = assets.get(inv.hostname if inv else h, {})
            entry = dict(hostname=inv.hostname if inv else h, criticality=inv.criticality if inv else None, counted=bool(inv),
                         basis="; ".join(a.get("basis", [])) or "affected asset", citation=inv.citation.model_dump() if inv else None)
            sp.assets.append(entry)
            if inv:
                counted.append(entry)
                sp.citations = uniq(sp.citations + [inv.citation])
            else:
                sp.steps.append(f"Cannot assign criticality: {h} is not in the asset inventory.")
        # assets touched but not counted as "reached" (rule 4.1: a confirmed login or session)
        if p["key"] == "credential_compromise":
            for a in built["assets"]:
                if a["reached"] is False and a["in_inventory"] and any("session" in role for role in a["roles"]) and a["hostname"] not in p["hosts"]:
                    sp.assets.append(dict(hostname=a["hostname"], criticality=a["criticality"], counted=False, basis="; ".join(a["basis"]),
                                          citation=r.asset_by_name(a["hostname"]).citation.model_dump()))
        if counted:
            listing = "; ".join(f"{e['hostname']} = {e['criticality']} ({e['basis']}) [{e['citation']['file']}:{e['citation']['locator']}]" for e in counted)
            sp.steps.append(("Assets involved (recipients' laptops): " if p["key"] == "phishing_no_click" else "Assets reached: ") + listing)
            top = max(counted, key=lambda e: CRIT_RANK.get(e["criticality"], 0))
            sp.driving_asset, sp.criticality = top["hostname"], top["criticality"]
            sp.result = row.cells.get(top["criticality"])
            sp.steps.append(f"Most critical asset reached (rule 4.1): {top['hostname']} = {top['criticality']} [{top['citation']['file']}:{top['citation']['locator']}]")
            sp.steps.append(f"Matrix cell: \"{row.label}\" x {top['criticality']} = {sp.result}")
            for e in sp.assets:
                if not e["counted"] and e["criticality"] and CRIT_RANK.get(e["criticality"], 0) > CRIT_RANK.get(top["criticality"], 0):
                    alt = row.cells.get(e["criticality"])
                    sp.steps.append(f"Not counted: {e['hostname']} = {e['criticality']} - {e['basis']}. If it were counted as reached the cell would be {alt}. [{e['citation']['file']}:{e['citation']['locator']}]")
        elif not p["hosts"]:
            sp.steps.append("No asset is tied to this part, so no matrix column applies.")
        if sp.note:
            sp.steps.append(f"Note: {sp.note}")
        parts.append(sp)

    scored = [p for p in parts if p.result in SEV_RANK]
    overall = min((p.result for p in scored), key=lambda s: SEV_RANK[s]) if scored else None
    steps: list[str] = []
    driving = None
    if overall:
        driving = next(p for p in scored if p.result == overall)
        if len(parts) > 1:
            steps.append("Rule 4.2: each part is scored and the whole incident gets the highest severity: "
                         + ", ".join(f"{p.part} = {p.result or 'no matrix result'}" for p in parts) + f" -> {overall}." + (f" [{r.rules['4.2'].ref}]" if "4.2" in r.rules else ""))
        else:
            steps.append(f"Single part: {driving.part} = {overall}.")
    else:
        steps.append("No part of this incident maps to a severity matrix cell: severity is left to a human decision.")
    src = next((p for p in built["parts"] if driving and p["label"] == driving.part), None)
    return dict(parts=parts, overall=overall, steps=steps, driving_asset=driving.driving_asset if driving else None,
                driving_part=driving.part if driving else None, rules=rules,
                reached_at=src["first_seen"] if src else None, reached_basis=src["first_seen_basis"] if src else "")


def detection(ctx: Ctx, built: dict[str, Any]) -> dict[str, Any]:
    note = ctx.refs.escalation_notes[:1]
    alerts = sorted(built["alerts"], key=lambda a: a["ts"])
    if alerts:
        a = alerts[0]
        return dict(ts=a["ts"], citations=[Citation(**a["citation"])] + note,
                    basis=(f"The escalation sheet starts the clock when the SOC first sees the incident. That is taken as the first IDS alert linked to it: "
                           f"{a['alert_id']}."))
    return dict(ts=built["start"], citations=note,
                basis="No IDS alert is linked to this incident, so the SOC clock is ASSUMED to start at its first log event (the files do not say when the SOC saw it).")


# ------------------------------------------------------------------ escalation
def contacts(ctx: Ctx, built: dict[str, Any], severity: Optional[str], sev: dict[str, Any], det: dict[str, Any]) -> list[Contact]:
    r = ctx.refs
    out: list[Contact] = []
    if not severity:
        return out
    inv = r.asset_by_name(sev["driving_asset"])
    affected_text = " ".join(f"{a.get('type') or ''} {a.get('owner') or ''}" for a in built["assets"] if a.get("reached") is not False).lower()
    for row in r.escalation:
        if row.severity != severity:
            continue
        c = Contact(severity=severity, role=row.who, time_limit=row.time_limit, time_limit_minutes=row.minutes, how=row.how, citations=[row.citation])
        m = re.match(r"^(.*?)\s+-\s+(.*?)\s*\((.*?)\)\s*$", row.who)
        if m:
            c.role, c.name, c.contact = m.group(1), m.group(2), m.group(3)
        elif re.search(r"data owner|system owner", row.who, re.I):
            want_data = bool(re.search(r"data owner", row.who, re.I))
            c.role = row.who.split("(")[0].strip()
            if inv:
                c.name = (inv.data_owner if want_data and inv.data_owner else None) or inv.owner_person or inv.owner
                c.citations.append(inv.citation)
                person = r.user_by_name((c.name or "").split(",")[0])
                if person:
                    c.contact = person.phone
                    c.citations.append(person.citation)
                else:
                    c.note = f"For {inv.hostname} the inventory gives '{inv.owner}'. No phone number or email for this owner is in the provided files."
            else:
                c.note = "The affected asset is not in the inventory, so the owner cannot be named from the files."
        cond = re.search(r"\bif\b(.+)$", row.how)
        if cond:
            c.condition = "if" + cond.group(1)
            words = [w for w in re.findall(r"finance|hr|customer|payroll|personal", cond.group(1).lower())]
            hit = [w for w in words if re.search(rf"\b{w}\b", affected_text)]
            c.condition_met = bool(hit) if words else None
            names = ", ".join(a["hostname"] for a in built["assets"] if a.get("reached") and a.get("type") and any(re.search(rf"\b{w}\b", a["type"].lower()) for w in hit))
            if hit and names:
                c.note = f"Condition met: {names} is listed in the inventory as holding {' and '.join(hit)} data."
                c.citations += [r.asset_by_name(n.strip()).citation for n in names.split(",")]
            elif words and not hit:
                c.note = "Condition not met by the inventory text of the assets reached; inform only if such data may be involved."
        if row.minutes is not None and det["ts"]:
            c.deadline_utc = det["ts"] + timedelta(minutes=row.minutes)
            if sev.get("reached_at") and sev["reached_at"] != det["ts"]:
                c.deadline_alt_utc = sev["reached_at"] + timedelta(minutes=row.minutes)
        c.citations = uniq(c.citations)
        out.append(c)
    return out


# ------------------------------------------------------------------ runbook actions
def _bind(ctx: Ctx, key: str, text: str, B: dict[str, Any]) -> tuple[Optional[str], list[Optional[Citation]], str]:
    """What the evidence already says about one runbook step.
    Returns (context, citations, status). It never invents an action."""
    r, fx = ctx.refs, B["facts"]
    C = lambda i: ctx.by_id[i].cite() if i else None  # noqa: E731
    t = lambda dt: tu.fmt_utc(dt)  # noqa: E731
    low = text.lower()
    missing = lambda tag: [m for m in r.missing_sources if tag in m.tags]  # noqa: E731
    if re.search(r"record all findings", low):
        return "The JSON case file and this report can be attached to the incident ticket.", [], "PENDING"

    if key == "phishing" and "phish" in fx:
        ph = fx["phish"]
        evs = [C(i) for i in ph["events"]]
        if "every recipient" in low:
            return f"Recipients in the gateway log: {', '.join(ph['recipients'])}.", evs, "ANSWERED_BY_EVIDENCE"
        if "remove or quarantine" in low:
            return f"Message {ph['msgid']} was delivered (not quarantined) to {len(ph['recipients'])} mailbox(es).", evs, "PENDING"
        if "block the sender domain" in low:
            return f"Sender domain: {ph['sender_domain']}. Link domain: {ph['url_host']}.", evs[:1], "PENDING"
        if "check the firewall logs" in low:
            bits, cites = [], []
            for c in ph["clicks"]:
                bits.append(f"connection seen for {c['user']} ({c['laptop']}, {c['src_ip']} -> {c['dst_ip']})")
                cites += [C(c["event"])] + [Citation(**b) for b in c["binding"]]
            for n in ph["no_click"]:
                bits.append(f"none seen for {n['user']} ({n['laptop']})")
                cites += [r.user(n["user"]).citation, r.asset_by_name(n["laptop"]).citation]
            return "Checked in the perimeter firewall log: " + "; ".join(bits) + ".", cites, "ANSWERED_BY_EVIDENCE"
        if "if a click is found" in low:
            if ph["clicks"]:
                users = ", ".join(c["user"] for c in ph["clicks"])
                return f"A connection to the link host is seen for {users}: the credential-compromise runbook is opened below.", [C(c["event"]) for c in ph["clicks"]] + [r.user(c["user"]).citation for c in ph["clicks"]], "ANSWERED_BY_EVIDENCE"
            return "No click is seen in the firewall log: this step does not apply.", [], "ANSWERED_BY_EVIDENCE"
        if "warning notice" in low:
            return f"Recipients: {', '.join(ph['emails'])}.", evs, "PENDING"

    if key == "credential_compromise" and fx.get("cred"):
        creds = fx["cred"]
        cr = creds[0]
        u = r.user(cr["user"])
        if "call the real user" in low:
            if u:
                return f"{u.full_name} ({u.username}): {u.phone}.", [u.citation], "PENDING"
            return f"The account {cr['user']} is not in the user directory: no phone number is available in the files.", [], "PENDING"
        caveat = "Suspected only - confirm with the user first (step 1). " if cr.get("suspected_only") else ""
        if "disable the account" in low:
            txt = caveat + f"Account {cr['user']}. VPN session {cr['session']} " + (f"ended at {t(cr['session_end_ts'])}." if cr["session_end_ts"] else "has no end record in the log.")
            cites = [C(cr["success"]), C(cr["session_end"])]
            if fx.get("lockout") and fx["lockout"]["user"] == cr["user"]:
                txt += f" The account has been locked out since {t(fx['lockout']['ts'])}; a lockout is not the same as disabling it."
                cites.append(C(fx["lockout"]["lock"]))
            return txt, cites, "PENDING"
        if "block the attacker source ip" in low:
            return caveat + f"Source address of the VPN login: {cr['src_ip']}.", [C(cr["success"])], "PENDING"
        if "reset the password" in low:
            if fx.get("reset"):
                return f"The password was already changed from the VPN session at {t(fx['reset']['ts'])}; reset it again through the helpdesk after the account is disabled.", [C(fx["reset"]["event"])], "PENDING"
            return None, [], "PENDING"
        if "review all logins" in low:
            reached = [a for a in B["assets"] if a["reached"] and any(str(cr["session"]) in role for role in a["roles"])]
            auth_only = [a for a in B["assets"] if a["reached"] is False and any("session" in role for role in a["roles"])]
            txt = f"In the logs of {r.log_date}, session {cr['session']} reached: {', '.join(a['hostname'] for a in reached) or 'no internal system'}."
            if auth_only:
                txt += f" Authentication requests only (no logon on the server): {', '.join(a['hostname'] for a in auth_only)}."
            cites = [c for a in reached + auth_only for c in a["citations"]]
            return txt, cites, "ANSWERED_BY_EVIDENCE"
        if "if phishing was the source" in low:
            ck = fx.get("click")
            if ck and ck["user"] == cr["user"]:
                a = r.asset_by_name(ck["laptop"])
                return f"Phishing is the suspected source: the laptop is {ck['laptop']} ({a.tag if a else 'not in inventory'}).", [C(ck["event"])] + [Citation(**b) for b in ck["binding"]], "PENDING"
            return "No phishing link is tied to this account in the logs.", [], "ANSWERED_BY_EVIDENCE"
        if "large data transfer" in low:
            tr = fx.get("transfer")
            if tr:
                return f"A large transfer is seen ({tu.fmt_bytes(tr['bytes'])} from {tr['server_name']}): the data-exfiltration runbook is opened below.", [C(tr["event"])], "ANSWERED_BY_EVIDENCE"
            fw_file = ctx.by_type["fw_int"][0].source_file if ctx.by_type.get("fw_int") else None
            return "No large transfer by this account is seen in the firewall logs.", [next((c.citation for c in r.coverage if c.file == fw_file), None)], "ANSWERED_BY_EVIDENCE"
        if "keep all logs unchanged" in low:
            return "A SHA-256 hash of every input file is recorded in the case file (evidence integrity digest).", [], "PENDING"

    if key == "data_exfiltration" and "transfer" in fx:
        tr = fx["transfer"]
        a = r.asset_by_name(tr["server"])
        ev = C(tr["event"])
        if "unusually large transfer" in low:
            sess = f" (VPN session {tr['session']})" if tr["session"] else ""
            return (f"{tu.fmt_bytes(tr['bytes'])}; {t(tr['start'])} to {t(tr['end'])}; from {tr['server_name']} ({tr['server_ip']}) to {tr['client_ip']}{sess}.",
                    [ev, C(tr["session_auth"])], "ANSWERED_BY_EVIDENCE")
        if "block the destination" in low:
            txt = f"Destination of the transfer: {tr['client_ip']}"
            if tr["session"]:
                txt += f", a VPN pool address used by session {tr['session']}; the remote endpoint of that session is {tr['session_src_ip']}"
            return txt + ".", [ev, C(tr["session_auth"]), r.vpn_pool_citation], "PENDING"
        if "do not reboot" in low:
            return f"Source server: {tr['server_name']}.", [ev], "PENDING"
        if "ask the system owner" in low and a:
            return f"{a.hostname}: owner '{a.owner}'; inventory type '{a.type}'.", [a.citation], "PENDING"
        if "file-level audit logs" in low:
            m = [x for x in missing("file_audit")]
            if m:
                return f"They do not exist (\"{m[0].text}\"): it is recorded as unknown which files were read.", [m[0].citation], "ANSWERED_BY_EVIDENCE"
            return None, [], "PENDING"
        if "inform legal" in low and a:
            words = [w for w in ("finance", "hr", "customer") if re.search(rf"\b{w}\b", a.type.lower() + " " + a.owner.lower())]
            if words:
                return f"Applies: the inventory lists {a.hostname} as '{a.type}'.", [a.citation], "ANSWERED_BY_EVIDENCE"
            return f"The inventory text for {a.hostname} ('{a.type}') does not mention finance, HR or customer data; ask the owner.", [a.citation], "PENDING"

    if key == "web_attack" and "web" in fx:
        w = fx["web"]
        reqs = [C(x["event"]) for x in w["requests"]]
        if "find the attacker ip" in low:
            extra = f" plus {len(w['other_requests'])} other request(s)" if w["other_requests"] else "; no other request from this address"
            return f"{w['src_ip']}: {len(w['requests'])} attack requests in the web server log{extra}.", reqs, "ANSWERED_BY_EVIDENCE"
        if "block the attacker ip" in low:
            return f"Attacker address: {w['src_ip']}.", reqs[:1], "PENDING"
        if "response codes and response sizes" in low:
            fail = [ctx.by_id[i] for i in w["failed"]]
            ok = [ctx.by_id[i] for i in w["success"]]
            txt = f"{len(fail)} request(s) answered with HTTP {', '.join(sorted({str(e.fields['status']) for e in fail}))} / {', '.join(sorted({str(e.fields['bytes']) for e in fail}))} bytes"
            txt += ("; " + "; ".join(f"1 answered with HTTP {e.fields['status']} / {e.fields['bytes']:,} bytes - may mean success" for e in ok)) if ok else "; no large 200 response"
            return txt + ".", [e.cite() for e in fail + ok], "ANSWERED_BY_EVIDENCE"
        if "review the code" in low:
            return f"Attacked page: {', '.join(w['paths'])}.", reqs[:1], "PENDING"
        if "database server logs" in low:
            m = missing("db")
            if m:
                return f"Not available: \"{m[0].text}\".", [m[0].citation], "ANSWERED_BY_EVIDENCE"
            return None, [], "PENDING"
        if "sql injection rule" in low:
            al = [a for a in B["alerts"] if re.search(r"sql|web", str(a["sensor"]) + str(a["description"]), re.I)]
            if al:
                return (f"{al[0]['sensor']} raised {al[0]['alert_id']}, yet the web server still answered the requests, so they were not blocked.",
                        [Citation(**al[0]["citation"])] + reqs[:1], "PENDING")
            return None, [], "PENDING"

    if key == "recon" and "scan" in fx:
        sc = fx["scan"]
        ip, first = sc["src_ip"], C(sc["events"][0])
        if "check the change calendar" in low:
            cal = next((c for c in B["claims"] if c.topic == "calendar"), None)
            return (cal.text if cal else "Checked: no approved change matches the source, the target and the time window."), (cal.citations if cal else [c.citation for c in r.changes]), "ANSWERED_BY_EVIDENCE"
        if "if it is approved" in low:
            return "Not approved: this step does not apply.", [], "ANSWERED_BY_EVIDENCE"
        if "source is external" in low:
            if sc["internal"]:
                return f"{ip} is an internal address: this step does not apply.", [first], "ANSWERED_BY_EVIDENCE"
            return f"{ip} is an external address and no approved change matches: block it.", [first], "PENDING"
        if "source is internal" in low:
            if not sc["internal"]:
                return f"{ip} is an external address: this step does not apply.", [first], "ANSWERED_BY_EVIDENCE"
            a = r.asset_by_ip(ip)
            if a:
                return f"The device is {a.hostname} ({a.tag}); owner in the inventory: {a.owner}.", [a.citation, first], "PENDING"
            return f"{ip} is not in the asset inventory: the device owner cannot be named from the files.", [first], "PENDING"
        if "which scanned ports answered" in low:
            bits = []
            if sc["allowed"]:
                bits.append("allowed: " + ", ".join(f"{x['ip']}:{x['port']}" for x in sc["allowed"]))
            if sc["denied"]:
                bits.append("denied: " + ", ".join(f"{x['ip']}:{x['port']}" for x in sc["denied"]))
            if sc["probes"]:
                bits.append("web requests that followed: " + ", ".join(f"{x['url']} -> HTTP {x['status']}" for x in sc["probes"]))
            cites = [C(i) for i in sc["events"]]
            nl = sc.get("no_login_claim")
            if nl:
                bits.append("no login attempt from this address in the VPN or domain controller logs")
                cites += nl.citations
            return "; ".join(bits) + ".", cites, "ANSWERED_BY_EVIDENCE"
        if "next 24 hours" in low:
            m = missing("other_dates")
            return f"Only logs of {r.log_date} are available, so later activity from {ip} cannot be checked from these files.", [first] + [x.citation for x in m], "PENDING"
    return None, [], "PENDING"


def actions(ctx: Ctx, built: dict[str, Any]) -> tuple[list[RunbookAction], list[str]]:
    r = ctx.refs
    out: list[RunbookAction] = []
    notes: list[str] = []
    for rb_req in built["runbooks"]:
        rb = r.runbook_for(rb_req["key"])
        if rb is None:
            notes.append(f"No approved runbook exists for '{rb_req['key'].replace('_', ' ')}': no action is recommended for it; escalate per the escalation sheet.")
            continue
        for s in rb.steps:
            try:
                context, cites, status = _bind(ctx, rb_req["key"], s.text, built)
            except Exception as exc:  # noqa: BLE001 - a binding bug must never drop a runbook step
                context, cites, status = None, [], "PENDING"
                notes.append(f"Context for {rb.runbook_id} step {s.no} could not be derived ({type(exc).__name__}).")
            out.append(RunbookAction(runbook_id=rb.runbook_id, step_no=s.no, text=s.text, citation=s.citation, context=context,
                                     context_citations=uniq(cites), status=status,
                                     opened_because=rb_req["reason"] if s.no == rb.steps[0].no else None,
                                     opened_citations=rb_req["citations"] if s.no == rb.steps[0].no else []))
    if any(p["key"] == "prompt_injection" for p in built["parts"]) and not out:
        notes.append("No approved runbook exists for prompt injection in log data: no action is recommended from the runbooks; escalate for a human decision.")
    return out, notes
