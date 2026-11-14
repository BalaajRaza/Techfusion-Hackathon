"""Stage 9 - the three-tier evidence ledger, built per incident.

Every sentence here is produced by code from parsed events and carries the
citations that prove it. Status rules (security rules 2.1 - 2.4):
  CONFIRMED              a log line or table row states it directly
  SUSPECTED              fits a pattern but needs a guess - the guess is written in `rule`
  INSUFFICIENT_EVIDENCE  the logs are silent or the source does not exist
Never-confirmable claims (what was read, who the attacker is, whether a
password was typed) are created as SUSPECTED / INSUFFICIENT by construction.
"""
from __future__ import annotations

import re
from datetime import datetime
from typing import Any, Iterable, Optional

from ..models import CRIT_RANK, Citation, Claim, Event, Finding, Incident, TimelineEntry
from . import timeutil as tu
from .detectors import Ctx, levenshtein
from .references import Asset, IP_RE, is_internal_ip


def uniq(cites: Iterable[Optional[Citation]]) -> list[Citation]:
    seen: set[str] = set()
    out: list[Citation] = []
    for c in cites:
        if c is not None and c.ref not in seen:
            seen.add(c.ref)
            out.append(c)
    return out


def _cit(d: dict[str, Any]) -> Citation:
    return Citation(**d)


class Builder:
    def __init__(self, ctx: Ctx, findings: list[Finding], alert_links: dict[str, dict[str, Any]], near: list[dict[str, Any]]):
        self.ctx = ctx
        self.r = ctx.refs
        self.findings = sorted(findings, key=lambda f: (f.start or datetime.max.replace(tzinfo=tu.UTC), f.id))
        self.alert_links = alert_links
        self.near = near
        self.claims: list[Claim] = []
        self.timeline: list[TimelineEntry] = []
        self.assets: dict[str, dict[str, Any]] = {}
        self.accounts: dict[str, dict[str, Any]] = {}
        self.parts: list[dict[str, Any]] = []
        self.runbooks: list[dict[str, Any]] = []
        self.attacker_ips: list[str] = []
        self.summary: list[tuple[int, str, list[str]]] = []
        self.facts: dict[str, Any] = {}
        self.sessions: list[str] = []
        self.kinds = {f.kind for f in self.findings}
        self.flags: list[str] = []

    # ------------------------------------------------------------ formatting
    def t(self, dt: Optional[datetime]) -> str:
        return tu.fmt_utc(dt)

    def both(self, dt: Optional[datetime]) -> str:
        if dt is None:
            return "unknown time"
        return f"{tu.fmt_utc(dt)} ({tu.fmt_local(dt, self.r.local_tz_hours, self.r.local_tz_label)})"

    def rng(self, a: datetime, b: datetime) -> str:
        return tu.fmt_utc(a) if a == b else f"{tu.fmt_utc(a)[:-4]}-{tu.fmt_utc(b)}"

    def E(self, event_id: str) -> Event:
        return self.ctx.by_id[event_id]

    def C(self, event_id: Optional[str]) -> Optional[Citation]:
        return self.ctx.by_id[event_id].cite() if event_id else None

    def rule(self, no: str) -> Optional[Citation]:
        return self.r.rules.get(no)

    def missing(self, tag: str, host: Optional[str] = None) -> list[Citation]:
        out = [m.citation for m in self.r.missing_sources if tag in m.tags and (host is None or f"host:{host}" in m.tags or not any(t.startswith("host:") for t in m.tags))]
        return out

    def coverage_row(self, source_file: str) -> Optional[Citation]:
        return next((c.citation for c in self.r.coverage if c.file == source_file), None)

    def file_of(self, source_type: str) -> Optional[str]:
        evs = self.ctx.by_type.get(source_type)
        return evs[0].source_file if evs else None

    def asset_cite(self, hostname: Optional[str]) -> Optional[Citation]:
        a = self.r.asset_by_name(hostname)
        return a.citation if a else None

    def user_cite(self, username: Optional[str]) -> Optional[Citation]:
        u = self.r.user(username)
        return u.citation if u else None

    def full_name(self, username: Optional[str]) -> str:
        u = self.r.user(username)
        return f"{u.full_name} ({u.username})" if u else str(username)

    # ------------------------------------------------------------ recorders
    def claim(self, status: str, text: str, cites: Iterable[Optional[Citation]], rule: Optional[str] = None, topic: str = "") -> Claim:
        cl = uniq(cites)
        # the inventory row is the evidence for every hostname <-> address / criticality link
        for a in self.r.assets:
            if re.search(rf"(?<![\w-]){re.escape(a.hostname)}(?![\w-])", text) and a.citation.ref not in {c.ref for c in cl}:
                cl.append(a.citation)
        ents = sorted(set(IP_RE.findall(text)) | {u.username for u in self.r.users if re.search(rf"\b{u.username}\b", text)}
                      | {a.hostname for a in self.r.assets if a.hostname in text})
        c = Claim(claim_id=f"C{len(self.claims) + 1}", text=text, status=status, rule=rule, citations=cl, entities=ents, topic=topic)
        self.claims.append(c)
        return c

    def tl(self, ts: Optional[datetime], label: str, detail: str, cites: Iterable[Optional[Citation]], status: str = "CONFIRMED",
           phase: str = "", end: Optional[datetime] = None) -> None:
        if ts is None:
            return
        cites = uniq(cites)
        for a in self.r.assets:
            if re.search(rf"(?<![\w-]){re.escape(a.hostname)}(?![\w-])", label + " " + detail) and a.citation.ref not in {c.ref for c in cites}:
                cites.append(a.citation)
        self.timeline.append(TimelineEntry(ts_utc=ts, ts_end_utc=end if end and end != ts else None, label=label, detail=detail,
                                           phase=phase, status=status, citations=uniq(cites)))

    def asset(self, hostname: Optional[str], role: str, reached: Optional[bool], basis: str, cites: Iterable[Optional[Citation]]) -> None:
        a = self.r.asset_by_name(hostname)
        key = a.hostname if a else str(hostname)
        cur = self.assets.get(key)
        entry = dict(hostname=key, tag=a.tag if a else None, type=a.type if a else None, criticality=a.criticality if a else None,
                     owner=a.owner if a else None, in_inventory=bool(a), roles=[role], reached=reached, basis=[basis],
                     citations=uniq(list(cites) + ([a.citation] if a else [])))
        if cur:
            cur["roles"] = list(dict.fromkeys(cur["roles"] + [role]))
            cur["basis"] = list(dict.fromkeys(cur["basis"] + [basis]))
            cur["reached"] = bool(cur["reached"]) or bool(reached) if (cur["reached"] is not None or reached is not None) else None
            cur["citations"] = uniq(cur["citations"] + entry["citations"])
        else:
            self.assets[key] = entry

    def account(self, username: Optional[str], role: str, cites: Iterable[Optional[Citation]]) -> None:
        if not username:
            return
        u = self.r.user(username)
        cur = self.accounts.setdefault(username, dict(username=username, full_name=u.full_name if u else None, role_in_company=u.role if u else None,
                                                      phone=u.phone if u else None, in_directory=bool(u), roles=[], citations=[]))
        cur["roles"] = list(dict.fromkeys(cur["roles"] + [role]))
        cur["citations"] = uniq(cur["citations"] + list(cites) + ([u.citation] if u else []))

    def part(self, key: str, label: str, hosts: list[str], cites: Iterable[Optional[Citation]], note: Optional[str] = None,
             first_seen: Optional[datetime] = None, first_seen_basis: str = "") -> None:
        cur = next((p for p in self.parts if p["key"] == key and p["label"] == label), None)
        if cur:
            cur["hosts"] = list(dict.fromkeys(cur["hosts"] + hosts))
            cur["citations"] = uniq(cur["citations"] + list(cites))
            if first_seen and (cur["first_seen"] is None or first_seen < cur["first_seen"]):
                cur["first_seen"], cur["first_seen_basis"] = first_seen, first_seen_basis
        else:
            self.parts.append(dict(key=key, label=label, hosts=hosts, citations=uniq(cites), note=note, first_seen=first_seen, first_seen_basis=first_seen_basis))

    def open_runbook(self, key: str, reason: str, cites: Iterable[Optional[Citation]]) -> None:
        if not any(rb["key"] == key for rb in self.runbooks):
            self.runbooks.append(dict(key=key, reason=reason, citations=uniq(cites)))

    def say(self, order: int, text: str, claims: list[Claim]) -> None:
        self.summary.append((order, text, [c.claim_id for c in claims]))

    def alert_time(self, f: Finding) -> tuple[Optional[datetime], str]:
        alerts = sorted((self.E(a) for a in f.alert_ids), key=lambda e: e.ts_utc)
        if alerts:
            return alerts[0].ts_utc, f"IDS alert {alerts[0].fields.get('alert_id')}"
        return f.start, "first log event (no IDS alert)"

    # ============================================================ handlers
    def h_phishing_delivery(self, f: Finding) -> None:
        d, r = f.data, self.r
        evs = [self.E(i) for i in f.event_ids]
        first, last = min(e.ts_utc for e in evs), max(e.ts_utc for e in evs)
        names = [x["user"] or x["to"] for x in d["recipients"]]
        cites: list[Optional[Citation]] = [e.cite() for e in evs]
        text = (f"Email {d['msgid']} from {d['sender']} with the link host {d['url_host']} was delivered to {len(evs)} mailbox(es) "
                f"({', '.join(names)}) at {self.rng(first, last)} ({tu.fmt_local(first, r.local_tz_hours, r.local_tz_label)}); "
                f"SPF={d['spf']}, DKIM={d['dkim']}, spam score {d['score']}.")
        if r.quarantine_score is not None and d["score"] is not None and d["score"] < r.quarantine_score and d["delivered"]:
            text += f" The score is below the gateway's quarantine threshold of {r.quarantine_score}, so the message was not quarantined."
            cites.append(r.quarantine_score_citation)
        c1 = self.claim("CONFIRMED", text, cites, topic="phish_delivery")
        self.tl(first, "Phishing email delivered", f"{d['msgid']} from {d['sender']} to {', '.join(names)}", [e.cite() for e in evs], phase="Delivery", end=last)
        if d["lookalike"] and r.company_email_domain:
            norm = lambda s: re.sub(r"[^a-z0-9]", "", s.lower())  # noqa: E731
            k = levenshtein(norm(d["sender_domain"]), norm(r.company_email_domain))
            self.claim("CONFIRMED", f"The sender domain {d['sender_domain']} is not the company mail domain {r.company_email_domain}; "
                                    f"ignoring punctuation it differs by {k} character(s) (a look-alike spelling).",
                       [evs[0].cite(), self.user_cite(names[0])], topic="phish_lookalike")
        for u in names:
            clicked = any(c["user"] == u for c in d["clicks"])
            self.account(u, "phishing recipient - connection to the link host seen" if clicked else "phishing recipient - no click seen",
                         [e.cite() for e in evs if e.user_account == u])
        edge_file = self.file_of("fw_edge")
        link_ip = d["link_ips"][0] if d["link_ips"] else None
        nc_hosts = []
        for nc in d["no_click"]:
            if not link_ip:
                continue
            nc_hosts.append(nc["laptop"])
            self.claim("CONFIRMED", f"No click is seen for {nc['user']}: the perimeter firewall log, which covers the full day, has no connection "
                                    f"from {nc['laptop']} ({nc['laptop_ip']}) to {link_ip}.",
                       [self.coverage_row(edge_file) if edge_file else None, self.asset_cite(nc["laptop"]), self.user_cite(nc["user"])]
                       + [self.C(a) for a in d["intel_alerts"]] + [self.C(x) for x in nc["other_outbound"][:2]], topic="phish_no_click")
        if d["no_click"]:
            users = ", ".join(nc["user"] for nc in d["no_click"])
            self.claim("INSUFFICIENT_EVIDENCE", f"Whether {users} opened the link on a phone or another network that Orbit does not log cannot be determined.",
                       self.missing("proxy") + self.missing("edr") + [self.user_cite(nc["user"]) for nc in d["no_click"]],
                       rule="No web proxy log and no laptop endpoint (EDR) log exist.", topic="phish_no_click_gap")
            self.part("phishing_no_click", "Phishing email delivered, no click seen", nc_hosts, [e.cite() for e in evs], note=f"Recipients with no click seen: {users}. " + " ".join(f"[{self.user_cite(nc['user']).ref}]" for nc in d["no_click"] if self.user_cite(nc["user"])),
                      first_seen=first, first_seen_basis="email delivery time (no IDS alert for the delivery itself)")
        if not link_ip:
            self.claim("INSUFFICIENT_EVIDENCE", f"No log ties the link host {d['url_host']} to an IP address, so the firewall logs cannot show who clicked.",
                       [evs[0].cite()] + self.missing("proxy"), topic="phish_no_intel")
        self.open_runbook("phishing", f"phishing email {d['msgid']} delivered", [evs[0].cite()])
        ph = self.facts.setdefault("phish", {})
        ph.update(msgid=d["msgid"], sender_domain=d["sender_domain"], url_host=d["url_host"], recipients=names, emails=[x["to"] for x in d["recipients"]],
                  events=f.event_ids, clicks=d["clicks"], no_click=d["no_click"], link_ip=link_ip, intel=d["intel_alerts"], claim=c1)
        if not d["clicks"]:
            self.say(10, f"Phishing email {d['msgid']} from the look-alike sender {d['sender']} was delivered to {', '.join(names)} at {self.t(first)}; no click is seen in the firewall log.", [c1])

    def h_phishing_click(self, f: Finding) -> None:
        d, r = f.data, self.r
        e = self.E(d["event"])
        delivered = self.E(d["delivered_event"])
        binding = [_cit(c) for c in d["binding"]]
        intel = [self.C(a) for a in d["intel_alerts"]]
        c1 = self.claim("CONFIRMED", f"At {self.both(e.ts_utc)} the address {d['src_ip']} opened an outbound connection to {d['dst_ip']}:{e.fields.get('dport')} "
                                     f"({tu.fmt_bytes(e.fields.get('bytes') or 0)}). At that time {d['src_ip']} was held by {d['laptop']} (DHCP lease), "
                                     f"the laptop assigned to {self.full_name(d['user'])}.", [e.cite()] + binding, topic="click")
        for a in d["intel_alerts"]:
            al = self.E(a)
            self.claim("CONFIRMED", f"IDS alert {al.fields['alert_id']} at {self.t(al.ts_utc)} reports that {d['dst_ip']} hosts the domain {d['url_host']}, "
                                    f"which is the link host in email {d['msgid']}.", [al.cite(), delivered.cite()], topic="click_intel")
        self.tl(e.ts_utc, f"{d['laptop']} connects to the phishing link host", f"{d['src_ip']} -> {d['dst_ip']}:{e.fields.get('dport')}", [e.cite()] + binding[:1] + intel, phase="Click")
        c2 = self.claim("SUSPECTED", f"{d['user']} opened the phishing link: {d['laptop']} ({d['src_ip']}) connected to {d['dst_ip']} "
                                     f"{tu.fmt_span(d['delay_s'])} after the email arrived.", [e.cite(), delivered.cite()] + intel + binding + self.missing("proxy"),
                        rule=(f"Guess needed: that this connection was the user opening the link in the email. The only tie between {d['dst_ip']} and "
                              f"{d['url_host']} is the threat-intel note in the IDS alert; no web proxy log exists to show the URL."), topic="click_suspected")
        self.claim("INSUFFICIENT_EVIDENCE", f"What {d['user']} did on the page (for example whether a password was typed in) is not shown by any log.",
                   self.missing("proxy") + self.missing("edr") + [self.user_cite(d["user"])], rule="No web proxy log and no laptop endpoint (EDR) log exist.", topic="click_gap")
        self.claim("INSUFFICIENT_EVIDENCE", f"Whether {d['laptop']} was infected with malware cannot be determined.", self.missing("edr"),
                   rule="Laptop endpoint security (EDR) logs are not collected.", topic="malware_gap")
        self.asset(d["laptop"], "laptop that connected to the phishing link host", False, "outbound connection only - not reached by the attacker", [e.cite()] + binding)
        self.account(d["user"], "owner of the laptop that connected to the phishing link host", [e.cite()])
        note = next((c for c in r.matrix_notes if re.search(r"click is seen", c.text, re.I)), None)
        rb = r.runbook_for("phishing")
        step = next((s.citation for s in rb.steps if re.search(r"click is found", s.text, re.I)), None) if rb else None
        self.open_runbook("phishing", f"phishing email {d['msgid']} delivered", [delivered.cite()])
        self.open_runbook("credential_compromise", f"a click is seen for {d['user']}: the matrix handles it as credential compromise and the phishing runbook opens the credential runbook",
                          [note, step, e.cite(), self.user_cite(d["user"])])
        self.facts.setdefault("click_claims", []).extend([c1, c2])
        self.facts["click"] = dict(d, ts=e.ts_utc, first_seen=self.alert_time(f))

    def _session_story(self, sid: Optional[str], user: Optional[str], auth: Event, d: dict[str, Any], suspect: bool) -> list[Claim]:
        """What the logs show a VPN session doing inside the network."""
        r = self.r
        out: list[Claim] = []
        if not sid or sid in self.sessions:
            return out
        self.sessions.append(sid)
        ip = d.get("assigned_ip")
        dc = [self.E(i) for i in d.get("session_dc", [])]
        fw = [self.E(i) for i in d.get("session_fw", [])]
        reached: dict[str, dict[str, Any]] = {}

        tick = [e for e in dc if e.action in ("kerberos_tgt", "kerberos_service_ticket")]
        if tick:
            bits = []
            for e in tick:
                if e.action == "kerberos_tgt":
                    bits.append(f"a Kerberos TGT at {self.t(e.ts_utc)}")
                    self.tl(e.ts_utc, "Kerberos TGT for the VPN session", f"{user} from {ip}", [e.cite()], phase="Internal access")
                else:
                    spn = str(e.fields.get("service", ""))
                    host = r.asset_by_name(spn.split("/", 1)[1]) if "/" in spn else None
                    bits.append(f"a service ticket for {spn}" + (f" ({host.hostname})" if host else "") + f" at {self.t(e.ts_utc)}")
                    self.tl(e.ts_utc, f"Service ticket for {host.hostname if host else spn}", f"{spn} requested from {ip}", [e.cite()], phase="Internal access")
                    if host:
                        reached.setdefault(host.hostname, dict(tickets=[], sessions=[], logons=[]))["tickets"].append(e)
            out.append(self.claim("CONFIRMED", f"From {ip}, the address of VPN session {sid}, the account {user} requested " + ", ".join(bits) + ".",
                                  [e.cite() for e in tick] + [auth.cite(), r.internal_domain_citation], topic="session_tickets"))
        for e in dc:
            if e.action in ("logon", "rdp_logon") and e.outcome == "SUCCESS":
                host = r.asset_by_name(e.fields.get("target")) or r.asset_by_name(e.host)
                if host:
                    reached.setdefault(host.hostname, dict(tickets=[], sessions=[], logons=[]))["logons"].append(e)
        if fw:
            bits = []
            for e in fw:
                host = r.asset_by_ip(e.ip_dest)
                when = self.rng(e.start, e.end) if e.end else self.t(e.start)
                bits.append(f"{e.ip_dest}:{e.fields.get('dport')} ({host.hostname if host else 'not in the inventory'}) {when}, {e.outcome}, {tu.fmt_bytes(e.fields.get('bytes') or 0)}")
                if host and e.outcome == "ALLOW":
                    reached.setdefault(host.hostname, dict(tickets=[], sessions=[], logons=[]))["sessions"].append(e)
                big = (e.fields.get("bytes") or 0) >= 1_000_000_000
                if not big:
                    self.tl(e.start, f"Session to {host.hostname if host else e.ip_dest}:{e.fields.get('dport')}", f"{ip} -> {e.ip_dest}:{e.fields.get('dport')}, {tu.fmt_bytes(e.fields.get('bytes') or 0)}",
                            [e.cite()], phase="Internal access", end=e.end)
            fw_file = fw[0].source_file
            out.append(self.claim("CONFIRMED", f"The internal firewall recorded these sessions from {ip} while session {sid} was open: " + "; ".join(bits) + ".",
                                  [e.cite() for e in fw] + [auth.cite(), self.coverage_row(fw_file)],
                                  rule="The internal firewall logs in local time when a session closes; start = close time minus duration, converted to UTC.", topic="session_fw"))
        if not dc and not fw:
            out.append(self.claim("CONFIRMED", f"No domain-controller event and no internal-firewall session from {ip} appears while session {sid} was open.",
                                  [auth.cite(), self.coverage_row(self.file_of("dc") or ""), self.coverage_row(self.file_of("fw_int") or "")], topic="session_quiet"))

        for hostname, ev in reached.items():
            a = r.asset_by_name(hostname)
            is_dc = bool(a and re.search(r"domain controller", a.type, re.I))
            auth_only = is_dc and not ev["logons"] and all((s.fields.get("dport") in (88, 389, 464, 636)) for s in ev["sessions"])
            cites = [x.cite() for x in ev["sessions"] + ev["tickets"] + ev["logons"]]
            if auth_only:
                ports = sorted({s.fields.get("dport") for s in ev["sessions"]})
                self.asset(hostname, f"authentication requests from session {sid}", False,
                           f"only Kerberos / directory traffic (port {', '.join(map(str, ports))}) - no logon ON this server by the account (no EventID 4624 for it)", cites)
            else:
                ports = sorted({s.fields.get("dport") for s in ev["sessions"]})
                basis = (f"allowed session(s) to port {', '.join(map(str, ports))}" if ev["sessions"] else "service ticket only - no session seen in the firewall log")
                if ev["logons"]:
                    basis = "interactive / remote logon recorded by the domain controller"
                self.asset(hostname, f"accessed from VPN session {sid}", bool(ev["sessions"] or ev["logons"]), basis, cites)
        self.facts.setdefault("session_reached", {})[sid] = reached
        return out

    def h_mfa_fatigue(self, f: Finding) -> None:
        d, r = f.data, self.r
        fails = [self.E(i) for i in d["fails"]]
        ok = self.E(d["success"])
        u, ip, geo, sid = d["user"], d["src_ip"], d["geo"], d["session"]
        reasons = ", ".join(f"{n}x {k}" for k, n in d["fail_reasons"].items())
        c1 = self.claim("CONFIRMED", f"{len(fails)} VPN logins for {u} from {ip} (geo {geo}) failed between {self.t(fails[0].ts_utc)} and {self.t(fails[-1].ts_utc)}: {reasons}.",
                        [e.cite() for e in fails], topic="mfa_fails")
        c2 = self.claim("CONFIRMED", f"At {self.both(ok.ts_utc)} the VPN login for {u} from {ip} (geo {geo}) succeeded with mfa={ok.fields.get('mfa')}; "
                                     f"session {sid} was given the address {d['assigned_ip']}.", [ok.cite()], topic="vpn_success")
        others = [e for e in self.ctx.ev("vpn") if e.action == "vpn_auth" and e.outcome == "SUCCESS" and e.id != ok.id]
        if d["home_geo"] and others and all(e.fields.get("geo") == d["home_geo"] for e in others):
            self.claim("CONFIRMED", f"Every other successful VPN login in the log came from geo {d['home_geo']}; this is the only one from geo {geo}.",
                       [e.cite() for e in others] + [ok.cite()], topic="geo")
        if d["edge_events"]:
            edge = [self.E(i) for i in d["edge_events"]]
            self.claim("CONFIRMED", f"The perimeter firewall shows {ip} connecting to {edge[0].ip_dest}:{edge[0].fields.get('dport')}, the public address of {d['vpn_asset']}, at "
                                    + " and ".join(self.t(e.ts_utc) for e in edge) + ".", [e.cite() for e in edge], topic="vpn_edge")
        self.tl(fails[0].ts_utc, f"{len(fails)} rejected MFA pushes for {u}", f"VPN logins from {ip} (geo {geo}): {reasons}", [e.cite() for e in fails], phase="Credential use", end=fails[-1].ts_utc)
        self.tl(ok.ts_utc, f"VPN login approved for {u} from geo {geo}", f"session {sid}, address {d['assigned_ip']}, source {ip}", [ok.cite()], phase="Credential use")
        new_country = [self.C(a) for a in f.alert_ids if re.search(r"new country", str(self.E(a).fields.get("description")), re.I)]
        c3 = self.claim("SUSPECTED", f"The password of {u} was known to whoever logged in from {ip}, and the approved push at {self.t(ok.ts_utc)} was not a genuine login by the account owner.",
                        [e.cite() for e in fails] + [ok.cite(), self.rule("6.1")] + new_country,
                        rule=("Rule 6.1: several rejected MFA pushes followed by an approved push from a new country is treated as a sign of a stolen password. "
                              "Guess needed: that the owner approved the last push by mistake or under pressure - the logs do not show who approved it."), topic="cred_suspected")
        self.account(u, f"account used for the VPN login from {ip}", [ok.cite()])
        self.asset(d["vpn_asset"], f"VPN gateway - login by session {sid}", True, "successful VPN login", [ok.cite()])
        if ip and ip not in self.attacker_ips:
            self.attacker_ips.append(ip)
        story = self._session_story(sid, u, ok, d, suspect=True)
        if d["session_end"]:
            end = self.E(d["session_end"])
            self.claim("CONFIRMED", f"Session {sid} ended at {self.t(end.ts_utc)} after {d['duration_s']} s; the VPN gateway counted {tu.fmt_bytes(d['bytes_to_client'] or 0)} "
                                    f"sent to the client and {tu.fmt_bytes(d['bytes_from_client'] or 0)} received from it.", [end.cite()], topic="session_end")
            self.tl(end.ts_utc, f"VPN session {sid} ends", f"duration {d['duration_s']} s, {tu.fmt_bytes(d['bytes_to_client'] or 0)} to client", [end.cite()], phase="Session end")
        self.open_runbook("credential_compromise", f"rejected MFA pushes then an approved VPN login for {u} from a new country (rule 6.1)", [ok.cite(), self.rule("6.1")])
        seen, basis = self.alert_time(f)
        self.facts.setdefault("cred", []).append(dict(user=u, src_ip=ip, geo=geo, session=sid, assigned_ip=d["assigned_ip"], success=ok.id, fails=d["fails"],
                                                      session_end=d["session_end"], session_end_ts=d["session_end_ts"], session_start=ok.ts_utc,
                                                      first_seen=seen, first_seen_basis=basis, suspected_only=False))
        self.say(20, f"The account {u} was used for a VPN login from {ip} (geo {geo}) at {self.t(ok.ts_utc)} after {len(fails)} rejected MFA pushes.", [c1, c2])
        self.facts["cred_claims"] = [c2, c3] + story

    def h_large_transfer(self, f: Finding) -> None:
        d, r = f.data, self.r
        e = self.E(d["event"])
        server = d["server"] or d["server_ip"]
        a = r.asset_by_name(d["server"])
        s2c = d["bytes_server_to_client"]
        direction = f", of which {tu.fmt_bytes(s2c)} went from the server to the client" if s2c else ""
        c1 = self.claim("CONFIRMED", f"One session from {d['client_ip']} to {d['server_ip']}:{d['port']} ({server}) ran from {self.t(e.start)} to {self.t(e.end)} "
                                     f"and carried {tu.fmt_bytes(d['bytes'])} in total{direction}.", [e.cite(), self.coverage_row(e.source_file)],
                        rule=f"The internal firewall logs in local time when a session closes: close {e.ts_original} local = {self.t(e.ts_utc)}; start = close minus {d['duration_s']} s.",
                        topic="transfer")
        claims = [c1]
        if d["session"]:
            end = self.E(d["session_end"]) if d["session_end"] else None
            auth = self.E(d["session_auth"])
            txt = f"{d['client_ip']} was the address of VPN session {d['session']} (account {d['client_user']}, source {d['session_src_ip']})."
            if end and d["vpn_bytes_to_client"]:
                txt += (f" When that session ended the VPN gateway had sent {tu.fmt_bytes(d['vpn_bytes_to_client'])} to the client, so the transferred data "
                        f"left {server} for the remote VPN client.")
            claims.append(self.claim("CONFIRMED", txt, [auth.cite(), end.cite() if end else None, e.cite()], topic="transfer_vpn"))
        self.tl(e.start, f"Large transfer from {server}", f"{tu.fmt_bytes(d['bytes'])} over port {d['port']} to {d['client_ip']}", [e.cite()], phase="Impact", end=e.end)
        row = r.matrix_row("data_exfiltration")
        who = f"the person using session {d['session']}" if d["session"] else f"whoever used {d['client_ip']}"
        c3 = self.claim("SUSPECTED", f"The transfer was business data being taken from {server}" + (f" ({a.type})" if a else "") + f" by {who}.",
                        [e.cite(), self.rule("2.4"), row.citation if row else None],
                        rule=("The transfer itself is confirmed. That it was a theft of business data is a guess: rule 2.4 says a large transfer is evidence of a transfer, "
                              "not of which files were read."), topic="exfil_suspected")
        audit = self.missing("file_audit", d["server"])
        c4 = self.claim("INSUFFICIENT_EVIDENCE", f"Which files or folders on {server} were read or copied is unknown.", audit or [e.cite()],
                        rule=f"No file access (audit) log exists for {server}." if audit else "The provided files contain no file-level audit log.", topic="files_gap")
        self.claim("INSUFFICIENT_EVIDENCE", "Whether the data was copied onward from the remote client to anywhere else is unknown.",
                   [self.C(d["session_end"]) if d["session_end"] else e.cite()] + self.missing("other_dates"),
                   rule="The logs stop at the VPN gateway; nothing records what the remote client did with the data.", topic="onward_gap")
        self.asset(server, "source of the large transfer", True, f"allowed session carrying {tu.fmt_bytes(d['bytes'])}", [e.cite()])
        seen, basis = self.alert_time(f)
        self.part("data_exfiltration", "Data exfiltration (large transfer)", [server], [e.cite()], first_seen=seen, first_seen_basis=basis)
        cred = r.runbook_for("credential_compromise")
        step = next((s.citation for s in cred.steps if re.search(r"large data transfer", s.text, re.I)), None) if cred else None
        self.open_runbook("data_exfiltration", f"a large data transfer is seen from {server}", [step, e.cite()])
        self.facts["transfer"] = dict(d, start=e.start, end=e.end, server_name=server)
        self.say(30, f"About {d['bytes'] / 1e9:.2f} GB moved from {server} to {d['client_ip']}" + (f" (VPN session {d['session']})" if d["session"] else "")
                 + f" between {self.t(e.start)} and {self.t(e.end)}.", claims)
        self.say(60, f"Suspected: the transfer was business data being taken from {server}. Not enough evidence: which files were read is unknown.", [c3, c4])

    def h_password_reset(self, f: Finding) -> None:
        d = f.data
        e = self.E(d["event"])
        via = f", the address of VPN session {d['session']}" if d["session"] else ""
        sess = self.ctx.graph.session(d["session"])
        c1 = self.claim("CONFIRMED", f"At {self.both(e.ts_utc)} the password of {d['user']} was reset (EventID 4724, caller {d['caller']}, result {d['result']}) from {d['client_ip']}{via}.",
                        [e.cite(), self.C(sess.auth_event) if sess else None], topic="pw_reset")
        self.tl(e.ts_utc, f"Password of {d['user']} reset from the VPN session" if d["session"] else f"Password of {d['user']} reset", f"caller {d['caller']}, client {d['client_ip']}", [e.cite()], phase="Persistence")
        if d["notice"]:
            n = self.E(d["notice"])
            self.claim("CONFIRMED", f"The email gateway delivered the notice \"{n.fields.get('subject')}\" to {n.fields.get('to')} at {self.t(n.ts_utc)}.", [n.cite()], topic="pw_notice")
        self.account(d["user"], "password reset during the incident", [e.cite()])
        self.facts["reset"] = dict(d, ts=e.ts_utc, claim=c1)

    def h_lockout(self, f: Finding) -> None:
        d = f.data
        fails = [self.E(i) for i in d["fails"]]
        lock = self.E(d["lock"])
        binding = [_cit(c) for c in d["binding"]]
        src = f" from {d['src_host']} ({d['src_ip']})" if d["src_host"] else (f" from {d['src_ip']}" if d["src_ip"] else "")
        when = " and ".join(self.t(e.ts_utc) for e in fails)
        c1 = self.claim("CONFIRMED", f"{len(fails)} logon(s) for {d['user']}{src} failed with {', '.join(d['reasons'])} at {when}, and the account was locked out at {self.t(lock.ts_utc)}.",
                        [e.cite() for e in fails] + [lock.cite()] + binding[:2], topic="lockout")
        self.tl(fails[0].ts_utc if fails else lock.ts_utc, f"Failed logons and lockout for {d['user']}", f"{len(fails)} bad-password logons{src}, lockout at {self.t(lock.ts_utc)}",
                [e.cite() for e in fails] + [lock.cite()], phase="Aftermath", end=lock.ts_utc)
        reset = self.facts.get("reset")
        if reset and reset["user"] == d["user"] and reset["ts"] < lock.ts_utc and reset.get("session"):
            gap = (fails[0].ts_utc if fails else lock.ts_utc) - reset["ts"]
            c2 = self.claim("SUSPECTED", f"The password reset at {self.t(reset['ts'])} was made by the person using session {reset['session']}, and the failed logons and lockout "
                                         f"were the real {d['user']} typing the old password{src}.",
                            [self.C(reset["event"]), lock.cite()] + [e.cite() for e in fails] + binding[:1],
                            rule=(f"Guess needed: no log says who typed the passwords. The reset came from the VPN session address; the failures came {tu.fmt_span(gap.total_seconds())} later "
                                  "from the owner's own laptop on the office network."), topic="lockout_suspected")
            self.say(40, f"The password of {d['user']} was reset from the VPN session at {self.t(reset['ts'])}, and the account was locked out at {self.t(lock.ts_utc)} after failed logons from the owner's laptop.",
                     [reset["claim"], c1, c2])
        self.facts["lockout"] = dict(d, ts=lock.ts_utc)

    def h_concurrent_login(self, f: Finding) -> None:
        d, r = f.data, self.r
        auth = self.E(d["auth"])
        u, sid = d["user"], d["session"]
        end_txt = self.t(d["session_end_ts"]) if d["session_end_ts"] else "the end of the log"
        if f.primary:
            c1 = self.claim("CONFIRMED", f"VPN session {sid} for {u} was open from {self.t(d['session_start'])} to {end_txt}, from {d['src_ip']} (geo {d['geo']}, mfa={d['mfa']}); "
                                         f"it was given the address {d['assigned_ip']}.", [auth.cite(), self.C(d["session_end"])], topic="cc_session")
            self.tl(auth.ts_utc, f"VPN login for {u}", f"session {sid} from {d['src_ip']} (geo {d['geo']}), {d['mfa']}", [auth.cite()], phase="Remote session")
            pieces, cites = [], []
            for i in d["strict"]:
                e = self.E(i)
                res = self.ctx.graph.resolve(e.ip_source, e.ts_utc)
                pieces.append(f"at {self.t(e.ts_utc)} from {e.ip_source} ({res.hostname or 'unknown host'})")
                cites += [e.cite()] + res.citations
                self.tl(e.ts_utc, f"Office logon for {u} while the VPN session is open", f"{e.fields.get('description')} from {e.ip_source} ({res.hostname})", [e.cite()] + res.citations[:1], phase="Office logon")
            c2 = self.claim("CONFIRMED", f"While that session was open, {u} also logged on to the domain on the office network " + " and ".join(pieces) + ".", cites, topic="cc_office")
            fails = [e for e in self.ctx.ev("vpn") if e.action == "vpn_auth" and e.outcome == "FAIL" and e.user_account == u]
            if not fails:
                self.claim("CONFIRMED", f"No failed or rejected VPN login for {u} appears in the VPN log; the login was approved on the first push.",
                           [auth.cite(), self.coverage_row(auth.source_file)], topic="cc_no_fail")
            self._session_story(sid, u, auth, d, suspect=False)
            if d["session_end"]:
                end = self.E(d["session_end"])
                self.tl(end.ts_utc, f"VPN session {sid} ends", f"{tu.fmt_bytes(d['bytes_to_client'] or 0)} sent to the client", [end.cite()], phase="Remote session")
            c3 = self.claim("SUSPECTED", f"The account {u} was used from two places at the same time, which rule 6.2 names as a sign of account misuse.",
                            [auth.cite(), self.rule("6.2")] + cites,
                            rule=("Rule 6.2. Guess needed: that the two logins were made by different people. A user who leaves a home VPN session open and then "
                                  "works from the office produces the same pattern."), topic="cc_suspected")
            c4 = self.claim("INSUFFICIENT_EVIDENCE", f"Whether both logins were made by {self.full_name(u)} cannot be told from the logs.", [self.user_cite(u), auth.cite()],
                            rule="Only the account owner can confirm it (the credential runbook starts by calling the user).", topic="cc_gap")
            self.account(u, "account logged in from two places at the same time (rule 6.2)", [auth.cite()])
            vpn_asset = auth.fields.get("file_asset")
            self.asset(vpn_asset, f"VPN gateway - login by session {sid}", True, "successful VPN login", [auth.cite()])
            self.open_runbook("credential_compromise", f"two logins by {u} from different places at the same time (rule 6.2)", [auth.cite(), self.rule("6.2")])
            self.facts.setdefault("cred", []).append(dict(user=u, src_ip=d["src_ip"], geo=d["geo"], session=sid, assigned_ip=d["assigned_ip"], success=auth.id, fails=[],
                                                          session_end=d["session_end"], session_end_ts=d["session_end_ts"], session_start=auth.ts_utc,
                                                          first_seen=f.start, first_seen_basis="first log event (no IDS alert)", suspected_only=True))
            self.say(20, f"The account {u} had VPN session {sid} open from {d['src_ip']} ({self.t(d['session_start'])} to {end_txt}) while it also logged on from the office network.", [c1, c2])
            self.say(60, "Suspected only: rule 6.2 names this pattern as a sign of account misuse, but the logs cannot show whether one person made both logins.", [c3, c4])
        for item in d["lease"]:
            e = self.E(item["event"])
            lease = _cit(item["lease"])
            res = self.ctx.graph.resolve(e.ip_source, e.ts_utc)
            lease_end = datetime.fromisoformat(item["lease_end"]) if isinstance(item["lease_end"], str) else item["lease_end"]
            self.claim("SUSPECTED", f"{u} appears in two places: the office laptop {res.hostname} ({e.ip_source}) logged on at {self.t(e.ts_utc)} and held its DHCP lease until "
                                    f"{self.t(lease_end)}, while VPN session {sid} was opened from {d['src_ip']} (geo {d['geo']}) at {self.t(d['session_start'])}.",
                       [e.cite(), lease, auth.cite(), self.rule("6.2")],
                       rule=("Rule 6.2: two logins by the same user from different places at the same time is a sign of account misuse. Guess needed: that the owner was still "
                             "at the office laptop - the lease shows the laptop on the office network, not the person."), topic="two_places")

    def h_web_attack(self, f: Finding) -> None:
        d, r = f.data, self.r
        reqs = d["requests"]
        evs = [self.E(x["event"]) for x in reqs]
        ip, asset = d["src_ip"], d["asset"] or "the web server"
        pats = list(dict.fromkeys(p for x in reqs for p in x["patterns"]))
        c1 = self.claim("CONFIRMED", f"{ip} sent {len(reqs)} requests carrying SQL injection patterns ({', '.join(pats)}) to {', '.join(d['paths'])} on {asset} between "
                                     f"{self.t(evs[0].ts_utc)} and {self.both(evs[-1].ts_utc)}; User-Agent: {', '.join(d['user_agents'])}.", [e.cite() for e in evs], topic="web_requests")
        self.tl(evs[0].ts_utc, f"SQL injection requests against {asset} begin", f"{len(reqs)} requests from {ip} to {', '.join(d['paths'])}", [e.cite() for e in evs], phase="Attack", end=evs[-1].ts_utc)
        success = [self.E(i) for i in d["success"]]
        failed = [e for e in evs if e.fields["status"] >= 400]
        claims = [c1]
        if failed:
            codes = ", ".join(sorted({str(e.fields["status"]) for e in failed}))
            sizes = ", ".join(sorted({f"{e.fields['bytes']:,}" for e in failed}))
            txt = f"{len(failed)} of the {len(reqs)} requests were answered with HTTP {codes} and {sizes} bytes."
            cites = [e.cite() for e in failed]
            for s in success:
                txt += f" The request \"{s.fields['url_decoded']}\" at {self.t(s.ts_utc)} was answered with HTTP {s.fields['status']} and {s.fields['bytes']:,} bytes."
                cites.append(s.cite())
            claims.append(self.claim("CONFIRMED", txt, cites, topic="web_responses"))
        if d["edge_events"]:
            edge = [self.E(i) for i in d["edge_events"]]
            self.claim("CONFIRMED", "The perimeter firewall allowed " + "; ".join(f"a connection from {ip} to {e.ip_dest}:{e.fields.get('dport')} at {self.t(e.ts_utc)} carrying {tu.fmt_bytes(e.fields.get('bytes') or 0)}" for e in edge)
                       + f". {edge[0].ip_dest} is the public address of {asset}.", [e.cite() for e in edge], topic="web_edge")
        web_file = evs[0].source_file
        later = [e for e in self.ctx.ev("web") if e.ip_source == ip and e.ts_utc > evs[-1].ts_utc]
        if not later:
            self.claim("CONFIRMED", f"The web server log, which covers the full day, has no request from {ip} after {self.t(evs[-1].ts_utc)}.", [evs[-1].cite(), self.coverage_row(web_file)], topic="web_after")
        rb = r.runbook_for("web_attack")
        step3 = next((s.citation for s in rb.steps if re.search(r"large 200", s.text, re.I)), None) if rb else None
        seen, basis = self.alert_time(f)
        if success:
            s = success[0]
            self.tl(s.ts_utc, "Injection request answered with a large HTTP 200", f"{s.fields['bytes']:,} bytes (errors were {d['baseline_error_bytes']:,} bytes)", [s.cite()], status="SUSPECTED", phase="Attack")
            c3 = self.claim("SUSPECTED", f"The SQL injection from {ip} succeeded and the response at {self.t(s.ts_utc)} returned data from the application's database.",
                            [s.cite(), step3] + [e.cite() for e in failed[:1]],
                            rule=(f"Web runbook step 3: a large 200 response to an attack request may mean success. The body was {s.fields['bytes']:,} bytes against "
                                  f"{d['baseline_error_bytes']:,} bytes for the failed attempts. Guess needed: that the body held query results - the web log records only the size."),
                            topic="web_success_suspected")
            c4 = self.claim("INSUFFICIENT_EVIDENCE", f"What the {s.fields['bytes']:,}-byte response contained (for example usernames or passwords) is unknown.", [s.cite()],
                            rule="The web server log records response size, not content.", topic="web_content_gap")
            db = self.missing("db")
            if db:
                self.claim("INSUFFICIENT_EVIDENCE", "Whether the injected SQL reached a database server, and what it read there, cannot be checked.", db,
                           rule="The database login and query log is not forwarded to the SOC.", topic="web_db_gap")
            self.part("web_attack_success", "Web application attack, success suspected", [asset], [s.cite()], first_seen=seen, first_seen_basis=basis)
            self.say(20, f"{ip} sent {len(reqs)} SQL injection requests to {', '.join(d['paths'])} on {asset} starting at {self.t(evs[0].ts_utc)}; {len(failed)} were answered with errors "
                         f"and one with HTTP 200 and {s.fields['bytes']:,} bytes.", claims)
            self.say(60, "Suspected: the injection succeeded. Not enough evidence: the content of that response is unknown.", [c3, c4])
        else:
            self.part("web_attack_attempt", "Web application attack, attempts only", [asset], [e.cite() for e in evs[:1]], first_seen=seen, first_seen_basis=basis)
            self.say(20, f"{ip} sent {len(reqs)} SQL injection requests to {asset} starting at {self.t(evs[0].ts_utc)}; none was answered with a large HTTP 200.", claims)
        self.asset(asset, "target of the SQL injection requests", True, "HTTP requests answered by the server", [e.cite() for e in evs[:1]])
        if ip not in self.attacker_ips:
            self.attacker_ips.append(ip)
        self.open_runbook("web_attack", f"SQL injection requests from {ip}", [evs[0].cite()])
        self.facts["web"] = dict(d, first=evs[0].ts_utc, last=evs[-1].ts_utc, failed=[e.id for e in failed])

    def h_scan(self, f: Finding) -> None:
        d, r = f.data, self.r
        ip = d["src_ip"]
        internal = is_internal_ip(ip)
        evs = [self.E(i) for i in f.event_ids if self.E(i).source_type != "ids"]
        if not evs:
            return
        sc = self.facts.setdefault("scan", dict(src_ip=ip, internal=internal, src_host=d.get("src_host"), denied=[], allowed=[], probes=[], events=[], targets=[]))
        sc["events"] += [e.id for e in evs]
        seen, basis = self.alert_time(f)
        if f.kind in ("port_scan", "internal_scan"):
            denied, allowed = d["denied"], d["allowed"]
            sc["denied"] += denied
            sc["allowed"] += allowed
            sc["targets"] = list(dict.fromkeys(sc["targets"] + d["targets"]))
            tgt = ", ".join(d["target_ips"])
            names = ", ".join(d["targets"]) or "not in the asset inventory"
            fmt = (lambda x: str(x["port"])) if len(d["target_ips"]) == 1 else (lambda x: f"{x['ip']}:{x['port']}")
            txt = f"{ip}" + (f" ({d['src_host']})" if d.get("src_host") else "") + f" tried {len(evs)} destinations on {tgt} ({names}) between {self.t(evs[0].start)} and {self.t(evs[-1].start)}: "
            bits = []
            if denied:
                bits.append("denied - " + ", ".join(fmt(x) for x in denied))
            if allowed:
                bits.append("allowed - " + ", ".join(fmt(x) for x in allowed))
            c1 = self.claim("CONFIRMED", txt + "; ".join(bits) + ".", [e.cite() for e in evs], topic="scan_ports")
            self.tl(evs[0].start, f"Port scan from {d.get('src_host') or ip}", f"{len(evs)} destinations on {names}: {len(denied)} denied, {len(allowed)} allowed", [e.cite() for e in evs], phase="Reconnaissance", end=evs[-1].start)
            self.say(20, f"{ip} scanned {len(evs)} ports on {names} between {self.t(evs[0].start)} and {self.t(evs[-1].start)}: {len(denied)} were denied and {len(allowed)} allowed.", [c1])
            for hname in d["targets"]:
                self.asset(hname, "target of the port scan", None, "scan target - no login or session beyond the scan itself", [evs[0].cite()])
            self.part("recon", "Unapproved scanning or reconnaissance", d["targets"], [e.cite() for e in evs[:1]], first_seen=seen, first_seen_basis=basis)
        else:
            reqs = d["requests"]
            sc["probes"] += reqs
            asset = d["asset"] or "the web server"
            sc["targets"] = list(dict.fromkeys(sc["targets"] + ([d["asset"]] if d["asset"] else [])))
            codes = ", ".join(sorted({str(x["status"]) for x in reqs}))
            c1 = self.claim("CONFIRMED", f"{ip} requested {', '.join(x['url'] for x in reqs)} on {asset} between {self.t(evs[0].ts_utc)} and {self.both(evs[-1].ts_utc)}; "
                                         f"the answers were HTTP {codes}. User-Agent: {', '.join(d['user_agents'])}.", [e.cite() for e in evs], topic="scan_probe")
            self.tl(evs[0].ts_utc, f"Web probing of {asset}", f"{ip} requested {', '.join(x['url'] for x in reqs)} -> HTTP {codes}", [e.cite() for e in evs], phase="Reconnaissance", end=evs[-1].ts_utc)
            self.say(25, f"{ip} also requested {', '.join(x['url'] for x in reqs)} on {asset}; the answers were HTTP {codes}.", [c1])
            self.asset(asset, "target of the web probing", None, "probe requests only", [evs[0].cite()])
            self.part("recon", "Unapproved scanning or reconnaissance", [asset], [e.cite() for e in evs[:1]], first_seen=seen, first_seen_basis=basis)
        if ip not in self.attacker_ips:
            self.attacker_ips.append(ip)
        self.open_runbook("recon", f"scanning from {ip} with no matching approved change", [evs[0].cite()])

    def h_admin_rdp(self, f: Finding) -> None:
        d = f.data
        e = self.E(d["logon"])
        bits = [f"{d['user']} logged on to {d['target']} by remote desktop from {d['client_ip']} at {self.both(e.ts_utc)}"]
        if d["priv"]:
            bits.append(f"special privileges were assigned at {self.t(self.E(d['priv'][0]).ts_utc)}")
        if d["logoff"]:
            bits.append(f"the logoff is at {self.t(self.E(d['logoff']).ts_utc)}")
        cites = [self.C(i) for i in [d["logon"]] + d["priv"] + ([d["logoff"]] if d["logoff"] else []) + d["fw"]] + [self.C(d["session_auth"])]
        c1 = self.claim("CONFIRMED", "; ".join(bits) + ".", cites, topic="rdp")
        self.tl(e.ts_utc, f"Remote desktop logon to {d['target']} by {d['user']}", f"from {d['client_ip']}", cites[:1], phase="Privileged access")
        c2 = self.claim("SUSPECTED", f"The remote desktop session of {d['user']} on {d['target']} was not authorised.", cites[:1],
                        rule="No approved change matches all five checks (see the change-calendar check). Guess needed: that the session was not sanctioned some other way.", topic="rdp_suspected")
        self.account(d["user"], f"remote desktop logon to {d['target']}", cites[:1])
        self.asset(d["target"], f"remote desktop logon by {d['user']}", True, "remote desktop logon recorded by the domain controller", cites[:1])
        seen, basis = self.alert_time(f)
        self.part("credential_compromise", "Unapproved privileged remote access (closest matrix row: credential compromise)", [d["target"]], cites[:1],
                  note="The matrix has no row for unapproved administrator access; the closest row is used and the choice is flagged for a human decision.",
                  first_seen=seen, first_seen_basis=basis)
        self.open_runbook("credential_compromise", f"remote desktop logon to {d['target']} with no matching approved change", cites[:1])
        self.say(20, f"{d['user']} logged on to {d['target']} by remote desktop from {d['client_ip']} at {self.t(e.ts_utc)} with no matching approved change.", [c1, c2])

    def h_prompt_injection(self, f: Finding) -> None:
        d = f.data
        e = self.E(d["event"])
        src = f" sent from {d['src_ip']}" if d["src_ip"] else ""
        c1 = self.claim("CONFIRMED", f"The {d['field']} of a {d['source_type']} log line{src} contains text written to instruct an AI assistant "
                                     f"(signatures: {', '.join(d['signatures'])}). The line is quarantined: its text is never passed to the language model, "
                                     "and it is reported here as an attack on the triage tooling.", [e.cite()], topic="injection")
        self.tl(e.ts_utc, "Prompt-injection text found in a log line", f"signatures: {', '.join(d['signatures'])}", [e.cite()], phase="Attack on tooling")
        self.claim("INSUFFICIENT_EVIDENCE", "Who planted the text, and whether other tools that read these logs acted on it, is unknown.", [e.cite()],
                   rule="The logs show the text, not its author or its effect elsewhere.", topic="injection_gap")
        self.part("prompt_injection", "Adversarial prompt injection in log data", [], [e.cite()],
                  note="The severity matrix has no row for this incident type: no severity is assigned by lookup; escalate for a human decision.", first_seen=e.ts_utc,
                  first_seen_basis="time of the log line")
        if d["src_ip"] and not is_internal_ip(d["src_ip"]) and d["src_ip"] not in self.attacker_ips:
            self.attacker_ips.append(d["src_ip"])
        self.facts.setdefault("injection", []).append(d)
        self.say(15, f"A {d['source_type']} log line{src} carries prompt-injection text aimed at AI log analysis; it was quarantined and not shown to the model.", [c1])

    # ============================================================ incident-level
    def cross_links(self) -> None:
        click, creds = self.facts.get("click"), self.facts.get("cred", [])
        note = next((c for c in self.r.matrix_notes if re.search(r"click is seen", c.text, re.I)), None)
        for cr in creds:
            if click and click["dst_ip"] == cr["src_ip"] and not cr["suspected_only"]:
                delta = (cr["session_start"] - click["ts"]).total_seconds()
                c = self.claim("SUSPECTED", f"The password of {cr['user']} was captured by the phishing page: the VPN logins came from {cr['src_ip']}, the same address that "
                                            f"threat intelligence ties to the phishing link host, {tu.fmt_span(delta)} after {click['laptop']} connected to it.",
                               [self.C(click["event"]), self.C(cr["success"])] + [self.C(a) for a in click["intel_alerts"]] + [note],
                               rule="Guess needed: that the user typed the password into the page - no log shows it. Matrix rule: a phishing email where a click is seen is handled as credential compromise.",
                               topic="phish_to_cred")
                ph = self.facts.get("phish", {})
                self.say(10, f"It began with phishing email {ph.get('msgid')} delivered at {self.t(self.E(ph['events'][0]).ts_utc) if ph.get('events') else '?'}; "
                             f"{click['laptop']} connected to the link host {click['dst_ip']} at {self.t(click['ts'])}.", [ph["claim"]] + self.facts.get("click_claims", [])[:1] if ph.get("claim") else [])
                self.say(55, f"Suspected: the password of {cr['user']} was captured by the phishing page and then used from {cr['src_ip']}.", [c])

    def alert_claims(self) -> list[dict[str, Any]]:
        out = []
        ids = sorted({a for f in self.findings for a in f.alert_ids}, key=lambda a: self.E(a).ts_utc)
        for a in ids:
            e = self.E(a)
            self.claim("CONFIRMED", f"IDS alert {e.fields['alert_id']} was raised at {self.t(e.ts_utc)} by the {e.fields.get('sensor')} sensor: \"{e.fields.get('description')}\".",
                       [e.cite()], topic="alert")
            self.tl(e.ts_utc, f"IDS alert {e.fields['alert_id']}", str(e.fields.get("description")), [e.cite()], phase="Detection")
            link = self.alert_links.get(a, {})
            link["disposition"] = "INCIDENT"
            out.append(dict(alert_id=e.fields["alert_id"], ts=e.ts_utc, sensor=e.fields.get("sensor"), description=e.fields.get("description"),
                            citation=e.cite().model_dump(), trigger_events=link.get("trigger_events", []), delay_s=link.get("delay_s")))
        return out

    def calendar_claims(self) -> None:
        r = self.r
        if not r.changes:
            return
        for f in self.findings:
            if not f.primary or f.kind in ("phishing_delivery", "phishing_click", "prompt_injection", "concurrent_login", "mfa_fatigue"):
                continue
            misses = sorted((n for n in self.near if n["finding_id"] == f.id), key=lambda n: -n["passed"])
            what = {"large_transfer": "the large transfer", "mfa_fatigue": "the VPN login", "web_attack": "the web requests", "port_scan": "the port scan",
                    "internal_scan": "the internal scan", "web_probe": "the web probing", "admin_rdp": "the remote desktop session"}.get(f.kind, "this activity")
            cites: list[Optional[Citation]] = [self.rule("3.1")]
            if misses and misses[0]["passed"] >= 3:
                m = misses[0]
                bad = "; ".join(c["detail"] for c in m["criteria"] if not c["ok"])
                txt = (f"No approved change covers {what}. The closest calendar entry, {m['change_id']}, passes {m['passed']} of the 5 checks and fails on: {bad}.")
                cites += [_cit(m["citation"]), self.C(f.event_ids[0]), self.C(f.data.get("session_auth"))]
            else:
                txt = f"No approved change covers {what}: none of the {len(r.changes)} change-calendar entries matches its system, actor and time window."
                cites += [c.citation for c in r.changes] + [self.C(f.event_ids[0]), self.C(f.data.get("session_auth"))]
            for fl in f.flags:
                if fl.startswith("APPROVED_ACTOR_OUTSIDE_WINDOW"):
                    txt += " The source is an approved tool, but it acted outside its approved window, so the activity is not approved."
                elif fl.startswith("APPROVED_ACTOR_OUT_OF_SCOPE_TARGET"):
                    txt += " The source is an approved tool inside its window, but the target is outside the approved scope, so the activity is not approved."
                elif fl.startswith("RESIDUAL_ANOMALY_DURING_MAINTENANCE"):
                    txt += " The time and target fit an approved change, but the actor is not the one named in it - an anomaly inside a maintenance window."
                elif fl.startswith("PARTLY_COVERED_BY"):
                    txt += f" Part of the activity was closed under an approved change; the events kept here are not covered ({fl.split(':', 1)[1]})."
                if fl.split(":")[0] not in self.flags:
                    self.flags.append(fl.split(":")[0])
            self.claim("CONFIRMED", txt, cites, rule="Rule 3.1: activity is approved only if the calendar lists the same system, the same person or tool, and a window that contains it.", topic="calendar")

    def scan_followups(self) -> None:
        sc = self.facts.get("scan")
        if not sc:
            return
        ip = sc["src_ip"]
        vpn = [e for e in self.ctx.ev("vpn") if e.ip_source == ip]
        dc = [e for e in self.ctx.ev("dc") if e.ip_source == ip]
        if not vpn and not dc:
            c = self.claim("CONFIRMED", f"No login attempt from {ip} appears in the VPN log or the domain controller log.",
                           [self.coverage_row(self.file_of("vpn") or ""), self.coverage_row(self.file_of("dc") or ""), self.C(sc["events"][0])], topic="scan_no_login")
            sc["no_login_claim"] = c
        if not sc["internal"]:
            self.claim("INSUFFICIENT_EVIDENCE", f"Who operates {ip} and what they intended is unknown.", [self.C(sc["events"][0])] + self.missing("other_dates"),
                       rule="The logs record the address only, and only for one day.", topic="scan_gap")

    def gaps(self, start: Optional[datetime], end: Optional[datetime]) -> list[dict[str, Any]]:
        r = self.r
        out: list[dict[str, Any]] = []
        if not start or not end:
            return out
        sess = [self.ctx.graph.session(s) for s in self.sessions]
        for g in r.gaps:
            if not (g.start_utc and g.end_utc and g.start_utc <= end and g.end_utc >= start):
                continue
            span = f"from {self.t(g.start_utc)} to {self.both(g.end_utc)}"
            txt = f"There are no {g.source.lower()} logs {span}"
            cites: list[Optional[Citation]] = [g.citation]
            open_sessions = [s for s in sess if s and s.start <= g.end_utc and (s.end or g.end_utc) >= g.start_utc]
            if g.kind == "outage" and open_sessions:
                s = open_sessions[0]
                txt += f", while VPN session {s.session} stayed open until {self.t(s.end)}: anything it did on the internal network in that window was not recorded."
                cites += [self.C(s.end_event), self.C(s.auth_event)]
            else:
                txt += "; activity in that window cannot be confirmed or ruled out."
            self.claim("INSUFFICIENT_EVIDENCE", txt, cites, rule=f"Coverage sheet: {g.reason}" if g.reason else None, topic="gap")
            out.append(dict(kind=g.kind, source=g.source, file=g.file, start_utc=g.start_utc, end_utc=g.end_utc, reason=g.reason, citation=g.citation.model_dump(),
                            overlaps_incident=True))
            if g.kind == "outage":
                covering = [c for c in r.changes if c.approved and c.start_utc and c.end_utc and c.start_utc <= g.end_utc and c.end_utc >= g.start_utc]
                if not covering:
                    self.claim("CONFIRMED", f"The change calendar has no entry whose window overlaps the {g.source.lower()} outage ({self.t(g.start_utc)} to {self.t(g.end_utc)}).",
                               [g.citation] + [c.citation for c in r.changes], rule="Observation only: the coverage sheet gives a reason for the outage; the calendar does not list it.", topic="gap_calendar")
        dates = self.missing("other_dates")
        if dates:
            self.claim("INSUFFICIENT_EVIDENCE", f"Whether related activity happened before or after {r.log_date} is unknown.", dates,
                       rule="No logs of any kind are available for other dates.", topic="other_dates")
        return out

    HANDLERS = {
        "phishing_delivery": "h_phishing_delivery", "phishing_click": "h_phishing_click", "mfa_fatigue": "h_mfa_fatigue",
        "large_transfer": "h_large_transfer", "password_reset": "h_password_reset", "lockout": "h_lockout",
        "concurrent_login": "h_concurrent_login", "web_attack": "h_web_attack", "port_scan": "h_scan", "internal_scan": "h_scan",
        "web_probe": "h_scan", "admin_rdp": "h_admin_rdp", "prompt_injection": "h_prompt_injection",
    }
    ORDER = ["phishing_delivery", "phishing_click", "mfa_fatigue", "concurrent_login", "large_transfer", "password_reset", "lockout",
             "web_attack", "port_scan", "internal_scan", "web_probe", "admin_rdp", "prompt_injection"]

    def title(self) -> tuple[str, list[str]]:
        k, fx = self.kinds, self.facts
        chain: list[str] = []
        if "mfa_fatigue" in k or "large_transfer" in k:
            cr = (fx.get("cred") or [{}])[0]
            if "phishing_delivery" in k:
                chain.append("Phishing email")
            if "phishing_click" in k:
                chain.append("Link host contacted")
            if "mfa_fatigue" in k:
                chain.append(f"VPN login from geo {cr.get('geo')} after rejected MFA pushes")
            if "large_transfer" in k:
                tr = fx["transfer"]
                chain.append(f"{tr['bytes'] / 1e9:.1f} GB transfer from {tr['server_name']}")
            if "password_reset" in k:
                chain.append("Password reset")
            if "lockout" in k:
                chain.append("Owner locked out")
            user = cr.get("user") or fx.get("transfer", {}).get("client_user")
            head = f"Suspected takeover of account {user} via VPN" if "mfa_fatigue" in k else f"Large transfer from {fx['transfer']['server_name']}"
            if "large_transfer" in k and "mfa_fatigue" in k:
                head += f", then a {fx['transfer']['bytes'] / 1e9:.1f} GB transfer from {fx['transfer']['server_name']}"
            return head, chain
        if "web_attack" in k:
            w = fx["web"]
            return f"SQL injection against {w['asset']} from {w['src_ip']}" + (" (success suspected)" if w["success"] else " (attempts only)"), ["SQL injection requests"] + (["Large HTTP 200 response"] if w["success"] else [])
        if "admin_rdp" in k:
            f = next(f for f in self.findings if f.kind == "admin_rdp")
            return f"Unapproved remote desktop logon to {f.data['target']} by {f.data['user']}", ["Remote desktop logon"]
        if k & {"port_scan", "internal_scan", "web_probe"}:
            sc = fx["scan"]
            src = sc.get("src_host") or sc["src_ip"]
            parts = (["Port scan"] if k & {"port_scan", "internal_scan"} else []) + (["Web probing"] if "web_probe" in k else [])
            return f"Unapproved {' and '.join(p.lower() for p in parts)} of {', '.join(sc['targets']) or 'internal systems'} from {src}", parts
        if "concurrent_login" in k:
            cr = fx["cred"][0]
            return f"Possible misuse of account {cr['user']}: VPN session overlapping an office logon (rule 6.2)", ["VPN session", "Concurrent office logon"]
        if "phishing_delivery" in k:
            return f"Phishing email {fx['phish']['msgid']} delivered, no click seen", ["Phishing email"]
        if "prompt_injection" in k:
            return "Prompt-injection text planted in log data", ["Prompt injection"]
        return self.findings[0].title, []

    def build(self) -> dict[str, Any]:
        for kind in self.ORDER:
            for f in self.findings:
                if f.kind == kind:
                    getattr(self, self.HANDLERS[kind])(f)
        for f in self.findings:
            if f.kind not in self.HANDLERS:
                self.claim("CONFIRMED", f.title, [self.C(i) for i in f.event_ids], topic="other")
        self.cross_links()
        # credential-compromise part: every asset a suspect session actually reached
        for cr in self.facts.get("cred", []):
            hosts = [h for h, a in self.assets.items() if a["reached"] and any(cr["session"] and cr["session"] in role for role in a["roles"])]
            label = "Credential compromise (account used by an attacker)" + (" - suspected only" if cr["suspected_only"] else "")
            self.part("credential_compromise", label, hosts, [self.C(cr["success"])], first_seen=cr["first_seen"], first_seen_basis=cr["first_seen_basis"],
                      note="Suspected only: rule 6.2 indicator, not confirmed attacker use. The severity is provisional until the user is contacted." if cr["suspected_only"] else None)
        alerts = self.alert_claims()
        self.calendar_claims()
        self.scan_followups()
        starts = [f.start for f in self.findings if f.start] + [t.ts_utc for t in self.timeline]
        ends = [f.end for f in self.findings if f.end] + [t.ts_end_utc or t.ts_utc for t in self.timeline]
        start, end = (min(starts), max(ends)) if starts else (None, None)
        gaps = self.gaps(start, end)
        self.timeline.sort(key=lambda t: (t.ts_utc, t.label))
        title, chain = self.title()
        return dict(title=title, kill_chain=chain, claims=self.claims, timeline=self.timeline, assets=list(self.assets.values()),
                    accounts=list(self.accounts.values()), parts=self.parts, runbooks=self.runbooks, attacker_ips=self.attacker_ips,
                    summary=[dict(text=t, claim_ids=c) for _, t, c in sorted(self.summary, key=lambda s: s[0])], facts=self.facts, alerts=alerts,
                    gaps=gaps, start=start, end=end, flags=self.flags, sessions=self.sessions,
                    heuristics=list(dict.fromkeys(h for f in self.findings for h in f.heuristics)))
