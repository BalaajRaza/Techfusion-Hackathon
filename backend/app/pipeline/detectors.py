"""Stage 5 - deterministic, rule-based detectors.

Every detector reads normalised events and reference tables only. No IP,
user or host of the data pack is hard-coded: a different day of logs in the
same formats is triaged by the same rules. Numeric thresholds are heuristics
(the security rules give none) and each use is recorded in Finding.heuristics.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional

from .. import config
from ..models import Citation, Event, Finding, SourceFile
from . import timeutil as tu
from .entities import EntityGraph
from .parsers import sort_key
from .references import Asset, References, is_internal_ip


class Ctx:
    """Shared, read-only view of the parsed evidence."""

    def __init__(self, files: dict[str, SourceFile], refs: References, events: list[Event], graph: EntityGraph):
        self.files = files
        self.refs = refs
        self.graph = graph
        self.all_events = events
        self.by_id = {e.id: e for e in events}
        self.events = sorted((e for e in events if e.parse_status == "parsed" and e.ts_utc is not None
                              and not any(f.startswith("DUPLICATE_OF") for f in e.flags)), key=sort_key)
        self.by_type: dict[str, list[Event]] = defaultdict(list)
        for e in self.events:
            self.by_type[e.source_type].append(e)

    def ev(self, *types: str) -> list[Event]:
        out: list[Event] = []
        for t in types:
            out.extend(self.by_type.get(t, []))
        return sorted(out, key=sort_key)

    def cite(self, event_id: str) -> Citation:
        return self.by_id[event_id].cite()

    def cites(self, event_ids: Iterable[str]) -> list[Citation]:
        return [self.by_id[i].cite() for i in event_ids]

    def target_assets(self, e: Event) -> list[Asset]:
        """The asset(s) an event was aimed at."""
        r = self.refs
        found: list[Asset] = []
        if e.source_type in ("fw_edge", "fw_int"):
            cand = [r.asset_by_ip(e.ip_dest)]
        elif e.source_type == "dc":
            cand = [r.asset_by_name(e.fields.get("file_asset")) or r.asset_by_name(e.host)]
        elif e.source_type in ("web", "vpn"):
            cand = [r.asset_by_name(e.fields.get("file_asset"))]
        else:
            cand = []
        for a in cand:
            if a and a not in found:
                found.append(a)
        return found


_fid = 0


def _finding(kind: str, title: str, events: list[Event], **kw: Any) -> Finding:
    global _fid
    _fid += 1
    starts = [e.start for e in events if e.start]
    ends = [e.end for e in events if e.end]
    return Finding(id=f"FND-{_fid:03d}", kind=kind, title=title, event_ids=[e.id for e in events],
                   start=min(starts) if starts else None, end=max(ends) if ends else None, **kw)


def reset_ids() -> None:
    global _fid
    _fid = 0


def levenshtein(a: str, b: str) -> int:
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike(domain: str, company: Optional[str]) -> bool:
    if not company or domain == company:
        return False
    norm = lambda d: re.sub(r"[^a-z0-9]", "", d.lower())  # noqa: E731
    return levenshtein(norm(domain), norm(company)) <= 2


# ------------------------------------------------------------------ phishing
def detect_phishing(ctx: Ctx) -> list[Finding]:
    r = ctx.refs
    out: list[Finding] = []
    groups: dict[str, list[Event]] = defaultdict(list)
    for e in ctx.ev("email"):
        groups[e.fields.get("msgid", e.id)].append(e)
    for msgid, evs in groups.items():
        f0 = evs[0].fields
        sender = str(f0.get("from", ""))
        sdom = sender.split("@")[-1].lower()
        url_host = f0.get("url_host")
        spf_fail = str(f0.get("spf", "")).lower() in ("fail", "softfail")
        is_lookalike = lookalike(sdom, r.company_email_domain)
        if not (spf_fail and (url_host or is_lookalike)):
            continue
        # which IP does threat intel tie to the link host?
        intel = [a for a in ctx.ev("ids") if url_host and url_host in a.fields.get("domains", [])]
        link_ips = sorted({ip for a in intel for ip in a.fields.get("ips", []) if not is_internal_ip(ip)})
        recipients, clicks, no_click = [], [], []
        for e in evs:
            user = r.user(e.user_account) if str(e.fields.get("to", "")).lower().endswith("@" + (r.company_email_domain or "")) else None
            rec: dict[str, Any] = dict(to=e.fields.get("to"), user=user.username if user else None, event=e.id, ts=e.ts_utc)
            recipients.append(rec)
            if not user:
                continue
            laptop = ctx.graph.laptop_of(user.username)
            if not laptop:
                continue
            outbound = [x for x in ctx.ev("fw_edge") if x.ip_source in laptop.ips and x.ts_utc >= e.ts_utc]
            hit = next((x for x in outbound if x.ip_dest in link_ips and x.outcome == "ALLOW"), None)
            if hit:
                res = ctx.graph.resolve(hit.ip_source, hit.ts_utc)
                clicks.append(dict(user=user.username, laptop=laptop.hostname, src_ip=hit.ip_source, dst_ip=hit.ip_dest, event=hit.id,
                                   delivered_event=e.id, delay_s=(hit.ts_utc - e.ts_utc).total_seconds(),
                                   binding=[c.model_dump() for c in res.citations], binding_note=res.note, binding_confidence=res.confidence))
            else:
                no_click.append(dict(user=user.username, laptop=laptop.hostname, laptop_ip=laptop.ips[0] if laptop.ips else None,
                                     other_outbound=[x.id for x in outbound][:5]))
        data = dict(msgid=msgid, sender=sender, sender_domain=sdom, lookalike=is_lookalike, url_host=url_host, link_ips=link_ips,
                    intel_alerts=[a.id for a in intel], spf=f0.get("spf"), dkim=f0.get("dkim"), score=f0.get("score"),
                    subject=f0.get("subject"), delivered=all(e.outcome == "delivered" for e in evs),
                    recipients=recipients, clicks=clicks, no_click=no_click)
        actors = [f"msg:{msgid}"] + [f"ip:{ip}" for ip in link_ips]
        heur = ["H-PHISH: an email is treated as phishing when SPF fails AND it carries a link host or a look-alike sender domain"]
        out.append(_finding("phishing_delivery", f"Phishing email {msgid} delivered to {len(evs)} recipient(s)", evs,
                            activity="phishing", actors=actors, data=data, heuristics=heur))
        for c in clicks:
            ev_click = ctx.by_id[c["event"]]
            out.append(_finding("phishing_click", f"{c['laptop']} connected to the phishing link host", [ev_click], activity="phishing",
                                actors=[f"msg:{msgid}", f"ip:{c['dst_ip']}", f"user:{c['user']}"], data=dict(c, msgid=msgid, url_host=url_host,
                                                                                                             intel_alerts=[a.id for a in intel])))
    return out


# ------------------------------------------------------------------ VPN / MFA
def session_activity(ctx: Ctx, sid: str) -> dict[str, list[str]]:
    """Everything the logs show a VPN session doing on the internal network."""
    s = ctx.graph.session(sid)
    if not s or not s.assigned_ip:
        return dict(dc=[], fw=[])
    end = s.end or datetime.max.replace(tzinfo=tu.UTC)
    dc = [e.id for e in ctx.ev("dc") if e.ip_source == s.assigned_ip and s.start <= e.ts_utc <= end]
    fw = [e.id for e in ctx.ev("fw_int", "fw_edge") if e.ip_source == s.assigned_ip and e.start and e.start <= end and (e.end or e.start) >= s.start]
    return dict(dc=dc, fw=fw)


def detect_mfa_fatigue(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    auths = [e for e in ctx.ev("vpn") if e.action == "vpn_auth"]
    geo_counts = Counter(e.fields.get("geo") for e in auths if e.outcome == "SUCCESS")
    for ok in auths:
        if ok.outcome != "SUCCESS" or "approved" not in str(ok.fields.get("mfa", "")):
            continue
        fails = [e for e in auths if e.user_account == ok.user_account and e.outcome == "FAIL"
                 and "mfa" in str(e.fields.get("reason", "")) and 0 <= (ok.ts_utc - e.ts_utc).total_seconds() <= config.MFA_WINDOW_S]
        if len(fails) < config.MFA_FAIL_MIN:
            continue
        sid = ok.fields.get("session")
        s = ctx.graph.session(sid)
        geo = ok.fields.get("geo")
        others = Counter({g: n for g, n in geo_counts.items() if g != geo})
        home_geo = others.most_common(1)[0][0] if others else None
        vpn_asset = ctx.refs.asset_by_name(ok.fields.get("file_asset"))
        gw_ips = (vpn_asset.public_ips + vpn_asset.ips) if vpn_asset else []
        edge = [e for e in ctx.ev("fw_edge") if e.ip_source == ok.ip_source and e.ip_dest in gw_ips
                and fails[0].ts_utc - timedelta(seconds=60) <= e.ts_utc <= ok.ts_utc + timedelta(seconds=5)]
        act = session_activity(ctx, sid) if sid else dict(dc=[], fw=[])
        end_ev = ctx.by_id.get(s.end_event) if s and s.end_event else None
        evs = fails + [ok] + ([end_ev] if end_ev else [])
        data = dict(user=ok.user_account, src_ip=ok.ip_source, geo=geo, home_geo=home_geo, fails=[e.id for e in fails], success=ok.id,
                    fail_reasons=dict(Counter(str(e.fields.get("reason")) for e in fails)), session=sid,
                    assigned_ip=ok.fields.get("assigned_ip"), session_end=end_ev.id if end_ev else None,
                    session_start=s.start if s else ok.ts_utc, session_end_ts=s.end if s else None,
                    bytes_to_client=s.bytes_to_client if s else None, bytes_from_client=s.bytes_from_client if s else None,
                    duration_s=s.duration_s if s else None, edge_events=[e.id for e in edge], vpn_asset=vpn_asset.hostname if vpn_asset else None,
                    session_dc=act["dc"], session_fw=act["fw"])
        heur = [f"H-MFA: 'several rejected MFA pushes' (rule 6.1) is taken as >= {config.MFA_FAIL_MIN} failed pushes within {config.MFA_WINDOW_S} s (inclusive) before the approved push"]
        out.append(_finding("mfa_fatigue", f"Repeated rejected MFA pushes then an approved VPN login for {ok.user_account}", evs, activity="vpn_login",
                            actors=[f"ip:{ok.ip_source}", f"user:{ok.user_account}"] + ([f"session:{sid}"] if sid else []), data=data, heuristics=heur))
    return out


def detect_concurrent_logins(ctx: Ctx) -> list[Finding]:
    """Rule 6.2: the same user logged in from two places at the same time."""
    out: list[Finding] = []
    r = ctx.refs
    office_logons = [e for e in ctx.ev("dc") if e.outcome == "SUCCESS" and e.action in ("kerberos_tgt", "logon", "rdp_logon")
                     and e.ip_source and is_internal_ip(e.ip_source) and not r.in_vpn_pool(e.ip_source)]
    for s in ctx.graph.sessions.values():
        if not s.user or not s.src_ip or is_internal_ip(s.src_ip):
            continue
        end = s.end or datetime.max.replace(tzinfo=tu.UTC)
        mine = [e for e in office_logons if e.user_account == s.user]
        strict = [e for e in mine if s.start <= e.ts_utc <= end]
        lease = []
        for e in mine:
            if e.ts_utc < s.start:
                ls = ctx.graph.lease_at(e.ip_source, s.start)
                if ls and ctx.graph.lease_at(e.ip_source, e.ts_utc) is ls:
                    lease.append((e, ls))
        if not strict and not lease:
            continue
        auth = ctx.by_id[s.auth_event]
        evs = [auth] + strict + [e for e, _ in lease] + ([ctx.by_id[s.end_event]] if s.end_event else [])
        act = session_activity(ctx, s.session)
        data = dict(user=s.user, session=s.session, src_ip=s.src_ip, geo=s.geo, assigned_ip=s.assigned_ip, mfa=s.mfa,
                    session_start=s.start, session_end_ts=s.end, auth=auth.id, session_end=s.end_event,
                    strict=[e.id for e in strict], lease=[dict(event=e.id, lease=ls.citation.model_dump(), lease_end=ls.end) for e, ls in lease],
                    bytes_to_client=s.bytes_to_client, session_dc=act["dc"], session_fw=act["fw"])
        out.append(_finding("concurrent_login", f"{s.user}: VPN session from {s.src_ip} overlaps an office logon", evs, activity="vpn_login",
                            primary=bool(strict), actors=[f"user:{s.user}", f"session:{s.session}"], data=data))
    return out


# ------------------------------------------------------------------ transfers
def detect_large_transfer(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    for e in ctx.ev("fw_int", "fw_edge"):
        size = e.fields.get("bytes") or 0
        if e.outcome != "ALLOW" or size < config.LARGE_TRANSFER_BYTES:
            continue
        client = ctx.graph.resolve(e.ip_source, e.start)
        server = ctx.refs.asset_by_ip(e.ip_dest)
        s2c = e.fields.get("bytes_server_to_client")
        actors = [f"ip:{e.ip_source}"]
        sess = ctx.graph.session(client.session) if client.kind == "vpn_session" else None
        if sess:
            actors += [f"session:{sess.session}", f"user:{sess.user}"]
        elif client.user:
            actors.append(f"user:{client.user}")
        data = dict(event=e.id, client_ip=e.ip_source, server_ip=e.ip_dest, server=server.hostname if server else None, port=e.fields.get("dport"),
                    bytes=size, bytes_server_to_client=s2c, duration_s=e.fields.get("duration_s"), client_kind=client.kind,
                    client_host=client.hostname, client_user=client.user, session=sess.session if sess else None,
                    session_src_ip=sess.src_ip if sess else None, session_end=sess.end_event if sess else None,
                    session_auth=sess.auth_event if sess else None, vpn_bytes_to_client=sess.bytes_to_client if sess else None,
                    client_binding=[c.model_dump() for c in client.citations])
        heur = [f"H-XFER: a single firewall session of >= {config.LARGE_TRANSFER_BYTES:,} bytes is treated as a large transfer"]
        who = f"session {sess.session}" if sess else (client.hostname or e.ip_source)
        out.append(_finding("large_transfer", f"Large transfer between {server.hostname if server else e.ip_dest} and {who}", [e],
                            activity="data_transfer", actors=actors, data=data, heuristics=heur))
    return out


# ------------------------------------------------------------------ directory events
def detect_password_reset(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    for e in ctx.ev("dc"):
        if e.action != "password_reset":
            continue
        res = ctx.graph.resolve(e.ip_source, e.ts_utc) if e.ip_source else None
        notice = next((m for m in ctx.ev("email") if m.user_account == e.user_account and re.search(r"password", str(m.fields.get("subject", "")), re.I)
                       and 0 <= (m.ts_utc - e.ts_utc).total_seconds() <= 300), None)
        actors = [f"user:{e.user_account}"] + ([f"session:{res.session}"] if res and res.session else [])
        data = dict(user=e.user_account, caller=str(e.fields.get("caller", "")), client_ip=e.ip_source, session=res.session if res else None,
                    event=e.id, notice=notice.id if notice else None, result=e.outcome)
        out.append(_finding("password_reset", f"Password reset for {e.user_account}", [e] + ([notice] if notice else []), primary=False,
                            activity="account_change", actors=actors, data=data))
    return out


def detect_lockout(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    dc = ctx.ev("dc")
    for lock in dc:
        if lock.action != "account_lockout":
            continue
        fails = [e for e in dc if e.action == "logon_failed" and e.user_account == lock.user_account
                 and 0 <= (lock.ts_utc - e.ts_utc).total_seconds() <= config.LOCKOUT_WINDOW_S]
        src = fails[0].ip_source if fails else None
        res = ctx.graph.resolve(src, fails[0].ts_utc) if src else None
        data = dict(user=lock.user_account, lock=lock.id, fails=[e.id for e in fails], src_ip=src,
                    src_host=res.hostname if res else None, binding=[c.model_dump() for c in res.citations] if res else [],
                    reasons=sorted({str(e.fields.get("reason")) for e in fails}))
        out.append(_finding("lockout", f"Account lockout for {lock.user_account}", fails + [lock], primary=False, activity="failed_logon",
                            actors=[f"user:{lock.user_account}"], data=data))
    return out


def detect_admin_rdp(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    dc = ctx.ev("dc")
    for e in dc:
        if e.action != "rdp_logon" or e.outcome != "SUCCESS":
            continue
        target = ctx.refs.asset_by_name(e.fields.get("target")) or ctx.refs.asset_by_name(e.host)
        logoff = next((x for x in dc if x.action == "logoff" and x.user_account == e.user_account and x.ts_utc >= e.ts_utc), None)
        end = logoff.ts_utc if logoff else e.ts_utc + timedelta(hours=12)
        priv = [x for x in dc if x.action == "special_privileges" and x.user_account == e.user_account and e.ts_utc <= x.ts_utc <= min(end, e.ts_utc + timedelta(seconds=60))]
        fw = [x for x in ctx.ev("fw_int") if x.ip_source == e.ip_source and target and x.ip_dest in target.ips and x.fields.get("dport") == 3389
              and x.start and x.start <= end and (x.end or x.start) >= e.ts_utc]
        res = ctx.graph.resolve(e.ip_source, e.ts_utc)
        sess = ctx.graph.session(res.session) if res.session else None
        evs = [e] + priv + ([logoff] if logoff else []) + fw
        data = dict(user=e.user_account, target=target.hostname if target else e.host, client_ip=e.ip_source, logon=e.id,
                    priv=[x.id for x in priv], logoff=logoff.id if logoff else None, fw=[x.id for x in fw],
                    session=sess.session if sess else None, session_auth=sess.auth_event if sess else None,
                    session_src_ip=sess.src_ip if sess else None, session_geo=sess.geo if sess else None,
                    session_user_matches=bool(sess and sess.user == e.user_account))
        actors = [f"user:{e.user_account}"] + ([f"session:{sess.session}"] if sess else [f"ip:{e.ip_source}"])
        out.append(_finding("admin_rdp", f"Remote desktop logon to {data['target']} by {e.user_account}", evs, activity="remote_desktop",
                            actors=actors, data=data))
    return out


# ------------------------------------------------------------------ web
SQLI = [
    ("UNION SELECT", re.compile(r"\bunion\b.{0,40}\bselect\b", re.I)),
    ("OR tautology", re.compile(r"\bor\b\s*'?\w+'?\s*=\s*'?\w+", re.I)),
    ("ORDER BY probe", re.compile(r"\border\s+by\s+\d+", re.I)),
    ("WAITFOR DELAY (time-based)", re.compile(r"waitfor\s+delay|sleep\s*\(\s*\d+|benchmark\s*\(", re.I)),
    ("stray quote", re.compile(r"=[^&]*'")),
    ("SQL comment", re.compile(r"--|/\*|#\s*$")),
    ("stacked query", re.compile(r"=[^&]*;")),
]
TRAVERSAL = re.compile(r"\.\./|\.\.\\|/etc/passwd|%00")
XSS = re.compile(r"<script|javascript:|onerror\s*=", re.I)
TOOL_UA = re.compile(r"sqlmap|nikto|nmap|masscan|acunetix|havij|wpscan|dirbuster|gobuster|nessus|openvas|qualys|nuclei|zgrab", re.I)
SENSITIVE_PATH = re.compile(r"^/(admin|phpmyadmin|\.env|\.git|wp-login|wp-admin|config|backup|server-status|manager|console|\.aws|cgi-bin)", re.I)


def attack_patterns(e: Event) -> list[str]:
    url = str(e.fields.get("url_decoded", ""))
    query = url.split("?", 1)[1] if "?" in url else ""
    hits = [name for name, pat in SQLI if query and pat.search("=" + query.split("=", 1)[1] if "=" in query else query)]
    if TRAVERSAL.search(url):
        hits.append("path traversal")
    if XSS.search(url):
        hits.append("script injection")
    return hits


def detect_web(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    by_ip: dict[str, list[Event]] = defaultdict(list)
    for e in ctx.ev("web"):
        by_ip[e.ip_source or "?"].append(e)
    for ip, evs in by_ip.items():
        attacks = [(e, attack_patterns(e)) for e in evs]
        attacks = [(e, p) for e, p in attacks if p]
        asset = ctx.refs.asset_by_name(evs[0].fields.get("file_asset"))
        if attacks:
            a_evs = [e for e, _ in attacks]
            errors = sorted(e.fields["bytes"] for e in a_evs if e.fields["status"] >= 400)
            baseline = errors[len(errors) // 2] if errors else None
            success = [e for e in a_evs if 200 <= e.fields["status"] < 300
                       and e.fields["bytes"] >= (baseline * config.WEB_SUCCESS_SIZE_FACTOR if baseline else 10_000)]
            targets = (asset.public_ips + asset.ips) if asset else []
            edge = [x for x in ctx.ev("fw_edge") if x.ip_source == ip and x.ip_dest in targets
                    and a_evs[0].ts_utc - timedelta(seconds=120) <= x.ts_utc <= a_evs[-1].ts_utc + timedelta(seconds=120)]
            tools = sorted({m.group(0) for e in a_evs if (m := TOOL_UA.search(str(e.fields.get("ua", ""))))})
            paths = sorted({str(e.fields["url_decoded"]).split("?")[0] for e in a_evs})
            data = dict(src_ip=ip, asset=asset.hostname if asset else None, requests=[dict(event=e.id, patterns=p, status=e.fields["status"],
                        bytes=e.fields["bytes"], ts=e.ts_utc, url=e.fields["url_decoded"]) for e, p in attacks],
                        success=[e.id for e in success], baseline_error_bytes=baseline, tools=tools, paths=paths,
                        user_agents=sorted({str(e.fields.get("ua")) for e in a_evs}), edge_events=[x.id for x in edge],
                        other_requests=[e.id for e in evs if e not in a_evs])
            heur = [f"H-WEB-200: an attack request answered with HTTP 2xx and a body >= {config.WEB_SUCCESS_SIZE_FACTOR}x the attacker's median error size counts as 'a large 200 response'"]
            out.append(_finding("web_attack", f"SQL injection requests against {data['asset'] or 'the web server'} from {ip}", a_evs + edge,
                                activity="web_attack", actors=[f"ip:{ip}"], data=data, heuristics=heur))
            continue
        probes = [e for e in evs if SENSITIVE_PATH.search(str(e.fields.get("url_decoded", ""))) or TOOL_UA.search(str(e.fields.get("ua", "")))]
        if len(probes) >= config.WEB_PROBE_MIN_REQUESTS:
            data = dict(src_ip=ip, asset=asset.hostname if asset else None, requests=[dict(event=e.id, status=e.fields["status"], url=e.fields["url_decoded"]) for e in probes],
                        user_agents=sorted({str(e.fields.get("ua")) for e in probes}), all_failed=all(e.fields["status"] >= 400 for e in probes))
            heur = [f"H-PROBE: >= {config.WEB_PROBE_MIN_REQUESTS} requests for sensitive paths or with a scanner User-Agent from one source"]
            out.append(_finding("web_probe", f"Web probing of {data['asset'] or 'the web server'} from {ip}", probes, activity="scan",
                                actors=[f"ip:{ip}"], data=data, heuristics=heur))
    return out


# ------------------------------------------------------------------ scans
def _runs(evs: list[Event], gap_s: int) -> list[list[Event]]:
    runs: list[list[Event]] = []
    for e in evs:
        if runs and (e.start - runs[-1][-1].start).total_seconds() <= gap_s:
            runs[-1].append(e)
        else:
            runs.append([e])
    return runs


def _dense(run: list[Event], key, minimum: int, window_s: int) -> bool:
    """Sliding window: does any window of window_s seconds hold >= minimum distinct keys?"""
    for i, first in enumerate(run):
        seen = {key(x) for x in run[i:] if (x.start - first.start).total_seconds() <= window_s}
        if len(seen) >= minimum:
            return True
    return False


def detect_scans(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    for stype, kind, minimum, key in (
        ("fw_edge", "port_scan", config.PORT_SCAN_MIN_PORTS, lambda x: x.fields.get("dport")),
        ("fw_int", "internal_scan", config.INTERNAL_SCAN_MIN_TARGETS, lambda x: (x.ip_dest, x.fields.get("dport"))),
    ):
        by_src: dict[str, list[Event]] = defaultdict(list)
        for e in ctx.ev(stype):
            by_src[e.ip_source or "?"].append(e)
        for src, evs in by_src.items():
            evs = sorted(evs, key=lambda x: x.start)
            for run in _runs(evs, config.SCAN_WINDOW_S):
                if not _dense(run, key, minimum, config.SCAN_WINDOW_S):
                    continue
                res = ctx.graph.resolve(src, run[0].start)
                targets = sorted({a.hostname for e in run for a in ctx.target_assets(e)})
                data = dict(src_ip=src, src_host=res.hostname, src_kind=res.kind, targets=targets,
                            target_ips=sorted({e.ip_dest for e in run if e.ip_dest}),
                            denied=[dict(event=e.id, ip=e.ip_dest, port=e.fields.get("dport")) for e in run if e.outcome == "DENY"],
                            allowed=[dict(event=e.id, ip=e.ip_dest, port=e.fields.get("dport"), bytes=e.fields.get("bytes")) for e in run if e.outcome == "ALLOW"])
                thr = f">= {minimum} distinct destination {'ports' if kind == 'port_scan' else 'address:port pairs'} from one source within {config.SCAN_WINDOW_S} s (sliding window)"
                label = res.hostname or src
                out.append(_finding(kind, f"Port scan from {label} against {', '.join(targets) or 'unlisted addresses'}", run, activity="scan",
                                    actors=[f"ip:{src}"], data=data, heuristics=[f"H-SCAN: {thr}"]))
    return out


# ------------------------------------------------------------------ prompt injection
def detect_injection(ctx: Ctx) -> list[Finding]:
    out: list[Finding] = []
    for e in ctx.all_events:
        if "PROMPT_INJECTION" not in e.flags:
            continue
        actors = [f"ip:{e.ip_source}"] if e.ip_source else [f"event:{e.id}"]
        field = "User-Agent" if e.source_type == "web" else ("subject / header" if e.source_type == "email" else "log text")
        data = dict(event=e.id, signatures=e.fields.get("injection_signatures", []), src_ip=e.ip_source, field=field,
                    source_type=e.source_type)
        out.append(_finding("prompt_injection", f"Adversarial prompt-injection text in {e.source_file}", [e], activity="prompt_injection",
                            actors=actors, data=data))
    return out


# ------------------------------------------------------------------ IDS alert linking
def _entity_tokens(ctx: Ctx, ips: Iterable[Optional[str]], users: Iterable[Optional[str]], hosts: Iterable[Optional[str]]) -> set[str]:
    toks: set[str] = set()
    for ip in ips:
        if ip:
            toks.add(f"ip:{ip}")
            a = ctx.refs.asset_by_ip(ip)
            if a:
                toks.add(f"host:{a.hostname}")
    for u in users:
        if u:
            toks.add(f"user:{u}")
    for h in hosts:
        a = ctx.refs.asset_by_name(h)
        if a:
            toks.add(f"host:{a.hostname}")
    return toks


def link_alerts(ctx: Ctx, findings: list[Finding]) -> dict[str, dict[str, Any]]:
    """Tie every IDS alert to the raw events that explain it (shared entity +
    time proximity), then to the finding that owns those events."""
    links: dict[str, dict[str, Any]] = {}
    for a in ctx.ev("ids"):
        a_tok = _entity_tokens(ctx, a.fields.get("ips", []), a.fields.get("users", []), a.fields.get("hosts", []))
        lo = a.ts_utc - timedelta(seconds=config.ALERT_LINK_BEFORE_S)
        hi = a.ts_utc + timedelta(seconds=config.ALERT_LINK_AFTER_S)
        scored: list[tuple[int, Event]] = []
        for e in ctx.events:
            if e.source_type in ("ids", "dhcp") or not (lo <= e.ts_utc <= hi):
                continue
            hosts = [x.hostname for x in ctx.target_assets(e)] + [e.fields.get("target")]
            n = len(a_tok & _entity_tokens(ctx, [e.ip_source, e.ip_dest], [e.user_account], hosts))
            if n:
                scored.append((n, e))
        best = max((n for n, _ in scored), default=0)
        triggers = [e for n, e in scored if n == best]
        owners = [f for f in findings if any(t.id in f.event_ids for t in triggers)]
        for f in owners:
            if a.id not in f.alert_ids:
                f.alert_ids.append(a.id)
        deltas = [d for d in ((a.ts_utc - t.ts_utc).total_seconds() for t in triggers) if d >= 0]
        links[a.id] = dict(alert_id=a.fields.get("alert_id"), ref=a.id, ts=a.ts_utc, description=a.fields.get("description"),
                           sensor=a.fields.get("sensor"), trigger_events=[t.id for t in triggers], findings=[f.id for f in owners],
                           delay_s=min(deltas) if deltas else None)
    return links


def run_detectors(ctx: Ctx) -> tuple[list[Finding], dict[str, dict[str, Any]]]:
    reset_ids()
    findings: list[Finding] = []
    for det in (detect_phishing, detect_mfa_fatigue, detect_large_transfer, detect_password_reset, detect_lockout,
                detect_web, detect_scans, detect_admin_rdp, detect_concurrent_logins, detect_injection):
        findings.extend(det(ctx))
    alert_links = link_alerts(ctx, findings)
    return findings, alert_links
