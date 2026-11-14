"""Stage 2 + 3 - one purpose-built parser per log format, each emitting Event
objects with UTC-normalised times. The format of a file is detected from its
content (the parser that matches the most lines wins), so a renamed file or a
second file of a known format still parses. A line no parser understands is
QUARANTINED with its file:line - never dropped.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta
from typing import Any, Callable, Optional
from urllib.parse import unquote

from ..models import Event, SourceFile
from ..security import injection
from . import timeutil as tu
from .references import CIDR_RE, IP_RE, References, TzPolicy

KV = re.compile(r'(\w+)=("([^"]*)"|\S+)')
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:example|com|net|org|local|io|info|biz)\b", re.I)


class ParseError(Exception):
    pass


def kv(text: str) -> dict[str, str]:
    return {m.group(1): (m.group(3) if m.group(3) is not None else m.group(2)) for m in KV.finditer(text)}


def norm_user(value: Optional[str]) -> Optional[str]:
    """ORBIT\\amalik / amalik@orbit.local / AMALIK -> amalik"""
    if not value:
        return None
    v = value.strip()
    if "\\" in v:
        v = v.split("\\", 1)[1]
    if "@" in v:
        v = v.split("@", 1)[0]
    return v.lower() or None


def _int(v: Any) -> Optional[int]:
    try:
        return int(str(v).rstrip("s"))
    except (TypeError, ValueError):
        return None


class TimeResolver:
    """Applies the time-zone policy of the coverage sheet to one file."""

    def __init__(self, policy: Optional[TzPolicy]):
        self.policy = policy

    def resolve(self, naive_or_aware: datetime, inline_tz: Optional[str]) -> tuple[datetime, str, bool]:
        if naive_or_aware.tzinfo is not None:
            return tu.to_utc(naive_or_aware), "offset written in the line", False
        if inline_tz:
            tz = tu.parse_offset(inline_tz)
            if tz is None:
                # unknown / ambiguous abbreviation: do not guess silently
                return naive_or_aware.replace(tzinfo=tu.UTC), f"unknown zone '{inline_tz}' - UTC ASSUMED", True
            return tu.to_utc(naive_or_aware.replace(tzinfo=tz)), f"{inline_tz} written in the line", False
        p = self.policy
        if p and p.mode == "fixed":
            src = f"{p.label} per coverage sheet {p.citation.ref}" if p.citation else p.label
            return tu.to_utc(naive_or_aware.replace(tzinfo=tu.tz_from_hours(p.offset_hours))), src, False
        return naive_or_aware.replace(tzinfo=tu.UTC), "no zone in line or coverage sheet - UTC ASSUMED", True


# --------------------------------------------------------------------------- VPN
VPN_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:?\d\d)?)\s+(?P<host>\S+)\s+(?P<kind>auth|session_end)\b(?P<rest>.*)$")


def parse_vpn(line: str, tr: TimeResolver) -> dict[str, Any]:
    m = VPN_RE.match(line)
    if not m:
        raise ParseError("not a VPN gateway line")
    dt = tu.parse_iso(m.group("ts"))
    if dt is None:
        raise ParseError("bad timestamp")
    ts, src, assumed = tr.resolve(dt, None)
    f = kv(m.group("rest"))
    out: dict[str, Any] = dict(ts_utc=ts, ts_original=m.group("ts"), tz_source=src, tz_assumed=assumed, host=m.group("host"),
                               user_account=norm_user(f.get("user")), fields=dict(f))
    if m.group("kind") == "auth":
        if "result" not in f or "user" not in f:
            raise ParseError("auth line without result/user")
        out.update(action="vpn_auth", outcome=f["result"].upper(), ip_source=f.get("src_ip"))
    else:
        dur = tu.parse_duration(f.get("duration", ""))
        out.update(action="vpn_session_end", outcome="END")
        out["fields"]["duration_s"] = dur
        for k in ("bytes_to_client", "bytes_from_client"):
            out["fields"][k] = _int(f.get(k))
        if dur is not None:
            out.update(ts_start_utc=ts - timedelta(seconds=dur), ts_end_utc=ts)
    return out


# --------------------------------------------------------------------------- Windows DC
DC_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\s+(?P<tz>[A-Za-z]{2,5}|[+-]\d\d:?\d\d))?\s*\|\s*(?P<host>[^|]+?)\s*\|\s*EventID=(?P<eid>\d+)\s*\|\s*(?P<desc>[^|]+?)\s*(?:\|(?P<rest>.*))?$")
DC_ACTIONS = {
    "4768": "kerberos_tgt", "4769": "kerberos_service_ticket", "4724": "password_reset",
    "4625": "logon_failed", "4740": "account_lockout", "4624": "logon", "4672": "special_privileges",
    "4634": "logoff", "4720": "account_created", "4728": "group_member_added", "4732": "group_member_added",
}


def parse_dc(line: str, tr: TimeResolver) -> dict[str, Any]:
    m = DC_RE.match(line)
    if not m:
        raise ParseError("not a domain-controller line")
    dt = tu.parse_naive(m.group("ts"))
    if dt is None:
        raise ParseError("bad timestamp")
    ts, src, assumed = tr.resolve(dt, m.group("tz"))
    f = kv(m.group("rest") or "")
    eid, desc = m.group("eid"), m.group("desc")
    action = DC_ACTIONS.get(eid, f"event_{eid}")
    lt = re.search(r"[Ll]ogon type (\d+)", desc)
    if action == "logon" and lt:
        f["logon_type"] = lt.group(1)
        if lt.group(1) == "10":
            action = "rdp_logon"
    account = f.get("account") or (f.get("target") if eid == "4724" else None)
    client = f.get("client")
    outcome = f.get("result", "").upper() or ("FAIL" if eid == "4625" else "INFO")
    f.update(event_id=eid, description=desc)
    return dict(ts_utc=ts, ts_original=m.group("ts") + (f" {m.group('tz')}" if m.group("tz") else ""), tz_source=src, tz_assumed=assumed,
                host=m.group("host"), user_account=norm_user(account), ip_source=client if client and IP_RE.fullmatch(client) else None,
                action=action, outcome=outcome, fields=f)


# --------------------------------------------------------------------------- Web (combined)
WEB_RE = re.compile(r'^(?P<ip>\S+) \S+ (?P<ruser>\S+) \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<url>\S+)(?: (?P<proto>[^"]*))?" (?P<status>\d{3}) (?P<bytes>\d+|-) "(?P<ref>[^"]*)" "(?P<ua>.*)"\s*$')


def parse_web(line: str, tr: TimeResolver) -> dict[str, Any]:
    m = WEB_RE.match(line)
    if not m:
        raise ParseError("not a combined-format access line")
    dt = tu.parse_apache(m.group("ts"))
    inline = None
    if dt is None:  # timestamp without offset
        try:
            dt = datetime.strptime(m.group("ts").strip(), "%d/%b/%Y:%H:%M:%S")
        except ValueError as exc:
            raise ParseError("bad timestamp") from exc
    ts, src, assumed = tr.resolve(dt, inline)
    url = m.group("url")
    try:
        decoded = unquote(url)
    except Exception:  # noqa: BLE001
        decoded = url
    return dict(ts_utc=ts, ts_original=m.group("ts"), tz_source=src, tz_assumed=assumed, ip_source=m.group("ip"),
                action="http_request", outcome=m.group("status"),
                fields=dict(method=m.group("method"), url=url, url_decoded=decoded, status=int(m.group("status")),
                            bytes=_int(m.group("bytes")) or 0, referer=m.group("ref"), ua=m.group("ua")))


# --------------------------------------------------------------------------- Firewalls
FW_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)(?:\s?(?P<tz>Z|UTC|[A-Z]{3,4}|[+-]\d\d:?\d\d))?\s+(?P<dev>\S+)\s+(?P<act>ALLOW|DENY|DROP|REJECT|ACCEPT)\s+(?P<proto>\w+)\s+(?P<sip>[\d.]+):(?P<sport>\d+)\s+->\s+(?P<dip>[\d.]+):(?P<dport>\d+)(?P<rest>.*)$")


def parse_fw(line: str, tr: TimeResolver) -> dict[str, Any]:
    m = FW_RE.match(line)
    if not m:
        raise ParseError("not a firewall session line")
    dt = tu.parse_naive(m.group("ts").replace("T", " "))
    if dt is None:
        raise ParseError("bad timestamp")
    ts, src, assumed = tr.resolve(dt, m.group("tz"))
    f = kv(m.group("rest"))
    act = {"DROP": "DENY", "REJECT": "DENY", "ACCEPT": "ALLOW"}.get(m.group("act"), m.group("act"))
    fields: dict[str, Any] = dict(device=m.group("dev"), proto=m.group("proto"), sport=int(m.group("sport")), dport=int(m.group("dport")), rule=f.get("rule"))
    total = _int(f.get("bytes_total")) if "bytes_total" in f else _int(f.get("bytes"))
    fields["bytes"] = total
    if "bytes_server_to_client" in f:
        fields["bytes_server_to_client"] = _int(f["bytes_server_to_client"])
    dur = tu.parse_duration(f["duration"]) if "duration" in f else None
    fields["duration_s"] = dur
    out: dict[str, Any] = dict(ts_utc=ts, ts_original=m.group("ts"), tz_source=src, tz_assumed=assumed, host=m.group("dev"),
                               ip_source=m.group("sip"), ip_dest=m.group("dip"), action="fw_session", outcome=act, fields=fields)
    logged_at = tr.policy.logged_at if tr.policy else None
    fields["logged_at"] = logged_at or "unknown"
    if logged_at == "close" and dur is not None:
        out.update(ts_start_utc=ts - timedelta(seconds=dur), ts_end_utc=ts)
    elif logged_at == "start":
        out.update(ts_start_utc=ts, ts_end_utc=(ts + timedelta(seconds=dur)) if dur is not None else None)
    return out


# --------------------------------------------------------------------------- Email gateway
EMAIL_RE = re.compile(r"^\[(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\s+(?P<tz>[A-Za-z]{1,5}|[+-]\d\d:?\d\d))?\]\s+(?P<rest>.*\bmsgid=.*)$")


def parse_email(line: str, tr: TimeResolver) -> dict[str, Any]:
    m = EMAIL_RE.match(line)
    if not m:
        raise ParseError("not an email-gateway line")
    dt = tu.parse_naive(m.group("ts"))
    if dt is None:
        raise ParseError("bad timestamp")
    ts, src, assumed = tr.resolve(dt, m.group("tz"))
    f: dict[str, Any] = kv(m.group("rest"))
    if "to" not in f or "from" not in f:
        raise ParseError("email line without from/to")
    try:
        f["score"] = float(f["score"]) if "score" in f else None
    except ValueError:
        f["score"] = None
    return dict(ts_utc=ts, ts_original=m.group("ts") + (f" {m.group('tz')}" if m.group("tz") else ""), tz_source=src, tz_assumed=assumed,
                user_account=norm_user(f["to"]), action="email", outcome=str(f.get("action", "")).lower(), fields=f)


# --------------------------------------------------------------------------- DHCP
DHCP_RE = re.compile(r"^(?P<ts>\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(?:\s+(?P<tz>[+-]\d\d:?\d\d|Z|UTC|[A-Z]{3,4}))?\s+(?P<kind>DHCP[A-Z]+)\s+(?P<rest>.*)$")


def parse_dhcp(line: str, tr: TimeResolver) -> dict[str, Any]:
    m = DHCP_RE.match(line)
    if not m:
        raise ParseError("not a DHCP line")
    dt = tu.parse_naive(m.group("ts"))
    if dt is None:
        raise ParseError("bad timestamp")
    ts, src, assumed = tr.resolve(dt, m.group("tz"))
    f: dict[str, Any] = kv(m.group("rest"))
    if "ip" not in f:
        raise ParseError("DHCP line without ip")
    lease = tu.parse_duration(f.get("lease", "")) if f.get("lease") else None
    f["lease_s"] = lease
    return dict(ts_utc=ts, ts_original=m.group("ts") + (f" {m.group('tz')}" if m.group("tz") else ""), tz_source=src, tz_assumed=assumed,
                host=f.get("hostname"), ip_source=f["ip"], action="dhcp_" + m.group("kind")[4:].lower(), outcome=m.group("kind"),
                ts_start_utc=ts, ts_end_utc=(ts + timedelta(seconds=lease)) if lease else None, fields=f)


# --------------------------------------------------------------------------- Generic fallback
GENERIC_TS = re.compile(r"(\d{4}-\d\d-\d\d[T ]\d\d:\d\d:\d\d(?:\.\d+)?)\s?(Z|[+-]\d\d:?\d\d|[A-Z]{2,5})?")


def parse_generic(line: str, tr: TimeResolver) -> dict[str, Any]:
    """Unknown format: keep what can be established (a timestamp, IPs, key=value
    pairs) so the line is still citable and searchable."""
    m = GENERIC_TS.search(line)
    dt = None
    tz = None
    original = ""
    if m:
        dt = tu.parse_iso(m.group(1).replace(" ", "T"))
        tz = m.group(2) if m.group(2) and tu.parse_offset(m.group(2)) else None
        original = m.group(0).strip()
    else:
        ep = re.search(r"\b(\d{13}|\d{10})\b", line)
        if ep:
            dt, original = tu.parse_epoch(ep.group(1)), ep.group(1)
    if dt is None:
        raise ParseError("no recognisable timestamp")
    ts, src, assumed = tr.resolve(dt, tz)
    ips = IP_RE.findall(line)
    f = kv(line)
    return dict(ts_utc=ts, ts_original=original, tz_source=src, tz_assumed=assumed, ip_source=ips[0] if ips else None,
                ip_dest=ips[1] if len(ips) > 1 else None, user_account=norm_user(f.get("user") or f.get("account")),
                action="generic", outcome=f.get("result", ""), fields=f)


PARSERS: dict[str, Callable[[str, TimeResolver], dict[str, Any]]] = {
    "vpn": parse_vpn, "dc": parse_dc, "web": parse_web, "fw": parse_fw, "email": parse_email, "dhcp": parse_dhcp,
}


def detect_format(lines: list[str]) -> tuple[str, int]:
    """Content sniffing: the parser that accepts the most lines wins."""
    probe = TimeResolver(None)
    best, best_n = "generic", 0
    for name, fn in PARSERS.items():
        n = 0
        for ln in lines:
            try:
                fn(ln, probe)
                n += 1
            except ParseError:
                pass
            except Exception:  # noqa: BLE001
                pass
        if n > best_n:
            best, best_n = name, n
    return best, best_n


def _mk_event(f: SourceFile, locator: str, line_no: int, raw: str, source_type: str, data: dict[str, Any]) -> Event:
    return Event(id=f"{f.filename}:{locator}", source_file=f.filename, line_no=line_no, locator=locator, raw_line=raw, source_type=source_type, **data)


def parse_log_file(f: SourceFile, refs: References) -> tuple[list[Event], dict[str, Any]]:
    """Parse one fenced-code-block log file. Returns (events incl. quarantined, audit)."""
    units = [u for u in f.units if u.kind == "log"]
    lines = [u.text for u in units]
    fmt, matched = detect_format(lines)
    policy = refs.tz_policies.get(f.filename)
    tr = TimeResolver(policy)
    parser = PARSERS.get(fmt, parse_generic)
    file_asset = next((a.hostname for a in refs.assets if re.search(rf"\b{re.escape(a.hostname)}\b", f.title, re.I)), None)
    events: list[Event] = []
    seen: dict[str, str] = {}
    for u in units:
        line_no = int(u.locator[1:])
        raw = u.text
        try:
            ev = _mk_event(f, u.locator, line_no, raw, fmt, parser(raw, tr))
        except Exception as exc:  # noqa: BLE001 - malformed input must never crash the run
            reason = f"malformed line: {exc}" if isinstance(exc, ParseError) else f"parser error: {type(exc).__name__}: {exc}"
            events.append(Event(id=f"{f.filename}:{u.locator}", source_file=f.filename, line_no=line_no, locator=u.locator,
                                raw_line=raw, source_type=fmt, parse_status="quarantined", quarantine_reason=reason, action="quarantined"))
            continue
        if fmt == "fw":
            ev.source_type = "fw_int" if (policy and policy.logged_at == "close") or _all_internal(lines) else "fw_edge"
        if fmt in ("web", "vpn", "dc") and file_asset:
            ev.fields["file_asset"] = file_asset
        if raw in seen:
            ev.flags.append("DUPLICATE_OF:" + seen[raw])  # log-shipping duplicate: kept and citable, ignored by detectors
        else:
            seen[raw] = ev.id
        hits = injection.scan(raw)
        if hits:
            ev.flags.append("PROMPT_INJECTION")
            ev.fields["injection_signatures"] = hits
            ev.quarantine_reason = "prompt-injection signature: " + ", ".join(hits)
        events.append(ev)

    audit = dict(file=f.filename, format=fmt, lines=len(units), parsed=sum(1 for e in events if e.parse_status == "parsed"),
                 quarantined=[dict(ref=e.id, reason=e.quarantine_reason, raw=e.raw_line) for e in events if e.parse_status == "quarantined"],
                 duplicates=[e.id for e in events if any(fl.startswith("DUPLICATE_OF") for fl in e.flags)],
                 tz_policy=(policy.label if policy else "none"), tz_assumed=any(e.tz_assumed for e in events))
    return events, audit


def _all_internal(lines: list[str]) -> bool:
    from .references import is_internal_ip
    ips = [ip for ln in lines for ip in IP_RE.findall(ln)]
    return bool(ips) and all(is_internal_ip(ip) for ip in ips)


def is_internal_only(line: str) -> bool:
    from .references import is_internal_ip
    ips = IP_RE.findall(line)
    return bool(ips) and all(is_internal_ip(ip) for ip in ips)


def parse_ids_file(f: SourceFile, refs: References) -> tuple[list[Event], dict[str, Any]]:
    """IDS alert summary is a markdown table; each row becomes one Event cited by alert ID."""
    from .references import col
    policy = refs.tz_policies.get(f.filename)
    tr = TimeResolver(policy)
    events: list[Event] = []
    n = 0
    for tb in f.tables:
        for r in tb.rows:
            n += 1
            raw_ts = col(r, "time")
            m = re.match(r"^(\d{4}-\d\d-\d\d[ T]\d\d:\d\d:\d\d)\s*([A-Za-z]{1,5}|[+-]\d\d:?\d\d)?$", raw_ts)
            dt = tu.parse_naive(m.group(1).replace("T", " ")) if m else None
            if dt is None:
                events.append(Event(id=f"{f.filename}:{r.locator}", source_file=f.filename, line_no=n, locator=r.locator, raw_line=r.text,
                                    source_type="ids", parse_status="quarantined", quarantine_reason="alert row without a readable time", action="quarantined"))
                continue
            ts, src, assumed = tr.resolve(dt, m.group(2))
            desc = col(r, "description")
            ev = Event(id=f"{f.filename}:{r.locator}", source_file=f.filename, line_no=n, locator=r.locator, raw_line=r.text, source_type="ids",
                       ts_utc=ts, ts_original=raw_ts, tz_source=src, tz_assumed=assumed, action="ids_alert", outcome="ALERT",
                       fields=dict(alert_id=col(r, "alert id", "alert"), sensor=col(r, "sensor"), description=desc,
                                   ips=[ip for ip in IP_RE.findall(CIDR_RE.sub(" ", desc))], cidrs=CIDR_RE.findall(desc),
                                   domains=[d for d in DOMAIN_RE.findall(desc)],
                                   users=[u.username for u in refs.users if re.search(rf"\b{re.escape(u.username)}\b", desc)],
                                   hosts=[a.hostname for a in refs.assets if re.search(rf"\b{re.escape(a.hostname)}\b", desc)]))
            hits = injection.scan(r.text)
            if hits:
                ev.flags.append("PROMPT_INJECTION")
                ev.fields["injection_signatures"] = hits
            events.append(ev)
    audit = dict(file=f.filename, format="ids-table", lines=n, parsed=sum(1 for e in events if e.parse_status == "parsed"),
                 quarantined=[dict(ref=e.id, reason=e.quarantine_reason, raw=e.raw_line) for e in events if e.parse_status == "quarantined"],
                 duplicates=[], tz_policy=(policy.label if policy else "none"), tz_assumed=any(e.tz_assumed for e in events))
    return events, audit


SOURCE_PRIORITY = {"email": 0, "dhcp": 1, "fw_edge": 2, "vpn": 3, "dc": 4, "fw_int": 5, "web": 6, "ids": 7}


def sort_key(e: Event) -> tuple:
    """Deterministic ordering: time, then source priority, then line number."""
    return (e.ts_utc or datetime.max.replace(tzinfo=tu.UTC), SOURCE_PRIORITY.get(e.source_type, 9), e.source_file, e.line_no)
