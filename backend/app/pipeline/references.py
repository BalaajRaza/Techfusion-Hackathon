"""Parsers for the reference files: asset inventory, user directory, severity
matrix, escalation sheet, change calendar, runbooks, security rules and the
log source coverage sheet. All values used later come from these tables - no
hostname, user, IP or SLA is hard-coded in the pipeline.
"""
from __future__ import annotations

import ipaddress
import re
from datetime import datetime, timedelta
from typing import Any, Optional

from pydantic import BaseModel, Field

from ..models import Citation, SourceFile, Table, TableRow
from . import timeutil as tu

IP_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d|\.\d)")
CIDR_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}/\d{1,2}")
HHMM = r"\d{1,2}:\d{2}(?::\d{2})?"


def col(row: TableRow, *keys: str) -> str:
    for k in keys:
        for h, v in row.cells.items():
            if k in h.lower():
                return v.strip()
    return ""


def cite_row(f: SourceFile, row: TableRow) -> Citation:
    return Citation(file=f.filename, locator=row.locator, text=row.text)


def cite_unit(f: SourceFile, locator: str) -> Citation:
    u = f.unit(locator)
    return Citation(file=f.filename, locator=locator, text=u.text if u else "")


class Asset(BaseModel):
    tag: str
    hostname: str
    type: str
    ips: list[str]
    public_ips: list[str] = Field(default_factory=list)
    owner: str
    owner_person: Optional[str] = None
    data_owner: Optional[str] = None
    criticality: str
    citation: Citation


class DirUser(BaseModel):
    username: str
    full_name: str
    email: str
    role: str
    laptop_tag: str
    phone: str
    manager: str
    citation: Citation


class ChangeEntry(BaseModel):
    change_id: str
    date: str
    window_text: str
    tz_label: str
    start_utc: Optional[datetime] = None
    end_utc: Optional[datetime] = None
    system_target: str
    scope_hosts: list[str] = Field(default_factory=list)
    scope_cidrs: list[str] = Field(default_factory=list)
    performed_by: str
    actor_hosts: list[str] = Field(default_factory=list)
    actor_ips: list[str] = Field(default_factory=list)
    actor_users: list[str] = Field(default_factory=list)
    description: str
    status: str
    approved: bool = False
    citation: Citation


class MatrixRow(BaseModel):
    label: str
    cells: dict[str, str]
    citation: Citation


class EscalationRow(BaseModel):
    severity: str
    who: str
    time_limit: str
    minutes: Optional[int] = None
    how: str
    citation: Citation


class RunbookStep(BaseModel):
    no: int
    text: str
    citation: Citation


class Runbook(BaseModel):
    runbook_id: str
    title: str
    file: str
    steps: list[RunbookStep]
    title_citation: Citation


class CoverageRow(BaseModel):
    source: str
    file: str
    tz_text: str
    coverage_text: str
    notes: str
    citation: Citation


class Gap(BaseModel):
    source: str
    file: str
    start_utc: Optional[datetime]
    end_utc: Optional[datetime]
    kind: str          # outage | outside_coverage
    reason: str
    citation: Citation


class MissingSource(BaseModel):
    text: str
    tags: list[str]
    citation: Citation


class TzPolicy(BaseModel):
    mode: str          # inline | fixed | assumed
    offset_hours: float = 0.0
    label: str = "UTC"
    logged_at: Optional[str] = None  # start | close
    citation: Optional[Citation] = None


class References(BaseModel):
    assets: list[Asset] = Field(default_factory=list)
    users: list[DirUser] = Field(default_factory=list)
    changes: list[ChangeEntry] = Field(default_factory=list)
    matrix: list[MatrixRow] = Field(default_factory=list)
    matrix_notes: list[Citation] = Field(default_factory=list)
    escalation: list[EscalationRow] = Field(default_factory=list)
    escalation_notes: list[Citation] = Field(default_factory=list)
    runbooks: list[Runbook] = Field(default_factory=list)
    rules: dict[str, Citation] = Field(default_factory=dict)
    coverage: list[CoverageRow] = Field(default_factory=list)
    gaps: list[Gap] = Field(default_factory=list)
    missing_sources: list[MissingSource] = Field(default_factory=list)
    tz_policies: dict[str, TzPolicy] = Field(default_factory=dict)
    local_tz_label: str = "PKT"
    local_tz_hours: float = 5.0
    local_tz_citation: Optional[Citation] = None
    vpn_pool: Optional[tuple[str, str]] = None
    vpn_pool_citation: Optional[Citation] = None
    internal_domain: Optional[str] = None
    internal_domain_citation: Optional[Citation] = None
    company_email_domain: Optional[str] = None
    log_date: Optional[str] = None
    quarantine_score: Optional[float] = None
    quarantine_score_citation: Optional[Citation] = None

    # ---- lookups -----------------------------------------------------------
    def asset_by_name(self, name: Optional[str]) -> Optional[Asset]:
        """Hostname match tolerant to case, FQDN and the SRV- prefix
        (the inventory note says FS01.orbit.local is SRV-FS01)."""
        if not name:
            return None
        n = name.strip().upper().split(":")[0]
        if self.internal_domain and n.endswith("." + self.internal_domain.upper()):
            n = n[: -len(self.internal_domain) - 1]
        for a in self.assets:
            h = a.hostname.upper()
            if n == h or n == a.tag.upper():
                return a
        for a in self.assets:
            h = a.hostname.upper()
            if "-" in h and h.split("-", 1)[1] == n:
                return a
        return None

    def asset_by_ip(self, ip: Optional[str]) -> Optional[Asset]:
        if not ip:
            return None
        for a in self.assets:
            if ip in a.ips or ip in a.public_ips:
                return a
        return None

    def asset_by_tag(self, tag: str) -> Optional[Asset]:
        return next((a for a in self.assets if a.tag == tag), None)

    def user(self, username: Optional[str]) -> Optional[DirUser]:
        if not username:
            return None
        return next((u for u in self.users if u.username == username.lower()), None)

    def user_by_name(self, full_name: str) -> Optional[DirUser]:
        return next((u for u in self.users if u.full_name.lower() == full_name.strip().lower()), None)

    def in_vpn_pool(self, ip: Optional[str]) -> bool:
        if not ip or not self.vpn_pool:
            return False
        try:
            lo, hi = (ipaddress.ip_address(x) for x in self.vpn_pool)
            return lo <= ipaddress.ip_address(ip) <= hi
        except ValueError:
            return False

    def runbook_for(self, key: str) -> Optional[Runbook]:
        pat = RUNBOOK_KEYS.get(key)
        if not pat:
            return None
        return next((rb for rb in self.runbooks if re.search(pat, rb.title, re.I)), None)

    def matrix_row(self, key: str) -> Optional[MatrixRow]:
        pat = MATRIX_KEYS.get(key)
        if not pat:
            return None
        return next((r for r in self.matrix if re.search(pat, r.label, re.I)), None)


# incident-type key -> pattern matched against the runbook title / matrix row label
RUNBOOK_KEYS = {
    "phishing": r"phish",
    "credential_compromise": r"credential",
    "web_attack": r"web application|web attack",
    "data_exfiltration": r"exfil",
    "recon": r"scan|recon",
    "malware": r"malware",
}
MATRIX_KEYS = {
    "phishing_no_click": r"phishing.*no click",
    "credential_compromise": r"credential compromise",
    "data_exfiltration": r"data exfiltration",
    "web_attack_attempt": r"web application attack.*attempts only",
    "web_attack_success": r"web application attack.*success",
    "recon": r"scanning|reconnaissance",
    "malware": r"malware",
}

INTERNAL_NETS = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def is_internal_ip(ip: Optional[str]) -> bool:
    """RFC 1918 only. (ipaddress.is_private would also call the documentation
    ranges 192.0.2.0/24, 198.51.100.0/24 and 203.0.113.0/24 private.)"""
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in n for n in INTERNAL_NETS)


def _parse_minutes(text: str) -> Optional[int]:
    m = re.search(r"(\d+)\s*(minute|min|hour|hr)", text.lower())
    if not m:
        return None
    return int(m.group(1)) * (60 if m.group(2).startswith("h") else 1)


def _window_utc(date: str, window: str, tz_hours: float) -> tuple[Optional[datetime], Optional[datetime]]:
    m = re.search(rf"({HHMM})\s*(?:-|to|–)\s*({HHMM})", window)
    d = tu.parse_naive(f"{date} 00:00:00")
    if not m or d is None:
        return None, None
    tz = tu.tz_from_hours(tz_hours)

    def at(hhmm: str) -> datetime:
        parts = [int(p) for p in hhmm.split(":")] + [0]
        return d.replace(hour=parts[0], minute=parts[1], second=parts[2], tzinfo=tz)

    start, end = at(m.group(1)), at(m.group(2))
    if end <= start:  # window crosses midnight
        end += timedelta(days=1)
    return tu.to_utc(start), tu.to_utc(end)


def build_references(files: dict[str, SourceFile]) -> References:
    refs = References()
    by_type: dict[str, list[SourceFile]] = {}
    for f in files.values():
        by_type.setdefault(f.source_type, []).append(f)

    # --- security rules: numbered rules + the company time zone ------------
    for f in by_type.get("rules", []):
        for u in f.units:
            if u.kind == "rule":
                refs.rules[u.locator[1:]] = Citation(file=f.filename, locator=u.locator, text=u.text)
                m = re.search(r"\b([A-Z]{2,5})\s*\(UTC\s*([+-]\d{1,2}(?:\.\d)?)", u.text)
                if m and refs.local_tz_citation is None:
                    refs.local_tz_label, refs.local_tz_hours = m.group(1), float(m.group(2))
                    refs.local_tz_citation = Citation(file=f.filename, locator=u.locator, text=u.text)
    tu.TZ_ABBR[refs.local_tz_label] = refs.local_tz_hours

    # --- asset inventory ----------------------------------------------------
    for f in by_type.get("inventory", []):
        for tb in f.tables:
            for r in tb.rows:
                ip_cell = col(r, "ip")
                all_ips = IP_RE.findall(ip_cell)
                pub = IP_RE.findall(ip_cell.split("public", 1)[1]) if "public" in ip_cell else []
                owner = col(r, "owner")
                m_data = re.search(r"data owner:\s*([^,)]+)(?:,\s*([^)]+))?", owner)
                m_person = re.search(r"\(([^():]+)\)", owner)
                person = m_person.group(1).strip() if m_person else (owner if re.fullmatch(r"[A-Z][a-z]+ [A-Z][a-z]+", owner) else None)
                refs.assets.append(Asset(
                    tag=col(r, "tag"), hostname=col(r, "hostname"), type=col(r, "type"),
                    ips=[i for i in all_ips if i not in pub], public_ips=pub, owner=owner,
                    owner_person=person,
                    data_owner=(m_data.group(1).strip() + (f", {m_data.group(2).strip()}" if m_data.group(2) else "")) if m_data else None,
                    criticality=col(r, "criticality"), citation=cite_row(f, r),
                ))
        for u in f.units:
            if u.kind != "text":
                continue
            m = re.search(r"pool\s+(\d+\.\d+\.\d+\.\d+)\s+to\s+(\d+\.\d+\.\d+\.\d+)", u.text)
            if m:
                refs.vpn_pool = (m.group(1), m.group(2))
                refs.vpn_pool_citation = Citation(file=f.filename, locator=u.locator, text=u.text)
            m = re.search(r"[Dd]omain name[^:]*:\s*([a-z0-9.\-]+\.[a-z]+)", u.text)
            if m:
                refs.internal_domain = m.group(1)
                refs.internal_domain_citation = Citation(file=f.filename, locator=u.locator, text=u.text)

    # --- user directory -----------------------------------------------------
    for f in by_type.get("directory", []):
        for tb in f.tables:
            for r in tb.rows:
                refs.users.append(DirUser(
                    username=col(r, "username").lower(), full_name=col(r, "full name", "name"),
                    email=col(r, "email"), role=col(r, "role"), laptop_tag=col(r, "laptop"),
                    phone=col(r, "phone"), manager=col(r, "manager"), citation=cite_row(f, r),
                ))
    domains = [u.email.split("@", 1)[1].lower() for u in refs.users if "@" in u.email]
    if domains:
        refs.company_email_domain = max(set(domains), key=domains.count)

    # --- severity matrix ----------------------------------------------------
    for f in by_type.get("matrix", []):
        for tb in f.tables:
            for r in tb.rows:
                cells = dict(r.cells)
                label = cells.pop(tb.headers[0])
                refs.matrix.append(MatrixRow(label=label, cells={k.strip(): v.strip() for k, v in cells.items()}, citation=cite_row(f, r)))
        refs.matrix_notes = [Citation(file=f.filename, locator=u.locator, text=u.text) for u in f.units if u.kind == "text" and u.text.startswith("-")]

    # --- escalation sheet ---------------------------------------------------
    for f in by_type.get("escalation", []):
        for tb in f.tables:
            for r in tb.rows:
                limit = col(r, "time limit", "limit")
                refs.escalation.append(EscalationRow(
                    severity=col(r, "severity"), who=col(r, "who"), time_limit=limit,
                    minutes=_parse_minutes(limit), how=col(r, "how"), citation=cite_row(f, r),
                ))
        refs.escalation_notes = [Citation(file=f.filename, locator=u.locator, text=u.text) for u in f.units if u.kind == "text" and u.text.lower().startswith("note")]

    # --- runbooks -----------------------------------------------------------
    for f in by_type.get("runbook", []):
        m = re.search(r"\b(RB-[A-Z]+-\d+)\b", f.title)
        title_unit = next((u for u in f.units if u.kind == "text"), None)
        steps = [RunbookStep(no=int(u.locator[1:]), text=re.sub(r"^\d+\.\s+", "", u.text), citation=Citation(file=f.filename, locator=u.locator, text=u.text)) for u in f.units if u.kind == "step"]
        refs.runbooks.append(Runbook(
            runbook_id=m.group(1) if m else f.filename, title=f.title, file=f.filename, steps=steps,
            title_citation=Citation(file=f.filename, locator=title_unit.locator if title_unit else "F1", text=f.title),
        ))

    # --- log source coverage sheet -----------------------------------------
    for f in by_type.get("coverage", []):
        in_missing = False
        for tb in f.tables:
            cov_header = next((h for h in tb.headers if "coverage" in h.lower()), "")
            m = re.search(r"\d{4}-\d{2}-\d{2}", cov_header)
            if m:
                refs.log_date = m.group(0)
            for r in tb.rows:
                refs.coverage.append(CoverageRow(
                    source=col(r, "source"), file=col(r, "file"), tz_text=col(r, "time zone", "zone"),
                    coverage_text=col(r, "coverage"), notes=col(r, "note"), citation=cite_row(f, r),
                ))
        for u in f.units:
            if u.kind != "text":
                continue
            if re.search(r"not?\s+exist|not\s+collected", u.text, re.I) and not u.text.startswith("-"):
                in_missing = True
                continue
            if in_missing and u.text.startswith("-"):
                refs.missing_sources.append(MissingSource(text=u.text.lstrip("- ").strip(), tags=_missing_tags(u.text), citation=Citation(file=f.filename, locator=u.locator, text=u.text)))

    for row in refs.coverage:
        refs.tz_policies[row.file] = _tz_policy(row, refs)
        refs.gaps.extend(_gaps(row, refs))
        m = re.search(r"score\s+(\d+(?:\.\d+)?)\s+or higher are quarantined", row.notes, re.I)
        if m:
            refs.quarantine_score = float(m.group(1))
            refs.quarantine_score_citation = row.citation

    # --- change calendar ----------------------------------------------------
    for f in by_type.get("calendar", []):
        for tb in f.tables:
            window_header = next((h for h in tb.headers if "window" in h.lower()), "")
            m = re.search(r"\(([A-Z]{2,5})\)", window_header) or re.search(r"times\s+([A-Z]{2,5})", f.title)
            label = m.group(1) if m else refs.local_tz_label
            hours = tu.TZ_ABBR.get(label, refs.local_tz_hours)
            for r in tb.rows:
                refs.changes.append(_change_entry(f, r, label, hours, refs))
    return refs


def _missing_tags(text: str) -> list[str]:
    t = text.lower()
    tags = []
    for tag, pat in (("file_audit", r"file access|audit"), ("db", r"query log|database|db01"), ("proxy", r"proxy"),
                     ("edr", r"edr|endpoint"), ("other_dates", r"dates other than|other dates")):
        if re.search(pat, t):
            tags.append(tag)
    for host in re.findall(r"\b[A-Z]{2,}-[A-Z0-9]+\b", text):
        tags.append("host:" + host)
    return tags


def _tz_policy(row: CoverageRow, refs: References) -> TzPolicy:
    t = row.tz_text
    logged = None
    if re.search(r"session closes|logged when .* closes", row.notes, re.I):
        logged = "close"
    elif re.search(r"connection starts|logged when .* starts", row.notes, re.I):
        logged = "start"
    if re.search(r"offset in each line", t, re.I):
        return TzPolicy(mode="inline", label="offset in each line", logged_at=logged, citation=row.citation)
    m = re.search(r"UTC\s*([+-]\d{1,2}(?:\.\d)?)", t)
    if m:
        abbr = re.search(r"\b([A-Z]{3,5})\b", t.replace("UTC", ""))
        return TzPolicy(mode="fixed", offset_hours=float(m.group(1)), label=abbr.group(1) if abbr else f"UTC{m.group(1)}", logged_at=logged, citation=row.citation)
    for abbr, hours in tu.TZ_ABBR.items():
        if abbr not in ("UTC", "Z", "GMT") and re.search(rf"\b{abbr}\b", t):
            return TzPolicy(mode="fixed", offset_hours=hours, label=abbr, logged_at=logged, citation=row.citation)
    if "UTC" in t.upper():
        return TzPolicy(mode="fixed", offset_hours=0, label="UTC", logged_at=logged, citation=row.citation)
    return TzPolicy(mode="assumed", label="UTC (assumed)", logged_at=logged, citation=row.citation)


def _gaps(row: CoverageRow, refs: References) -> list[Gap]:
    """Turn the 'Coverage' text into explicit UTC intervals with no logs."""
    out: list[Gap] = []
    text = row.coverage_text
    date = refs.log_date
    if not date:
        return out
    policy = refs.tz_policies.get(row.file)
    default_hours = policy.offset_hours if policy and policy.mode == "fixed" else 0.0

    def hours_for(abbr: Optional[str]) -> float:
        return tu.TZ_ABBR.get(abbr, default_hours) if abbr else default_hours

    m = re.search(rf"except\s+({HHMM})\s+to\s+({HHMM})\s*([A-Z]{{2,5}})?", text)
    if m:
        s, e = _window_utc(date, f"{m.group(1)} - {m.group(2)}", hours_for(m.group(3)))
        out.append(Gap(source=row.source, file=row.file, start_utc=s, end_utc=e, kind="outage", reason=row.notes or text, citation=row.citation))
    m = re.search(rf"({HHMM})\s+to\s+({HHMM})\s*([A-Z]{{2,5}})?\s+only", text)
    if m:
        s, e = _window_utc(date, f"{m.group(1)} - {m.group(2)}", hours_for(m.group(3)))
        day = tu.parse_naive(f"{date} 00:00:00").replace(tzinfo=tu.UTC)
        if s and s > day:
            out.append(Gap(source=row.source, file=row.file, start_utc=day, end_utc=s, kind="outside_coverage", reason=row.notes or text, citation=row.citation))
        if e and e < day + timedelta(days=1):
            out.append(Gap(source=row.source, file=row.file, start_utc=e, end_utc=day + timedelta(days=1), kind="outside_coverage", reason=row.notes or text, citation=row.citation))
    return out


def _change_entry(f: SourceFile, r: TableRow, label: str, hours: float, refs: References) -> ChangeEntry:
    target = col(r, "system", "target")
    by = col(r, "performed")
    status = col(r, "status")
    date = col(r, "date")
    window = col(r, "window")
    start, end = _window_utc(date, window, hours)

    def hosts_in(text: str) -> list[str]:
        return [a.hostname for a in refs.assets if re.search(rf"\b{re.escape(a.hostname)}\b", text, re.I)]

    actor_users = [u.username for u in refs.users if re.search(rf"\b{re.escape(u.username)}\b", by, re.I) or u.full_name.lower() in by.lower()]
    s = status.lower()
    approved = (s.startswith("approved") or s.startswith("completed")) and not re.search(r"not performed|postponed|cancel|reject|requested|pending", s)
    return ChangeEntry(
        change_id=col(r, "change id", "change"), date=date, window_text=window, tz_label=label,
        start_utc=start, end_utc=end, system_target=target, scope_hosts=hosts_in(target),
        scope_cidrs=CIDR_RE.findall(target), performed_by=by, actor_hosts=hosts_in(by),
        actor_ips=IP_RE.findall(by), actor_users=actor_users, description=col(r, "description"),
        status=status, approved=approved, citation=cite_row(f, r),
    )
