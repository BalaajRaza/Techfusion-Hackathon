"""Core data model. Every fact in the case file carries Citation objects that
point at an addressable unit (log line, table row, runbook step, rule) of a
source file, so grounding is structural rather than something a prompt asks for.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Literal, Optional

from pydantic import BaseModel, Field

Tier = Literal["CONFIRMED", "SUSPECTED", "INSUFFICIENT_EVIDENCE"]
TIER_LABEL = {
    "CONFIRMED": "Confirmed",
    "SUSPECTED": "Suspected",
    "INSUFFICIENT_EVIDENCE": "Not enough evidence in the logs",
}
CRIT_RANK = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
SEV_RANK = {"P1": 1, "P2": 2, "P3": 3, "P4": 4}


class Citation(BaseModel):
    file: str
    locator: str  # L7 (log line) | ALT-9002 / A-1005 / CHG-.. / username (table row) | S3 (step) | R2.4 (rule) | ROW3 | F15
    text: str = ""

    @property
    def ref(self) -> str:
        return f"{self.file}:{self.locator}"

    def __hash__(self) -> int:
        return hash((self.file, self.locator))


class Unit(BaseModel):
    """One addressable piece of a source file."""
    locator: str
    text: str
    file_line: int  # physical 1-based line in the markdown file
    kind: str       # log | blank | row | header | step | rule | text


class TableRow(BaseModel):
    locator: str
    cells: dict[str, str]
    file_line: int
    text: str


class Table(BaseModel):
    headers: list[str]
    header_line: int
    rows: list[TableRow] = Field(default_factory=list)


class SourceFile(BaseModel):
    filename: str
    title: str
    file_type: str            # log | reference | runbook
    source_type: str = "unknown"
    total_lines: int = 0      # log lines inside the code block, or addressable units
    sha256: str = ""
    units: list[Unit] = Field(default_factory=list)
    tables: list[Table] = Field(default_factory=list)

    def unit(self, locator: str) -> Optional[Unit]:
        for u in self.units:
            if u.locator == locator:
                return u
        return None


class Event(BaseModel):
    id: str                   # "<file>:<locator>" - the citation itself
    source_file: str
    line_no: int
    locator: str
    raw_line: str
    source_type: str
    ts_utc: Optional[datetime] = None        # the logged instant, normalised to UTC
    ts_start_utc: Optional[datetime] = None  # derived session start (close-logged sources)
    ts_end_utc: Optional[datetime] = None
    ts_original: str = ""
    tz_source: str = ""
    tz_assumed: bool = False
    host: Optional[str] = None
    ip_source: Optional[str] = None
    ip_dest: Optional[str] = None
    user_account: Optional[str] = None
    action: str = "unknown"
    outcome: str = ""
    fields: dict[str, Any] = Field(default_factory=dict)
    parse_status: str = "parsed"             # parsed | quarantined
    quarantine_reason: Optional[str] = None
    flags: list[str] = Field(default_factory=list)

    def cite(self) -> Citation:
        return Citation(file=self.source_file, locator=self.locator, text=self.raw_line)

    @property
    def start(self) -> Optional[datetime]:
        return self.ts_start_utc or self.ts_utc

    @property
    def end(self) -> Optional[datetime]:
        return self.ts_end_utc or self.ts_utc


class Finding(BaseModel):
    """Output of one deterministic detector."""
    id: str
    kind: str
    title: str
    primary: bool = True          # False = supporting only, never an incident by itself
    activity: str = "other"       # scan | remote_desktop | data_transfer | vpn_login | web_attack | ...
    actors: list[str] = Field(default_factory=list)  # pivot keys used for clustering
    event_ids: list[str] = Field(default_factory=list)
    alert_ids: list[str] = Field(default_factory=list)
    start: Optional[datetime] = None
    end: Optional[datetime] = None
    data: dict[str, Any] = Field(default_factory=dict)
    flags: list[str] = Field(default_factory=list)
    heuristics: list[str] = Field(default_factory=list)


class Claim(BaseModel):
    claim_id: str
    text: str
    status: Tier
    rule: Optional[str] = None    # inference rule, or the guess a "Suspected" claim needs
    citations: list[Citation] = Field(default_factory=list)
    entities: list[str] = Field(default_factory=list)
    topic: str = ""


class TimelineEntry(BaseModel):
    ts_utc: datetime
    ts_end_utc: Optional[datetime] = None
    label: str
    detail: str = ""
    phase: str = ""
    status: Tier = "CONFIRMED"
    citations: list[Citation] = Field(default_factory=list)


class SeverityPart(BaseModel):
    part: str
    matrix_row: Optional[str] = None
    matrix_citation: Optional[Citation] = None
    assets: list[dict[str, Any]] = Field(default_factory=list)
    driving_asset: Optional[str] = None
    criticality: Optional[str] = None
    result: Optional[str] = None
    steps: list[str] = Field(default_factory=list)
    citations: list[Citation] = Field(default_factory=list)
    note: Optional[str] = None


class RunbookAction(BaseModel):
    runbook_id: str
    step_no: int
    text: str
    citation: Citation
    context: Optional[str] = None            # what the evidence already says about this step
    context_citations: list[Citation] = Field(default_factory=list)
    status: str = "PENDING"                  # PENDING | ANSWERED_BY_EVIDENCE
    opened_because: Optional[str] = None
    opened_citations: list[Citation] = Field(default_factory=list)


class Contact(BaseModel):
    severity: str
    role: str
    name: Optional[str] = None
    contact: Optional[str] = None
    time_limit: str
    time_limit_minutes: Optional[int] = None
    how: str
    deadline_utc: Optional[datetime] = None
    deadline_alt_utc: Optional[datetime] = None   # counted from the moment this severity was first visible
    citations: list[Citation] = Field(default_factory=list)
    condition: Optional[str] = None
    condition_met: Optional[bool] = None
    note: Optional[str] = None


class Incident(BaseModel):
    incident_id: str
    title: str
    incident_type: str
    severity: Optional[str] = None
    confidence: str = "CONFIRMED"   # CONFIRMED activity | SUSPECTED_ONLY
    status: str = "TRIAGED"
    summary: list[dict[str, Any]] = Field(default_factory=list)   # [{text, claim_ids}]
    summary_source: str = "template"
    kill_chain: list[str] = Field(default_factory=list)
    highest_criticality_asset: Optional[str] = None
    detection_time_utc: Optional[datetime] = None
    detection_basis: str = ""
    detection_citations: list[Citation] = Field(default_factory=list)
    severity_reached_utc: Optional[datetime] = None
    severity_reached_basis: str = ""
    severity_parts: list[SeverityPart] = Field(default_factory=list)
    severity_steps: list[str] = Field(default_factory=list)
    timeline: list[TimelineEntry] = Field(default_factory=list)
    claims: list[Claim] = Field(default_factory=list)
    affected_assets: list[dict[str, Any]] = Field(default_factory=list)
    affected_accounts: list[dict[str, Any]] = Field(default_factory=list)
    attacker_ips: list[str] = Field(default_factory=list)
    gaps: list[dict[str, Any]] = Field(default_factory=list)
    actions: list[RunbookAction] = Field(default_factory=list)
    contacts: list[Contact] = Field(default_factory=list)
    alerts: list[dict[str, Any]] = Field(default_factory=list)
    finding_ids: list[str] = Field(default_factory=list)
    flags: list[str] = Field(default_factory=list)
    heuristics: list[str] = Field(default_factory=list)
    window_start_utc: Optional[datetime] = None
    window_end_utc: Optional[datetime] = None
