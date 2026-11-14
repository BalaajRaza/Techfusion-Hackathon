"""Optional Supabase persistence (PostgREST with the service-role key).

The pipeline never depends on the database: without SUPABASE_URL the API
serves everything from memory. With it, POST /api/persist upserts the case
file into the tables of supabase/migrations. Row ids are UUIDv5 of the
citation, so re-running the pipeline updates rows instead of duplicating them.
"""
from __future__ import annotations

import ipaddress
import re
import uuid
from typing import Any, Optional

import httpx

from . import config

NS = uuid.UUID("6f1d0c1e-7c1b-5d0a-9b57-0f6f1e0c0b17")


def uid(*parts: str) -> str:
    return str(uuid.uuid5(NS, "|".join(parts)))


def status() -> dict[str, Any]:
    return dict(configured=bool(config.SUPABASE_URL and config.SUPABASE_SERVICE_KEY), url=config.SUPABASE_URL or None)


def _ip(value: Optional[str]) -> Optional[str]:
    try:
        return str(ipaddress.ip_address(value)) if value else None
    except ValueError:
        return None


class _Rest:
    def __init__(self) -> None:
        self.base = f"{config.SUPABASE_URL}/rest/v1"
        self.headers = {"apikey": config.SUPABASE_SERVICE_KEY, "Authorization": f"Bearer {config.SUPABASE_SERVICE_KEY}", "Content-Type": "application/json"}
        self.client = httpx.Client(timeout=30)

    def upsert(self, table: str, rows: list[dict[str, Any]], on_conflict: str) -> int:
        for i in range(0, len(rows), 500):  # batch inserts
            r = self.client.post(f"{self.base}/{table}", params={"on_conflict": on_conflict}, json=rows[i:i + 500],
                                 headers={**self.headers, "Prefer": "resolution=merge-duplicates,return=minimal"})
            if r.status_code >= 300:
                raise RuntimeError(f"{table}: HTTP {r.status_code} {r.text[:300]}")
        return len(rows)

    def delete(self, table: str, column: str, values: list[str]) -> None:
        if not values:
            return
        quoted = ",".join('"' + v.replace('"', "") + '"' for v in values)
        r = self.client.delete(f"{self.base}/{table}", params={column: f"in.({quoted})"}, headers=self.headers)
        if r.status_code >= 300:
            raise RuntimeError(f"{table} delete: HTTP {r.status_code} {r.text[:300]}")


def persist(rt: Any) -> dict[str, int]:
    case = rt.case
    rest = _Rest()
    out: dict[str, int] = {}
    out["raw_files"] = rest.upsert("raw_files", [dict(filename=f["filename"], file_type=f["file_type"], total_lines=f["total_lines"], sha256_hash=f["sha256"]) for f in case["files"]], "filename")

    events, quarantined = [], []
    for e in rt.events_dump:
        if e["parse_status"] != "parsed" or not e["ts_utc"]:
            quarantined.append(dict(id=uid("q", e["id"]), source_file=e["source_file"], locator=e["locator"], raw_line=e["raw_line"], reason=e["quarantine_reason"] or "unparsed"))
            continue
        events.append(dict(id=uid("event", e["id"]), source_file=e["source_file"], line_no=e["line_no"], locator=e["locator"], raw_line=e["raw_line"], ts_utc=e["ts_utc"],
                           ts_start_utc=e["ts_start_utc"], ts_end_utc=e["ts_end_utc"], ts_original=e["ts_original"], tz_source=e["tz_source"], tz_assumed=e["tz_assumed"],
                           source_type=e["source_type"], host=e["host"], ip_source=_ip(e["ip_source"]), ip_dest=_ip(e["ip_dest"]), user_account=e["user_account"],
                           action=e["action"], outcome=e["outcome"] or "", fields=e["fields"], parse_status="parsed", quarantine_reason=e["quarantine_reason"], flags=e["flags"]))
    out["events"] = rest.upsert("events", events, "id")
    out["quarantined_lines"] = rest.upsert("quarantined_lines", quarantined, "id") if quarantined else 0

    kinds = {"ip": "IP", "host": "HOSTNAME", "user": "USER", "tag": "ASSET_TAG"}
    graph = case["entity_graph"]
    out["entity_nodes"] = rest.upsert("entity_nodes", [dict(id=uid("node", n["id"]), entity_type=kinds[n["id"].split(":")[0]], entity_val=n["id"],
                                                            metadata={k: v for k, v in n.items() if k not in ("id", "entity_type")}) for n in graph["nodes"]], "entity_val")
    out["entity_edges"] = rest.upsert("entity_edges", [dict(id=uid("edge", e["source"], e["target"], e["relation"], e["citation"]), source_entity=e["source"], target_entity=e["target"],
                                                            relation=e["relation"], valid_from=e["valid_from"], valid_until=e["valid_until"], confidence=e["confidence"],
                                                            evidence_citation=e["citation"]) for e in graph["edges"]], "id")
    changes = []
    for c in case["change_calendar"]:
        m = re.search(r"(\d{1,2}:\d{2}(?::\d{2})?)\s*(?:-|to)\s*(\d{1,2}:\d{2}(?::\d{2})?)", c["window_text"])
        if not (m and c["start_utc"] and c["end_utc"]):
            continue
        changes.append(dict(change_id=c["change_id"], date=c["date"], window_start_pkt=m.group(1), window_end_pkt=m.group(2), window_start_utc=c["start_utc"], window_end_utc=c["end_utc"],
                            system_target=c["system_target"], target_ip_cidr=", ".join(c["scope_cidrs"]) or None, performed_by=c["performed_by"], description=c["description"], status=c["status"]))
    out["change_calendar"] = rest.upsert("change_calendar", changes, "change_id")

    ids = [i["incident_id"] for i in case["incidents"]]
    for table in ("evidence_claims", "runbook_actions"):  # drop rows of earlier runs that no longer exist
        rest.delete(table, "incident_id", ids)
    out["incidents"] = rest.upsert("incidents", [dict(
        incident_id=i["incident_id"], title=i["title"], incident_type=i["incident_type"], severity=i["severity"],
        severity_derivation=dict(parts=i["severity_parts"], steps=i["severity_steps"]), highest_criticality_asset=i["highest_criticality_asset"],
        detection_time_utc=i["detection_time_utc"], sla_deadline_utc=min((c["deadline_utc"] for c in i["contacts"] if c["deadline_utc"]), default=None), status=i["status"]) for i in case["incidents"]], "incident_id")
    out["evidence_claims"] = rest.upsert("evidence_claims", [dict(id=uid("claim", i["incident_id"], c["claim_id"]), incident_id=i["incident_id"], claim_id=c["claim_id"], claim_text=c["text"],
                                                                  status=c["status"], inference_rule=c["rule"], cited_sources=c["citations"]) for i in case["incidents"] for c in i["claims"]], "id")
    out["runbook_actions"] = rest.upsert("runbook_actions", [dict(id=uid("action", i["incident_id"], a["runbook_id"], str(a["step_no"])), incident_id=i["incident_id"], runbook_id=a["runbook_id"],
                                                                  step_no=a["step_no"], action_text=a["text"], status=a["status"], citation=f"{a['citation']['file']}:{a['citation']['locator']}")
                                                             for i in case["incidents"] for a in i["actions"]], "id")
    known = {e["source_file"] + ":" + e["locator"] for e in events}
    excl = []
    for x in case["exclusions"]:
        for c in x["events"] + x["alerts"]:
            ref = f"{c['file']}:{c['locator']}"
            if ref in known:
                excl.append(dict(id=uid("excl", ref, x["change_id"]), event_id=uid("event", ref), change_id=x["change_id"], exclusion_reason=x["reason"], matched_criteria=x["criteria"]))
    out["benign_exclusions"] = rest.upsert("benign_exclusions", excl, "id") if excl else 0
    digest = case["integrity"]["evidence_integrity_digest"]
    out["reports"] = rest.upsert("reports", [dict(id=uid("report", iid), incident_id=iid, markdown_content=r["markdown"], json_payload=next(i for i in case["incidents"] if i["incident_id"] == iid),
                                                  evidence_sha256=digest, verifier_passed=r["verifier_passed"], verifier_log=r["verifier"]) for iid, r in case["reports"].items()], "id")
    return out
