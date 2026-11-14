"""Expected triage of the 20-file Orbit Logistics data pack."""
from datetime import datetime, timezone

from app.pipeline.ingest import ingest_file
from app import config

from .conftest import claims_text, inc_by


def utc(h, m, s=0):
    return datetime(2026, 11, 4, h, m, s, tzinfo=timezone.utc)


# ---------------------------------------------------------------- stage 1-3
def test_all_20_files_classified(orbit):
    files = {f["filename"]: f for f in orbit.case["files"]}
    assert len(files) == 20
    assert sum(f["file_type"] == "log" for f in files.values()) == 8
    assert sum(f["file_type"] == "runbook" for f in files.values()) == 5
    assert files["17_ids_alert_summary.md"]["source_type"] == "ids"


def test_line_numbering_inside_code_block():
    f = ingest_file(config.DATA_DIR / "11_vpn_auth_log.md")
    assert f.unit("L1").text.startswith("2026-11-04T02:58:41Z")
    assert f.unit("L7").text.startswith("2026-11-04T05:49:12Z")
    assert f.total_lines == 12


def test_every_log_line_parsed_none_dropped(orbit):
    pa = orbit.case["parsing_audit"]
    assert pa["total_lines"] == 82 and pa["parsed"] == 82 and pa["quarantined"] == []


def test_time_zones(orbit):
    ev = orbit.ctx.by_id
    assert ev["15_firewall_internal_log.md:L6"].ts_utc == utc(6, 21, 19)          # PKT, no zone written
    assert ev["15_firewall_internal_log.md:L6"].ts_start_utc == utc(6, 3, 12)     # logged at close: minus 1087 s
    assert ev["16_email_gateway_log.md:L2"].ts_utc == utc(4, 12, 7)               # [.. PKT]
    assert ev["13_web_server_log.md:L9"].ts_utc == utc(6, 6, 2)                   # +0500 in the line
    assert ev["19_dhcp_lease_log.md:L2"].ts_utc == utc(3, 57, 40)                 # +05:00 in the line
    assert ev["14_firewall_perimeter_log.md:L8"].ts_utc == utc(4, 19, 40)         # UTC, no zone written
    assert not any(s["tz_assumed"] for s in orbit.case["time_normalization"]["sources"])


def test_no_clock_skew(orbit):
    assert "No clock skew" in orbit.case["time_normalization"]["clock_skew"]["verdict"]


# ---------------------------------------------------------------- stage 4
def test_temporal_resolution(orbit):
    g = orbit.ctx.graph
    r = g.resolve("10.10.3.45", utc(6, 10))
    assert (r.kind, r.user, r.session) == ("vpn_session", "amalik", "VS-20433")
    assert g.resolve("10.10.3.45", utc(8, 0)).session is None   # after the session ended
    r = g.resolve("10.20.5.14", utc(4, 19, 40))
    assert (r.hostname, r.user, r.confidence) == ("LT-FIN-014", "amalik", "HIGH")


# ---------------------------------------------------------------- stage 5-6
def test_four_separate_incidents(orbit):
    sev = sorted((i["severity"], i["title"]) for i in orbit.case["incidents"])
    assert [s for s, _ in sev] == ["P1", "P2", "P3", "P4"]


def test_noise_closed_with_change_ids_never_deleted(orbit):
    x = {e["change_id"]: e for e in orbit.case["exclusions"]}
    assert set(x) == {"CHG-2026-1104-02", "CHG-2026-1104-03"}
    assert all(c["ok"] for c in x["CHG-2026-1104-02"]["criteria"]) and len(x["CHG-2026-1104-02"]["criteria"]) == 5
    assert {c["locator"] for c in x["CHG-2026-1104-02"]["alerts"]} == {"ALT-9006"}
    assert {c["locator"] for c in x["CHG-2026-1104-03"]["alerts"]} == {"ALT-9007"}
    assert "12_windows_dc_auth_log.md:L11" in {f"{c['file']}:{c['locator']}" for c in x["CHG-2026-1104-03"]["events"]}
    disp = {a["alert_id"]: a["disposition"] for a in orbit.case["alert_dispositions"]}
    assert disp["ALT-9006"].startswith("CLOSED_AS_HARMLESS") and disp["ALT-9005"] == "INCIDENT"
    assert not any("SCAN01" in i["title"] or "braza" in i["title"] for i in orbit.case["incidents"])


def test_postponed_change_is_not_approved(orbit):
    chg = {c["change_id"]: c for c in orbit.case["change_calendar"]}
    assert chg["CHG-2026-1104-05"]["approved"] is False


# ---------------------------------------------------------------- stage 7
def test_p1_severity_derivation(orbit):
    inc = inc_by(orbit, "amalik")
    assert inc["severity"] == "P1" and inc["highest_criticality_asset"] == "SRV-FS01"
    parts = {p["part"]: p for p in inc["severity_parts"]}
    exfil = next(p for k, p in parts.items() if k.startswith("Data exfiltration"))
    assert (exfil["driving_asset"], exfil["criticality"], exfil["result"]) == ("SRV-FS01", "High", "P1")
    cred = next(p for k, p in parts.items() if k.startswith("Credential"))
    assert cred["result"] == "P2"   # SRV-DC01 only saw Kerberos traffic -> not "reached" (rule 4.1)


def test_web_attack_p2(orbit):
    inc = inc_by(orbit, "SQL injection")
    assert inc["severity"] == "P2" and inc["highest_criticality_asset"] == "SRV-WEB01"


# ---------------------------------------------------------------- stage 8-9
def test_ledger_tiers(orbit):
    inc = inc_by(orbit, "amalik")
    confirmed, suspected, insufficient = (claims_text(inc, s) for s in ("CONFIRMED", "SUSPECTED", "INSUFFICIENT_EVIDENCE"))
    assert "2,426,727,912 bytes" in confirmed
    assert "business data being taken" in suspected            # rule 2.4: transfer != theft
    assert "Which files or folders on SRV-FS01" in insufficient
    assert "06:32:00 UTC to 07:28:59 UTC" in insufficient       # firewall reboot overlaps session VS-20433
    for word in ("stolen", "leaked", "exfiltrated"):
        assert word not in confirmed.lower()


def test_every_claim_is_cited(orbit):
    for inc in orbit.case["incidents"]:
        for c in inc["claims"]:
            assert c["citations"], c["text"]


# ---------------------------------------------------------------- stage 10
def test_runbook_steps_only_from_files(orbit):
    inc = inc_by(orbit, "amalik")
    ids = {(a["runbook_id"], a["step_no"]) for a in inc["actions"]}
    assert ("RB-CRED-02", 2) in ids and ("RB-EXFIL-04", 5) in ids and ("RB-PHISH-01", 4) in ids
    valid = {(rb.runbook_id, s.no) for rb in orbit.refs.runbooks for s in rb.steps}
    assert ids <= valid


def test_p1_contacts_and_deadlines(orbit):
    inc = inc_by(orbit, "amalik")
    c = {x["role"]: x for x in inc["contacts"]}
    assert c["CISO"]["name"] == "Hamza Qureshi" and c["CISO"]["time_limit_minutes"] == 15
    assert c["CISO"]["deadline_utc"].startswith("2026-11-04T04:34:41")   # ALT-9002 + 15 min
    assert "Saima Noor" in c["Data owner of the affected system"]["name"]
    assert c["Legal and Compliance"]["condition_met"] is True


# ---------------------------------------------------------------- stage 11
def test_all_reports_pass_verifier(orbit):
    for iid, r in orbit.case["reports"].items():
        assert r["verifier_passed"], (iid, r["verifier"]["errors"])
        assert r["verifier"]["citations_checked"] > 50


def test_report_has_rule_7_sections(orbit):
    md = next(iter(orbit.case["reports"].values()))["markdown"]
    for s in ("Summary", "Timeline (UTC)", "Affected assets and accounts", "Severity", "Confirmed", "Suspected", "Not enough evidence in the logs",
              "Missing log sources", "Closed as harmless", "Recommended actions", "People to inform"):
        assert f"## {s}" in md


def test_integrity_digest_is_stable():
    from app.pipeline.run import run_pipeline
    a = run_pipeline("orbit", llm_mode="off").case["integrity"]
    b = run_pipeline("orbit", llm_mode="off").case["integrity"]
    assert a["raw_files_sha256"] == b["raw_files_sha256"] and a["parsed_events_sha256"] == b["parsed_events_sha256"]
