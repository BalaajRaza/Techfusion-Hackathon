"""One planted example per edge case (scripts/build_edge_pack.py) and its expected outcome."""
from datetime import datetime, timezone

from .conftest import claims_text, inc_by


def test_malformed_lines_quarantined_with_citation(edge):
    q = {x["ref"]: x for x in edge.case["parsing_audit"]["quarantined"]}
    assert "13_web_server_log.md:L15" in q and "21_badge_access_log.md:L3" in q


def test_prompt_injection_is_a_finding_and_never_reaches_the_model(edge):
    hits = edge.case["parsing_audit"]["injection_hits"]
    assert any(h["ref"] == "13_web_server_log.md:L14" for h in hits)
    inc = inc_by(edge, "Prompt-injection")
    assert inc["severity"] is None and inc["status"] == "NEEDS_REVIEW"   # no matrix row: human decision
    from app.security import injection
    raw = edge.ctx.by_id["13_web_server_log.md:L14"].raw_line
    assert "Ignore all previous" not in injection.sandbox(raw)


def test_unknown_format_and_unknown_zone_are_flagged(edge):
    src = {s["file"]: s for s in edge.case["time_normalization"]["sources"]}
    assert src["21_badge_access_log.md"]["tz_assumed"] is True


def test_duplicate_line_kept_but_not_double_counted(edge):
    assert "11_vpn_auth_log.md:L13" in edge.case["parsing_audit"]["duplicates"]


def test_approved_scanner_outside_window_or_out_of_scope_is_escalated(edge):
    inc = inc_by(edge, "from SCAN01")
    assert inc["severity"] is not None
    assert "APPROVED_ACTOR_OUTSIDE_WINDOW" in inc["flags"] or "APPROVED_ACTOR_OUT_OF_SCOPE_TARGET" in inc["flags"]
    # the real monthly scan is still closed as harmless
    assert any(x["change_id"] == "CHG-2026-1104-02" for x in edge.case["exclusions"])


def test_attacker_inside_maintenance_window_is_kept(edge):
    inc = inc_by(edge, "10.10.7.77")
    assert "RESIDUAL_ANOMALY_DURING_MAINTENANCE" in inc["flags"]
    assert "maintenance window" in claims_text(inc, "CONFIRMED")


def test_ip_reused_by_two_hosts_is_ambiguous(edge):
    r = edge.ctx.graph.resolve("10.20.5.14", datetime(2026, 11, 4, 12, 0, tzinfo=timezone.utc))
    assert r.ambiguous and set(r.candidates) == {"LT-TEMP-099", "LT-FIN-014"}


def test_all_edge_reports_pass_verifier(edge):
    for iid, r in edge.case["reports"].items():
        assert r["verifier_passed"], (iid, r["verifier"]["errors"])


def test_original_incidents_unchanged(edge):
    sev = {i["title"].split(" ")[0]: i["severity"] for i in edge.case["incidents"]}
    assert inc_by(edge, "amalik")["severity"] == "P1" and inc_by(edge, "SQL injection")["severity"] == "P2"
