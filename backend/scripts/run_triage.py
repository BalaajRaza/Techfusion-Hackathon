"""CLI: run the pipeline and print a summary (or the full reports).

    python scripts/run_triage.py [dataset] [--llm auto|local|cloud|off] [--report] [--json out.json]
"""
import argparse
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.pipeline.run import run_pipeline  # noqa: E402

ap = argparse.ArgumentParser()
ap.add_argument("dataset", nargs="?", default="orbit")
ap.add_argument("--llm", default="off")
ap.add_argument("--report", action="store_true", help="print the full markdown reports")
ap.add_argument("--json", help="write the case file to this path")
ap.add_argument("--out", help="write each markdown report into this directory")
args = ap.parse_args()

rt = run_pipeline(args.dataset, llm_mode=args.llm)
case = rt.case
for s in case["pipeline_trace"]:
    print(f"[{s['stage']:>2}] {s['name']:<32} {s['ms']:>8.1f} ms  {s['detail']}")
print()
for inc in case["incidents"]:
    rep = case["reports"][inc["incident_id"]]
    v = rep["verifier"]
    print(f"{inc['incident_id']}  {inc['severity'] or '--'}  {inc['title']}")
    print(f"    type: {inc['incident_type']} | SOC clock: {inc['detection_time_utc']} | claims: {len(inc['claims'])} | actions: {len(inc['actions'])} | contacts: {len(inc['contacts'])}")
    print(f"    verifier: {'PASS' if v['passed'] else 'FAIL'}  lines={v['lines_checked']} citations={v['citations_checked']} errors={len(v['errors'])} warnings={len(v['warnings'])} downgrades={len(v['downgrades'])} summary={rep['summary_source']}")
    for e in v["errors"][:40]:
        print("      ERROR", e)
    for w in v["warnings"][:10]:
        print("      warn ", w)
print()
for x in case["exclusions"]:
    print(f"CLOSED {x['change_id']}: {x['title']} | events={[c['file'][:2] + ':' + c['locator'] for c in x['events']]} alerts={[c['locator'] for c in x['alerts']]}")
print("quarantined:", case["parsing_audit"]["quarantined"])
print("alerts:", [(a["alert_id"], a["disposition"]) for a in case["alert_dispositions"]])
print("integrity:", case["integrity"]["evidence_integrity_digest"])
if args.report:
    for inc in case["incidents"]:
        print("\n" + "=" * 100 + "\n" + case["reports"][inc["incident_id"]]["markdown"])
if args.out:
    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for inc in case["incidents"]:
        (out / f"{inc['incident_id']}.md").write_text(case["reports"][inc["incident_id"]]["markdown"], encoding="utf-8")
if args.json:
    Path(args.json).write_text(json.dumps(case, indent=2, default=str), encoding="utf-8")
