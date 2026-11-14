"""Developer helper: print raw detector output for a dataset."""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app import config  # noqa: E402
from app.pipeline import parsers  # noqa: E402
from app.pipeline.detectors import Ctx, run_detectors  # noqa: E402
from app.pipeline.entities import EntityGraph  # noqa: E402
from app.pipeline.ingest import load_dataset  # noqa: E402
from app.pipeline.references import build_references  # noqa: E402

name = sys.argv[1] if len(sys.argv) > 1 else "orbit"
files = load_dataset(config.DATASETS[name])
refs = build_references(files)
events = []
for f in files.values():
    if f.source_type == "log":
        events += parsers.parse_log_file(f, refs)[0]
    elif f.source_type == "ids":
        events += parsers.parse_ids_file(f, refs)[0]
ctx = Ctx(files, refs, events, EntityGraph(refs, events))
findings, links = run_detectors(ctx)
for f in findings:
    print(f"{f.id} {f.kind:18} primary={f.primary!s:5} {f.title}")
    print(f"      actors={f.actors} alerts={[a.split(':')[1] for a in f.alert_ids]}")
    print(f"      events={[e.split('_')[0] + ':' + e.split(':')[1] for e in f.event_ids]}")
for ref, l in links.items():
    print(l["alert_id"], "->", [t.split("_")[0] + ":" + t.split(":")[1] for t in l["trigger_events"]], l["findings"], l["delay_s"])
