"""FastAPI surface of the triage engine."""
from __future__ import annotations

import hashlib
import json
import queue
import threading
from typing import Any, Optional

from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
from pydantic import BaseModel, Field

from . import config, db
from .llm.gateway import LLMGateway
from .pipeline.run import STAGES, Runtime, run_pipeline
from .qa import FactStore, answer

app = FastAPI(title="Orbit Logistics - Security Incident Triage Assistant", version="1.0.0",
              description="11-stage deterministic triage pipeline. The LLM writes language; code establishes facts.")
app.add_middleware(CORSMiddleware, allow_origins=config.CORS_ORIGINS, allow_methods=["*"], allow_headers=["*"])

_STATE: dict[str, Runtime] = {}
_STORES: dict[str, FactStore] = {}
_LOCK = threading.Lock()


def _dataset(name: str) -> str:
    if name not in config.DATASETS:
        raise HTTPException(404, f"Unknown dataset '{name}'. Available: {', '.join(config.DATASETS)}")
    if not config.DATASETS[name].is_dir():
        raise HTTPException(404, f"Dataset '{name}' is not present on this server ({config.DATASETS[name]}).")
    return name


def _run(dataset: str, llm: Optional[str], on_stage=None, pace_ms: int = 0, verify: bool = True) -> Runtime:
    try:
        rt = run_pipeline(dataset, llm_mode=llm, on_stage=on_stage, pace_ms=pace_ms, verify=verify)
    except FileNotFoundError as exc:
        raise HTTPException(404, str(exc)) from exc
    with _LOCK:
        _STATE[dataset] = rt
        _STORES.pop(dataset, None)
    return rt


def get_rt(dataset: str = "orbit") -> Runtime:
    dataset = _dataset(dataset)
    rt = _STATE.get(dataset)
    if rt is None:
        rt = _run(dataset, "off")  # first touch: instant, template-only; the UI then triggers a full run
    return rt


def get_store(dataset: str) -> FactStore:
    rt = get_rt(dataset)
    with _LOCK:
        if dataset not in _STORES:
            _STORES[dataset] = FactStore(rt)
        return _STORES[dataset]


def _public_case(rt: Runtime) -> dict[str, Any]:
    return rt.case


@app.get("/")
def root() -> dict[str, Any]:
    return dict(service="Orbit Logistics Security Incident Triage Assistant", docs="/docs", health="/api/health")


@app.get("/api/health")
def health() -> dict[str, Any]:
    gw = LLMGateway()
    engines = {m: LLMGateway(m).status() for m in ("local", "cloud")}
    return dict(status="ok", llm=gw.status(), engines=engines, datasets={k: v.is_dir() for k, v in config.DATASETS.items()},
                supabase=db.status(), stages=[dict(stage=n, name=name) for n, name in STAGES])


@app.get("/api/datasets")
def datasets() -> list[dict[str, Any]]:
    labels = {"orbit": "Orbit Logistics data pack (20 files, 2026-11-04)", "edge_cases": "Edge-case test pack (planted traps: injection, malformed line, out-of-scope scan ...)"}
    return [dict(id=k, label=labels.get(k, k), available=v.is_dir()) for k, v in config.DATASETS.items()]


@app.post("/api/triage/run")
def triage_run(dataset: str = "orbit", llm: Optional[str] = Query(None, pattern="^(auto|local|cloud|off)$")) -> dict[str, Any]:
    return _public_case(_run(_dataset(dataset), llm))


@app.get("/api/triage/stream")
def triage_stream(dataset: str = "orbit", llm: Optional[str] = Query(None, pattern="^(auto|local|cloud|off)$"), pace_ms: int = Query(0, ge=0, le=2000),
                  verify: bool = True) -> StreamingResponse:
    """Server-sent events: one event per pipeline stage (running / done), then 'complete'."""
    dataset = _dataset(dataset)
    q: "queue.Queue[dict[str, Any]]" = queue.Queue()

    def work() -> None:
        try:
            rt = _run(dataset, llm, on_stage=q.put, pace_ms=pace_ms, verify=verify)
            q.put(dict(status="complete", stats=rt.case["stats"], llm=rt.case["llm"]))
        except HTTPException as exc:
            q.put(dict(status="error", detail=str(exc.detail)))
        except Exception as exc:  # noqa: BLE001
            q.put(dict(status="error", detail=f"{type(exc).__name__}: {exc}"))

    threading.Thread(target=work, daemon=True).start()

    def gen():
        while True:
            ev = q.get()
            yield f"data: {json.dumps(ev, default=str)}\n\n"
            if ev.get("status") in ("complete", "error"):
                break

    return StreamingResponse(gen(), media_type="text/event-stream", headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/case")
def case(dataset: str = "orbit") -> dict[str, Any]:
    return _public_case(get_rt(dataset))


@app.get("/api/incidents")
def incidents(dataset: str = "orbit") -> list[dict[str, Any]]:
    return [dict(incident_id=i["incident_id"], title=i["title"], severity=i["severity"], incident_type=i["incident_type"], status=i["status"],
                 detection_time_utc=i["detection_time_utc"]) for i in get_rt(dataset).case["incidents"]]


@app.get("/api/incidents/{incident_id}")
def incident(incident_id: str, dataset: str = "orbit") -> dict[str, Any]:
    c = get_rt(dataset).case
    inc = next((i for i in c["incidents"] if i["incident_id"] == incident_id), None)
    if not inc:
        raise HTTPException(404, f"No incident {incident_id}")
    return dict(incident=inc, report=c["reports"][incident_id])


@app.get("/api/incidents/{incident_id}/report.md", response_class=PlainTextResponse)
def incident_report_md(incident_id: str, dataset: str = "orbit") -> str:
    c = get_rt(dataset).case
    if incident_id not in c["reports"]:
        raise HTTPException(404, f"No incident {incident_id}")
    return c["reports"][incident_id]["markdown"]


@app.get("/api/events")
def events(dataset: str = "orbit", file: Optional[str] = None, q: Optional[str] = None, limit: int = Query(500, le=2000)) -> list[dict[str, Any]]:
    rows = getattr(get_rt(dataset), "events_dump", [])
    if file:
        rows = [r for r in rows if r["source_file"] == file]
    if q:
        ql = q.lower()
        rows = [r for r in rows if ql in r["raw_line"].lower()]
    return rows[:limit]


@app.get("/api/source-context")
def source_context(file: str, locator: str, radius: int = Query(5, ge=0, le=50), dataset: str = "orbit") -> dict[str, Any]:
    """Evidence Inspector: the cited unit with surrounding context, parser metadata and an integrity check."""
    rt = get_rt(dataset)
    f = rt.files.get(file)
    if f is None:
        raise HTTPException(404, f"No such file in the evidence: {file}")
    loc = locator if not locator.isdigit() else f"L{locator}"
    target = f.unit(loc)
    if target is None:
        raise HTTPException(404, f"{file} has no unit '{locator}'")
    pool = [u for u in f.units if (u.kind in ("log", "blank") if target.kind == "log" else u.kind not in ("log", "blank"))]
    idx = next(i for i, u in enumerate(pool) if u.locator == target.locator)
    window = pool[max(0, idx - radius): idx + radius + 1]
    path = config.DATASETS[dataset] / file
    try:
        on_disk = hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        on_disk = None
    ev = rt.ctx.by_id.get(f"{file}:{target.locator}") if rt.ctx else None
    meta = None
    if ev:
        meta = dict(parse_status=ev.parse_status, quarantine_reason=ev.quarantine_reason, ts_utc=ev.ts_utc, ts_start_utc=ev.ts_start_utc, ts_end_utc=ev.ts_end_utc,
                    ts_original=ev.ts_original, tz_source=ev.tz_source, tz_assumed=ev.tz_assumed, source_type=ev.source_type, action=ev.action, outcome=ev.outcome,
                    user=ev.user_account, ip_source=ev.ip_source, ip_dest=ev.ip_dest, host=ev.host, flags=ev.flags,
                    fields={k: v for k, v in ev.fields.items() if v not in (None, "", []) and k not in ("url_decoded",)})
    used_in = []
    ref = f"{file}:{target.locator}"
    for inc in rt.case["incidents"]:
        n = sum(1 for c in inc["claims"] for ct in c["citations"] if f"{ct['file']}:{ct['locator']}" == ref)
        if n:
            used_in.append(dict(incident_id=inc["incident_id"], severity=inc["severity"], claims=n))
    for x in rt.case["exclusions"]:
        if any(f"{c['file']}:{c['locator']}" == ref for c in x["events"] + x["alerts"]):
            used_in.append(dict(closed_as_harmless=x["change_id"]))
    return dict(file=file, title=f.title, file_type=f.file_type, locator=target.locator, target_line=int(target.locator[1:]) if target.kind == "log" else target.file_line,
                kind=target.kind, lines=[dict(line=(int(u.locator[1:]) if u.kind in ("log", "blank") else u.file_line), label=u.locator, text=u.text, is_target=u.locator == target.locator) for u in window],
                total_lines=f.total_lines, file_sha256=f.sha256, sha256_on_disk=on_disk, integrity="VERIFIED" if on_disk == f.sha256 else "CHANGED_SINCE_INGEST",
                parser=meta, used_in=used_in, line_convention=rt.case["line_convention"])


@app.get("/api/files/{filename}")
def file_units(filename: str, dataset: str = "orbit") -> dict[str, Any]:
    f = get_rt(dataset).files.get(filename)
    if f is None:
        raise HTTPException(404, f"No such file: {filename}")
    return dict(filename=f.filename, title=f.title, file_type=f.file_type, sha256=f.sha256, units=[u.model_dump() for u in f.units])


class AskBody(BaseModel):
    question: str = Field(min_length=2, max_length=600)
    dataset: str = "orbit"
    llm: bool = True
    verify: bool = True
    engine: Optional[str] = Field(None, pattern="^(auto|local|cloud|off)$")


@app.post("/api/ask")
def ask(body: AskBody) -> dict[str, Any]:
    rt = get_rt(body.dataset)
    return answer(rt, get_store(body.dataset), body.question, use_llm=body.llm, verify=body.verify, engine=body.engine)


class VerifyBody(BaseModel):
    markdown: str = Field(min_length=1, max_length=20000)
    dataset: str = "orbit"
    tier: Optional[str] = "SUSPECTED"


@app.post("/api/verify")
def verify(body: VerifyBody) -> dict[str, Any]:
    """Run the claim verifier on any text - paste a sentence with [file:line] citations and see whether it is grounded."""
    rt = get_rt(body.dataset)
    assert rt.verifier is not None
    lines_out, errors, warnings, downgrades = [], [], [], []
    for n, line in enumerate(body.markdown.splitlines(), 1):
        if not line.strip():
            continue
        res = rt.verifier.check_line(line, body.tier, n)
        errors += res["errors"]
        warnings += res["warnings"]
        fixed = rt.verifier.downgrade(line) if res["strong"] else line
        if res["strong"]:
            downgrades.append(f"line {n}: strong word(s) {', '.join(res['strong'])} downgraded")
        lines_out.append(dict(line=n, text=fixed, ok=not res["errors"], citations=res["citations"]))
    return dict(passed=not errors, errors=errors, warnings=warnings, downgrades=downgrades, lines=lines_out)


@app.post("/api/persist")
def persist(dataset: str = "orbit") -> dict[str, Any]:
    """Write the current case file to Supabase (requires SUPABASE_URL + service-role key)."""
    rt = get_rt(dataset)
    if not db.status()["configured"]:
        raise HTTPException(503, "Supabase is not configured: set SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY.")
    try:
        return db.persist(rt)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(502, f"Supabase write failed: {type(exc).__name__}: {exc}") from exc
