# Triage engine (FastAPI)

The 11-stage pipeline that turns the 20 files in `security_triage_data/` into a verified case file.
Stages 1-10 are plain Python. A language model is used only in stage 11, to write the summary
prose, and the code verifier rejects any output that is not grounded.

## Run

```bash
python -m venv .venv && .venv/Scripts/pip install -r requirements.txt   # Windows (use .venv/bin on Linux/macOS)
python scripts/build_edge_pack.py          # builds datasets/edge_cases (planted traps)
python -m pytest -q                        # 38 tests: data pack, edge cases, verifier, security, API
uvicorn app.main:app --reload --port 8000  # API at http://localhost:8000/docs
python scripts/run_triage.py orbit --report   # CLI: stage trace and full markdown reports
```

## LLM gateway (`LLM_MODE`)

| Mode | Behaviour |
|---|---|
| `off` | Deterministic template report, no model (instant) |
| `local` | Ollama at `OLLAMA_URL`. Picks `llama3.1:8b` / `qwen2.5:7b` if installed, else the largest installed model |
| `cloud` | Any OpenAI-compatible endpoint (`LLM_BASE_URL`, default Groq `llama-3.1-8b-instant`), then `LLM_FALLBACK_*` |
| `auto` | local, then cloud, then template |

Before any model call, IPs, users, hosts and emails are pseudonymised. The model sees verified
claims only, never raw logs, inside `<untrusted_evidence_data>`. Every sentence must cite claim
IDs. On rejection it gets one retry with the verifier's errors, then the template is used.
Retries use exponential backoff on 429/5xx, and answers are cached on disk by input hash.

## Pipeline map

| Stage | Module |
|---|---|
| 1 Ingest & classify (content-based, line convention) | `app/pipeline/ingest.py` |
| 2 Parse & quarantine (format sniffing, never drop a line) | `app/pipeline/parsers.py` |
| 3 UTC normalisation (zone policy read from file 20, close-logged sessions, clock skew) | `parsers.py`, `timeutil.py`, `run.py` |
| 4 Temporal entity graph (DHCP leases, VPN sessions, ambiguity) | `app/pipeline/entities.py` |
| 5 Detectors + IDS alert linking | `app/pipeline/detectors.py` |
| 6 Five-check change-calendar filter + clustering | `app/pipeline/noise.py` |
| 7 Severity matrix lookup with written steps | `app/pipeline/response.py` |
| 8-9 Coverage gaps and the 3-tier evidence ledger | `app/pipeline/assemble.py` |
| 10 Runbook-constrained actions and escalation deadlines | `app/pipeline/response.py` |
| 11 Report, LLM prose and claim verifier | `report.py`, `app/llm/`, `verifier.py` |

## Key endpoints

`GET /api/triage/stream` (SSE per stage) · `GET /api/case` · `GET /api/source-context?file=&locator=` (Evidence Inspector) ·
`POST /api/ask` (Q&A over the structured store) · `POST /api/verify` (run the verifier on any text) ·
`GET /api/incidents/{id}/report.md` · `POST /api/persist` (Supabase)

## Supabase

The schema is in `supabase/migrations/20261114000000_triage_schema.sql`. RLS is on for every table
and there are no policies, so only the service-role key (backend) can read the security data.
Set `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY`, then `POST /api/persist`. The API works without
a database: everything is also served from memory.

## Deploy (Render)

`render.yaml` at the repo root builds `backend/Dockerfile` from the repo root, so the data pack is
inside the image. The build runs the test suite. Set `GROQ_API_KEY` and `CORS_ORIGINS` in the dashboard.
