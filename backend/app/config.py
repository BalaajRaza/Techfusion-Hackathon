"""Runtime configuration. Everything is overridable through environment variables."""
from __future__ import annotations

import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
REPO_ROOT = BACKEND_DIR.parent

DATA_DIR = Path(os.getenv("DATA_DIR", str(REPO_ROOT / "security_triage_data")))
EDGE_PACK_DIR = Path(os.getenv("EDGE_PACK_DIR", str(BACKEND_DIR / "datasets" / "edge_cases")))
CACHE_DIR = Path(os.getenv("CACHE_DIR", str(BACKEND_DIR / ".cache")))

DATASETS: dict[str, Path] = {"orbit": DATA_DIR, "edge_cases": EDGE_PACK_DIR}

# --- LLM gateway (dual mode) -------------------------------------------------
# LLM_MODE: auto  -> try Ollama, then the cloud endpoint, then the template report
#           local -> Ollama only      cloud -> cloud endpoint only      off -> template only
LLM_MODE = os.getenv("LLM_MODE", "auto").lower()
OLLAMA_URL = os.getenv("OLLAMA_URL", "http://localhost:11434").rstrip("/")
OLLAMA_MODEL = os.getenv("OLLAMA_MODEL", "")  # empty -> pick the best installed model
OLLAMA_PREFERRED = ["llama3.1:8b", "qwen2.5:7b", "llama3.1", "qwen2.5", "llama3", "mistral", "gemma"]

# Any OpenAI-compatible endpoint works here (Groq by default, OpenRouter, vLLM, ...).
CLOUD_BASE_URL = os.getenv("LLM_BASE_URL", "https://api.groq.com/openai/v1").rstrip("/")
CLOUD_API_KEY = os.getenv("LLM_API_KEY") or os.getenv("GROQ_API_KEY") or ""
CLOUD_MODEL = os.getenv("LLM_MODEL", "llama-3.1-8b-instant")
# Optional second cloud endpoint, tried after the first one fails.
FALLBACK_BASE_URL = os.getenv("LLM_FALLBACK_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
FALLBACK_API_KEY = os.getenv("LLM_FALLBACK_API_KEY") or os.getenv("OPENROUTER_API_KEY") or ""
FALLBACK_MODEL = os.getenv("LLM_FALLBACK_MODEL", "meta-llama/llama-3.1-8b-instruct")

LLM_TIMEOUT_S = float(os.getenv("LLM_TIMEOUT_S", "90"))
LLM_MAX_RETRIES = int(os.getenv("LLM_MAX_RETRIES", "2"))
# Pseudonymise IPs / users / hosts before ANY model call (local or cloud).
LLM_PSEUDONYMIZE = os.getenv("LLM_PSEUDONYMIZE", "true").lower() != "false"

# --- Supabase (optional persistence) ----------------------------------------
SUPABASE_URL = os.getenv("SUPABASE_URL", "").rstrip("/")
SUPABASE_SERVICE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY") or os.getenv("SUPABASE_SERVICE_KEY") or ""

# --- API ---------------------------------------------------------------------
CORS_ORIGINS = [o.strip() for o in os.getenv("CORS_ORIGINS", "*").split(",") if o.strip()]

# --- Detection thresholds ----------------------------------------------------
# The data pack's rules give no numeric thresholds, so every number below is a
# heuristic. Each one is named in the report wherever it was used.
MFA_FAIL_MIN = 3            # ">= 3 rejected pushes" stands for "several" in rule 6.1
MFA_WINDOW_S = 300          # ... followed by an approved push within 5 minutes (inclusive)
LARGE_TRANSFER_BYTES = 1_000_000_000   # >= 1 GB in one firewall session
PORT_SCAN_MIN_PORTS = 5     # >= 5 distinct destination ports from one source ...
SCAN_WINDOW_S = 60          # ... inside a sliding 60 second window
INTERNAL_SCAN_MIN_TARGETS = 4
WEB_PROBE_MIN_REQUESTS = 2
WEB_SUCCESS_SIZE_FACTOR = 10  # a 200 response >= 10x the attacker's usual error size
LOCKOUT_WINDOW_S = 300
ALERT_LINK_BEFORE_S = 120   # an IDS alert is linked to events up to 120 s before it
ALERT_LINK_AFTER_S = 5
CLOCK_SKEW_FLAG_S = 10
