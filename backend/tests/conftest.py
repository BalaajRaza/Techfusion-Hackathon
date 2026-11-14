import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from app.pipeline.run import run_pipeline  # noqa: E402


@pytest.fixture(scope="session")
def orbit():
    return run_pipeline("orbit", llm_mode="off")


@pytest.fixture(scope="session")
def edge():
    if not (ROOT / "datasets" / "edge_cases").is_dir():
        import subprocess
        subprocess.check_call([sys.executable, str(ROOT / "scripts" / "build_edge_pack.py")])
    return run_pipeline("edge_cases", llm_mode="off")


def inc_by(rt, needle):
    return next(i for i in rt.case["incidents"] if needle in i["title"])


def claims_text(inc, status=None):
    return "\n".join(c["text"] for c in inc["claims"] if status is None or c["status"] == status)
