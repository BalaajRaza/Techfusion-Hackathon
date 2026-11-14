"""Stage 1 - ingest and classify.

Line-numbering convention (stated in every report):
  * Log files: 1-based, line 1 is the first line INSIDE the fenced code block  -> locator L<n>
  * Tables: the row ID in the first column (alert ID, asset tag, change ID,
    username). Tables without a unique ID column use ROW<n> (1 = first data row).
  * Runbooks: step number -> S<n>.  Security rules: rule number -> R<n.n>.
  * Any other non-empty line: F<physical file line>.
"""
from __future__ import annotations

import gzip
import hashlib
import re
from pathlib import Path

from ..models import SourceFile, Table, TableRow, Unit

FENCE = re.compile(r"^\s*```")
ID_LIKE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.\-]{0,39}$")
STEP = re.compile(r"^(\d+)\.\s+\S")
RULE = re.compile(r"^(\d+\.\d+)\s+\S")
SEPARATOR = re.compile(r"^:?-{2,}:?$")

LINE_CONVENTION = (
    "Citations are file:locator. Log files: L<n>, 1-based, where line 1 is the first log line inside the "
    "code block. Tables: the row ID (alert ID, asset tag, change ID, username); tables without an ID column "
    "use ROW<n> counted from the first data row. Runbooks: S<n> is step n. Security rules: R<n.n> is rule n.n. "
    "Any other line: F<n> is the physical line n of the file."
)


def split_row(line: str) -> list[str]:
    return [c.strip() for c in line.strip().strip("|").split("|")]


def read_text(path: Path) -> tuple[str, str]:
    raw = path.read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if path.suffix == ".gz":
        raw = gzip.decompress(raw)
    return raw.decode("utf-8-sig", errors="replace"), digest


def classify(title: str, tables: list[Table], has_code: bool) -> tuple[str, str]:
    """Classify by content (headers / title), not by file name, so renamed or
    unseen files still land in the right class."""
    t = title.lower()
    heads = [" | ".join(h.lower() for h in tb.headers) for tb in tables]
    joined = " || ".join(heads)
    if "alert id" in joined:
        return "log", "ids"
    if has_code:
        return "log", "log"
    if "runbook" in t:
        return "runbook", "runbook"
    if "asset tag" in joined:
        return "reference", "inventory"
    if "change id" in joined:
        return "reference", "calendar"
    if "username" in joined:
        return "reference", "directory"
    if "incident type" in joined:
        return "reference", "matrix"
    if "who to inform" in joined:
        return "reference", "escalation"
    if "time zone" in joined and "source" in joined:
        return "reference", "coverage"
    if "rules" in t or "policy" in t:
        return "reference", "rules"
    return "reference", "unknown"


def ingest_file(path: Path) -> SourceFile:
    text, digest = read_text(path)
    lines = text.splitlines()  # handles CRLF and LF
    title = next((ln.lstrip("# ").strip() for ln in lines if ln.startswith("#")), path.name)

    units: list[Unit] = []
    tables: list[Table] = []
    in_code = False
    has_code = False
    code_n = 0
    cur: Table | None = None

    for i, line in enumerate(lines, 1):
        if FENCE.match(line):
            in_code = not in_code
            has_code = True
            cur = None
            continue
        if in_code:
            code_n += 1
            units.append(Unit(locator=f"L{code_n}", text=line, file_line=i, kind="log" if line.strip() else "blank"))
            continue
        s = line.strip()
        if s.startswith("|"):
            cells = split_row(s)
            if cur is None:
                cur = Table(headers=cells, header_line=i)
                tables.append(cur)
                units.append(Unit(locator=f"F{i}", text=s, file_line=i, kind="header"))
            elif all(SEPARATOR.match(c) for c in cells):
                continue
            else:
                # tolerate a header row repeated mid-table
                if cells == cur.headers:
                    continue
                cells += [""] * (len(cur.headers) - len(cells))
                cur.rows.append(TableRow(locator="", cells=dict(zip(cur.headers, cells)), file_line=i, text=s))
            continue
        cur = None
        if not s:
            continue
        m = RULE.match(s)
        if m:
            units.append(Unit(locator=f"R{m.group(1)}", text=s, file_line=i, kind="rule"))
            continue
        m = STEP.match(s)
        if m:
            units.append(Unit(locator=f"S{m.group(1)}", text=s, file_line=i, kind="step"))
            continue
        units.append(Unit(locator=f"F{i}", text=s, file_line=i, kind="text"))

    used = {u.locator for u in units}
    for t_idx, tb in enumerate(tables, 1):
        firsts = [next(iter(r.cells.values()), "") for r in tb.rows]
        id_col = bool(firsts) and all(ID_LIKE.match(f) for f in firsts) and len(set(firsts)) == len(firsts)
        for n, row in enumerate(tb.rows, 1):
            loc = firsts[n - 1] if id_col else f"ROW{n}"
            if loc in used:
                loc = f"T{t_idx}-{loc}"
            used.add(loc)
            row.locator = loc
            units.append(Unit(locator=loc, text=row.text, file_line=row.file_line, kind="row"))

    units.sort(key=lambda u: u.file_line)
    file_type, source_type = classify(title, tables, has_code)
    total = code_n if has_code else len([u for u in units if u.kind in ("row", "step", "rule")])
    return SourceFile(
        filename=path.name, title=title, file_type=file_type, source_type=source_type,
        total_lines=total, sha256=digest, units=units, tables=tables,
    )


def load_dataset(data_dir: Path) -> dict[str, SourceFile]:
    if not data_dir.is_dir():
        raise FileNotFoundError(f"Data directory not found: {data_dir}")
    files: dict[str, SourceFile] = {}
    for path in sorted(data_dir.iterdir()):
        if not path.is_file() or path.name.lower().startswith("readme"):
            continue
        if path.suffix not in (".md", ".log", ".txt", ".gz", ".csv"):
            continue
        files[path.name] = ingest_file(path)
    if not files:
        raise FileNotFoundError(f"No input files in {data_dir}")
    return files
