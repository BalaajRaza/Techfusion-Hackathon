"""Stage 3 helpers - timestamp parsing and UTC normalisation.

Nothing here guesses silently: when a zone cannot be established the caller
gets tz_assumed=True and the report says so.
"""
from __future__ import annotations

import re
from datetime import datetime, timedelta, timezone
from typing import Optional

UTC = timezone.utc

# Only unambiguous abbreviations. The company zone (PKT) is re-read from the
# security rules at run time; ambiguous ones (CST, IST, ...) are never mapped.
TZ_ABBR: dict[str, float] = {"UTC": 0, "Z": 0, "GMT": 0, "PKT": 5}

_OFFSET = re.compile(r"^([+-])(\d{2}):?(\d{2})$")
_NAIVE_FORMATS = (
    "%Y-%m-%d %H:%M:%S", "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f", "%Y-%m-%dT%H:%M:%S.%f",
    "%Y/%m/%d %H:%M:%S", "%Y-%m-%d %H:%M", "%Y-%m-%d %I:%M:%S %p",
)


def tz_from_hours(hours: float) -> timezone:
    return timezone(timedelta(hours=hours))


def parse_offset(text: str) -> Optional[timezone]:
    """'+05:00' / '+0500' / 'Z' / 'UTC' / 'PKT' -> tzinfo, or None when unknown."""
    text = text.strip()
    if text.upper() in TZ_ABBR:
        return tz_from_hours(TZ_ABBR[text.upper()])
    m = _OFFSET.match(text)
    if m:
        sign = 1 if m.group(1) == "+" else -1
        return timezone(sign * timedelta(hours=int(m.group(2)), minutes=int(m.group(3))))
    return None


def parse_naive(text: str) -> Optional[datetime]:
    text = text.strip()
    for fmt in _NAIVE_FORMATS:
        try:
            return datetime.strptime(text, fmt)
        except ValueError:
            continue
    return None


def parse_iso(text: str) -> Optional[datetime]:
    """ISO 8601, aware if it carries Z / an offset, naive otherwise."""
    try:
        return datetime.fromisoformat(text.strip().replace("Z", "+00:00"))
    except ValueError:
        return None


def parse_apache(text: str) -> Optional[datetime]:
    try:
        return datetime.strptime(text.strip(), "%d/%b/%Y:%H:%M:%S %z")
    except ValueError:
        return None


def parse_epoch(text: str) -> Optional[datetime]:
    if re.fullmatch(r"\d{10}", text):
        return datetime.fromtimestamp(int(text), UTC)
    if re.fullmatch(r"\d{13}", text):
        return datetime.fromtimestamp(int(text) / 1000, UTC)
    return None


def to_utc(dt: datetime) -> datetime:
    return dt.astimezone(UTC)


def parse_duration(text: str) -> Optional[int]:
    """'312s' / '8h' / '30m' / '2d' / '45' -> seconds."""
    m = re.fullmatch(r"(\d+)\s*([smhd]?)", str(text).strip().lower())
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "s": 1, "m": 60, "h": 3600, "d": 86400}[m.group(2)]


def fmt_utc(dt: Optional[datetime], date: bool = False) -> str:
    if dt is None:
        return "unknown time"
    return to_utc(dt).strftime("%Y-%m-%d %H:%M:%S UTC" if date else "%H:%M:%S UTC")


def fmt_local(dt: datetime, hours: float, label: str) -> str:
    return dt.astimezone(tz_from_hours(hours)).strftime("%H:%M:%S ") + label


def fmt_span(seconds: float) -> str:
    seconds = int(abs(seconds))
    h, rem = divmod(seconds, 3600)
    m, s = divmod(rem, 60)
    if h:
        return f"{h} h {m} min {s} s"
    if m:
        return f"{m} min {s} s"
    return f"{s} s"


def fmt_bytes(n: int) -> str:
    n = int(n)
    if n >= 1_000_000_000:
        return f"{n:,} bytes ({n / 1e9:.2f} GB)"
    if n >= 1_000_000:
        return f"{n:,} bytes ({n / 1e6:.1f} MB)"
    return f"{n:,} bytes"
