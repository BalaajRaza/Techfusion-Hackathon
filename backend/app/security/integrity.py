"""Tamper-evident chain of custody.

digest = SHA-256( SHA-256(raw files) + SHA-256(parsed events) + SHA-256(case file) )
Any change to an input file, to a parsed event or to a finding changes the digest.
"""
from __future__ import annotations

import hashlib
import json
from typing import Any


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def canonical(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"), default=str)


def bundle_hash(file_hashes: dict[str, str]) -> str:
    return sha256_text("\n".join(f"{name}:{digest}" for name, digest in sorted(file_hashes.items())))


def evidence_digest(file_hashes: dict[str, str], events: list[dict[str, Any]], case_content: Any) -> dict[str, Any]:
    raw = bundle_hash(file_hashes)
    parsed = sha256_text(canonical(events))
    case = sha256_text(canonical(case_content))
    return dict(algorithm="SHA-256", raw_files_sha256=raw, parsed_events_sha256=parsed, case_file_sha256=case,
                evidence_integrity_digest=sha256_text(raw + parsed + case), files=dict(sorted(file_hashes.items())))
