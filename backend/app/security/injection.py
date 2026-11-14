"""Security layer: logs are attacker-controlled input.

* scan()      - prompt-injection signatures in any log text (User-Agent, URL,
                email subject, ...). A hit is quarantined AND becomes a finding.
* sanitize()  - strips the payload before any text may reach a model.
* redact_secrets() - masks credentials found in log text.
* sandbox()   - wraps evidence in the XML data boundary used in every prompt.
"""
from __future__ import annotations

import re
from urllib.parse import unquote_plus

SIGNATURES: list[tuple[str, re.Pattern[str]]] = [
    ("ignore-previous-instructions", re.compile(r"(ignore|disregard|forget|override)\s+(all\s+|any\s+|the\s+)?(previous|prior|above|earlier|preceding)\s+(instructions?|prompts?|rules?|context|messages?)", re.I)),
    ("system-prompt-reference", re.compile(r"\bsystem\s+prompt\b|\byour\s+instructions\b", re.I)),
    ("role-override", re.compile(r"\byou\s+are\s+now\b|\bact\s+as\s+(an?\s+)?(unrestricted|different|new)\b|\bpretend\s+(you\s+are|to\s+be)\b", re.I)),
    ("jailbreak-mode", re.compile(r"\b(DAN|sudo|developer|god|admin)\s+mode\b", re.I)),
    ("verdict-forcing", re.compile(r"(classify|mark|report|label|treat|flag)\s+(this|it|everything|all|these|the)\b[^.]{0,40}\b(as\s+)?(benign|harmless|safe|no\s+incident|false\s+positive)", re.I)),
    ("verdict-forcing", re.compile(r"\bno\s+incident\s+detected\b|\boutput\s*:\s*no\s+incident\b", re.I)),
    ("chat-markup", re.compile(r"</?\s*(system|assistant|instructions?)\s*>|\[/?INST\]|<\|im_(start|end)\|>", re.I)),
    ("new-instructions", re.compile(r"\bnew\s+instructions?\s*:", re.I)),
    ("boundary-escape", re.compile(r"</\s*untrusted_evidence_data\s*>", re.I)),
]

SECRET_PATTERNS = [
    re.compile(r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|authorization)\s*[=:]\s*(\"[^\"]+\"|\S+)"),
    re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-]{12,}"),
    re.compile(r"\b(?:sk|pk|gsk|ghp|xox[bap])[-_][A-Za-z0-9\-_]{16,}\b"),
]


def scan(text: str) -> list[str]:
    """Return the names of the injection signatures found in text.
    URL-encoded payloads are decoded first so %20-obfuscation does not hide them."""
    candidates = {text}
    try:
        candidates.add(unquote_plus(text))
    except Exception:  # noqa: BLE001 - never let hostile input break parsing
        pass
    hits: list[str] = []
    for name, pat in SIGNATURES:
        if any(pat.search(c) for c in candidates) and name not in hits:
            hits.append(name)
    return hits


def sanitize(text: str) -> str:
    """Remove injection payloads; what remains is safe to show a model."""
    out = text
    for _, pat in SIGNATURES:
        out = pat.sub("[INJECTION-PAYLOAD-REMOVED]", out)
    return out


def redact_secrets(text: str) -> str:
    out = SECRET_PATTERNS[0].sub(lambda m: f"{m.group(1)}=[REDACTED]", text)
    for pat in SECRET_PATTERNS[1:]:
        out = pat.sub("[REDACTED-SECRET]", out)
    return out


def sandbox(payload: str) -> str:
    """The only way evidence is ever placed in a prompt: inside a data boundary,
    never in the instruction part, with payloads and secrets removed and the
    closing tag neutralised so the data cannot break out of the boundary."""
    safe = redact_secrets(sanitize(payload)).replace("</untrusted_evidence_data", "&lt;/untrusted_evidence_data")
    return f'<untrusted_evidence_data context="read_only_factual_payload">\n{safe}\n</untrusted_evidence_data>'
