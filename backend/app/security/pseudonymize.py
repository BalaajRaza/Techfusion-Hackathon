"""Pseudonymisation before any model call (local or cloud).

Real IPs, usernames, full names, hostnames, emails and domains are swapped
for stable tokens (USER_1, IP_EXT_2, HOST_3 ...). The model only ever sees
tokens; real values are restored locally, in code, after verification.
"""
from __future__ import annotations

import re
from typing import Iterable

from ..pipeline.references import IP_RE, References, is_internal_ip

TOKEN_RE = re.compile(r"\b(?:USER|PERSON|HOST|EMAIL|DOMAIN|IP_EXT|IP_INT)_\d+\b")
EMAIL_RE = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
DOMAIN_RE = re.compile(r"\b(?:[a-z0-9-]+\.)+(?:example|com|net|org|local|io)\b", re.I)


class Pseudonymizer:
    def __init__(self, refs: References, extra_names: Iterable[str] = ()):
        self.forward: dict[str, str] = {}
        self.reverse: dict[str, str] = {}
        self._counters: dict[str, int] = {}
        self._static: list[tuple[re.Pattern[str], str]] = []
        for u in refs.users:
            tok = self._token("USER", u.username)
            self._static.append((re.compile(rf"(?<![\w.@-]){re.escape(u.username)}(?![\w@])", re.I), tok))
            self._static.append((re.compile(re.escape(u.full_name), re.I), self._token("PERSON", u.full_name)))
        for name in extra_names:
            if name and name not in self.forward:
                self._static.append((re.compile(re.escape(name), re.I), self._token("PERSON", name)))
        for a in sorted(refs.assets, key=lambda a: -len(a.hostname)):
            self._static.append((re.compile(rf"(?<![\w-]){re.escape(a.hostname)}(?![\w-])", re.I), self._token("HOST", a.hostname)))

    def _token(self, kind: str, real: str) -> str:
        if real in self.forward:
            return self.forward[real]
        self._counters[kind] = self._counters.get(kind, 0) + 1
        tok = f"{kind}_{self._counters[kind]}"
        self.forward[real] = tok
        self.reverse[tok] = real
        return tok

    def mask(self, text: str) -> str:
        out = EMAIL_RE.sub(lambda m: self._token("EMAIL", m.group(0)), text)
        for pat, tok in self._static:
            out = pat.sub(tok, out)
        out = IP_RE.sub(lambda m: self._token("IP_INT" if is_internal_ip(m.group(0)) else "IP_EXT", m.group(0)), out)
        out = DOMAIN_RE.sub(lambda m: self._token("DOMAIN", m.group(0)), out)
        return out

    def unmask(self, text: str) -> str:
        return TOKEN_RE.sub(lambda m: self.reverse.get(m.group(0), m.group(0)), text)

    def tokens_in(self, text: str) -> set[str]:
        return set(TOKEN_RE.findall(text))
