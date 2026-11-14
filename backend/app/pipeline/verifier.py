"""Stage 11b - the anti-hallucination claim verifier (code, not a model).

Runs on every report before it is shown, whoever wrote it:
  check 1  every cited file:locator exists in the ingested evidence
  check 2  every IP / username / hostname in a sentence appears in the lines
           that sentence cites (hostnames may be grounded through an alias)
  check 3  no IP appears in the report that does not exist in the evidence
  check 4  strong words (stolen, leaked, breached, exfiltrated, compromised)
           are only allowed on CONFIRMED statements; otherwise the wording is
           downgraded and the change is logged
"""
from __future__ import annotations

import re
from typing import Any, Iterable, Optional

from ..models import Claim, SourceFile, Unit
from .references import IP_RE, References

CITE_RE = re.compile(r"\[([A-Za-z0-9_.\-]+\.(?:md|log|txt|csv|gz)):([A-Za-z0-9_.\-]+)\]")
STRONG = {
    "stolen": "possibly taken (unconfirmed)", "leaked": "possibly exposed (unconfirmed)", "breached": "accessed",
    "exfiltrated": "transferred", "compromised": "possibly misused (unconfirmed)", "hacked": "accessed without approval (unconfirmed)",
}
STRONG_RE = re.compile(r"\b(" + "|".join(STRONG) + r")\b", re.I)
NEGATION = re.compile(r"\b(not|no|never|unknown|whether|cannot|can't|if|unless|nothing|without)\b", re.I)
SECTION_TIER = [(re.compile(r"^#+\s*Confirmed", re.I), "CONFIRMED"), (re.compile(r"^#+\s*Suspected", re.I), "SUSPECTED"),
                (re.compile(r"^#+\s*Not enough evidence", re.I), "INSUFFICIENT_EVIDENCE")]
CLAIM_TAG = re.compile(r"\b(C\d+)\b")
HEDGE = re.compile(r"\b(suspect\w*|may|might|possibl\w*|likely|appears?|seems?|could|unknown|unclear|not (shown|known|recorded|seen|confirmed)|"
                   r"cannot|can't|no (log|evidence|record)|do(es)? not show|whether|unconfirmed|inferred|indicat\w*|sign of)\b", re.I)


class ClaimVerifier:
    def __init__(self, files: dict[str, SourceFile], refs: References):
        self.files = files
        self.refs = refs
        blob = "\n".join(u.text for f in files.values() for u in f.units)
        self.known_ips = set(IP_RE.findall(blob))
        self.usernames = [u.username for u in refs.users]

    # ------------------------------------------------------------- lookups
    def lookup(self, file: str, locator: str) -> Optional[Unit]:
        f = self.files.get(file)
        return f.unit(locator) if f else None

    def _aliases(self, hostname: str) -> list[str]:
        a = self.refs.asset_by_name(hostname)
        if not a:
            return [hostname]
        short = a.hostname.split("-", 1)[1] if "-" in a.hostname else a.hostname
        return [a.hostname, a.tag] + a.ips + a.public_ips + [short]

    # ------------------------------------------------------------- strong words
    def _strong_violations(self, body: str, cited_text: str) -> list[tuple[str, int]]:
        masked = re.sub(r"\"[^\"]*\"|'[^']{12,}'", lambda m: " " * len(m.group(0)), body)
        out = []
        for m in STRONG_RE.finditer(masked):
            before = masked[max(0, m.start() - 60):m.start()]
            if NEGATION.search(before):
                continue
            # quoted from the source itself (e.g. the wording of a security rule)?
            words = re.findall(r"\w+", body[: m.end()])[-4:]
            if len(words) == 4 and re.search(r"\W+".join(map(re.escape, words)), cited_text, re.I):
                continue
            out.append((m.group(1), m.start()))
        return out

    @staticmethod
    def downgrade(text: str) -> str:
        return STRONG_RE.sub(lambda m: STRONG[m.group(1).lower()], text)

    # ------------------------------------------------------------- one line
    def check_line(self, line: str, tier: Optional[str], n: int) -> dict[str, Any]:
        errors: list[str] = []
        warnings: list[str] = []
        cited_units: list[str] = []
        cites = CITE_RE.findall(line)
        for file, loc in cites:
            u = self.lookup(file, loc)
            if u is None:
                errors.append(f"line {n}: invalid citation [{file}:{loc}] - no such file/line in the evidence")
            else:
                cited_units.append(u.text)
        body = CITE_RE.sub("", line)
        cited = "\n".join(cited_units)
        cited_low = cited.lower()
        ips = list(dict.fromkeys(IP_RE.findall(body)))
        users = [u for u in self.usernames if re.search(rf"(?<![\w.@-]){re.escape(u)}(?![\w@-])", body)]
        hosts = [a.hostname for a in self.refs.assets if re.search(rf"(?<![\w-]){re.escape(a.hostname)}(?![\w-])", body)]
        for ip in ips:
            if ip not in self.known_ips:
                errors.append(f"line {n}: IP {ip} does not exist anywhere in the evidence files")
        if cites:
            for ip in ips:
                if ip in self.known_ips and ip not in cited:
                    errors.append(f"line {n}: grounding mismatch - IP {ip} is not in the cited lines")
            for u in users:
                if u not in cited_low:
                    errors.append(f"line {n}: grounding mismatch - user {u} is not in the cited lines")
            for h in hosts:
                if not any(al.lower() in cited_low for al in self._aliases(h)):
                    errors.append(f"line {n}: grounding mismatch - host {h} (or an alias) is not in the cited lines")
        elif ips or users or hosts:
            warnings.append(f"line {n}: mentions {', '.join(ips + users + hosts)} without a citation")
        strong = []
        if tier and tier != "CONFIRMED":
            strong = self._strong_violations(body, cited)
        return dict(errors=errors, warnings=warnings, citations=len(cites), strong=[w for w, _ in strong])

    # ------------------------------------------------------------- whole report
    def verify_markdown(self, md: str, claim_tiers: Optional[dict[str, str]] = None) -> tuple[str, dict[str, Any]]:
        """Returns (possibly downgraded markdown, verification log)."""
        errors: list[str] = []
        warnings: list[str] = []
        downgrades: list[str] = []
        out_lines: list[str] = []
        tier: Optional[str] = None
        in_summary = False
        n_cites = n_lines = 0
        for n, line in enumerate(md.splitlines(), 1):
            if line.startswith("#"):
                tier = next((t for pat, t in SECTION_TIER if pat.match(line)), None)
                in_summary = bool(re.match(r"^#+\s*Summary", line, re.I))
                out_lines.append(line)
                continue
            if not line.strip() or re.match(r"^\|[\s:|-]+\|$", line.strip()):
                out_lines.append(line)
                continue
            line_tier = tier
            if in_summary and claim_tiers:
                tiers = [claim_tiers[c] for c in CLAIM_TAG.findall(line) if c in claim_tiers]
                line_tier = "CONFIRMED" if tiers and all(t == "CONFIRMED" for t in tiers) else ("SUSPECTED" if tiers else None)
            res = self.check_line(line, line_tier, n)
            n_lines += 1
            n_cites += res["citations"]
            errors += res["errors"]
            warnings += res["warnings"]
            if res["strong"]:
                fixed = self.downgrade(line)
                downgrades.append(f"line {n}: strong word(s) {', '.join(res['strong'])} on a statement that is not CONFIRMED - wording downgraded")
                line = fixed
            out_lines.append(line)
        log = dict(passed=not errors, lines_checked=n_lines, citations_checked=n_cites, errors=errors, warnings=warnings, downgrades=downgrades,
                   checks=["cited file:line exists", "entities in a sentence appear in its cited lines", "no IP outside the evidence", "strong words only on CONFIRMED statements"])
        return "\n".join(out_lines), log

    # ------------------------------------------------------------- model-written prose
    def verify_sentences(self, sentences: list[dict[str, Any]], claims: dict[str, Claim], known_entities: Iterable[str]) -> dict[str, Any]:
        """Model output: [{text, claim_ids}]. Every sentence must cite claim IDs
        that exist, and may only name entities that those claims name."""
        errors: list[str] = []
        downgrades: list[str] = []
        known = set(known_entities)
        for i, s in enumerate(sentences, 1):
            ids = s.get("claim_ids") or []
            text = s.get("text", "")
            if not ids:
                errors.append(f"sentence {i}: no claim ID - an unsupported sentence is not allowed")
                continue
            bad = [c for c in ids if c not in claims]
            if bad:
                errors.append(f"sentence {i}: cites unknown claim ID(s) {', '.join(bad)}")
                continue
            support = " ".join(claims[c].text + " " + " ".join(ct.text for ct in claims[c].citations) for c in ids).lower()
            for ip in IP_RE.findall(text):
                if ip not in self.known_ips:
                    errors.append(f"sentence {i}: IP {ip} does not exist in the evidence")
                elif ip not in support:
                    errors.append(f"sentence {i}: IP {ip} is not part of the claims it cites")
            for u in self.usernames:
                if re.search(rf"(?<![\w.@-]){re.escape(u)}(?![\w@-])", text) and u not in support:
                    errors.append(f"sentence {i}: user {u} is not part of the claims it cites")
            for a in self.refs.assets:
                if re.search(rf"(?<![\w-]){re.escape(a.hostname)}(?![\w-])", text) and not any(al.lower() in support for al in self._aliases(a.hostname)):
                    errors.append(f"sentence {i}: host {a.hostname} is not part of the claims it cites")
            for num in re.findall(r"\b\d{1,3}(?:,\d{3})+\b|\b\d{5,}\b", text):
                if num not in support and num.replace(",", "") not in support.replace(",", ""):
                    errors.append(f"sentence {i}: number {num} is not in the claims it cites")
            confirmed = all(claims[c].status == "CONFIRMED" for c in ids)
            if not any(claims[c].status == "CONFIRMED" for c in ids) and not HEDGE.search(text):
                errors.append(f"sentence {i}: states a Suspected / Not-enough-evidence claim as fact (no hedge such as 'suspected', 'may', 'not shown')")
            if not confirmed and self._strong_violations(text, support):
                s["text"] = self.downgrade(text)
                downgrades.append(f"sentence {i}: strong wording on a claim that is not CONFIRMED - downgraded")
        return dict(passed=not errors, errors=errors, downgrades=downgrades, sentences=len(sentences))
