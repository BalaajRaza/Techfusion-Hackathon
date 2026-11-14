"""Question answering over the STRUCTURED store (case file + parsed evidence),
never over raw text handed to a model.

1. Every claim, timeline entry, exclusion, gap, action, contact, reference row
   and parsed log line is a Fact with its citations.
2. Retrieval is deterministic (IDF-weighted lexical match + entity boosts).
3. If a model is available it may phrase the answer from the retrieved facts,
   citing fact IDs; the code verifier checks it. Otherwise - or when the
   verifier rejects the model's answer - the retrieved facts are returned as-is.
4. If nothing relevant is found the answer is "not enough evidence", not a guess.
"""
from __future__ import annotations

import math
import re
from typing import Any, Optional

from .llm.gateway import LLMGateway
from .llm.prose import write_prose
from .models import TIER_LABEL, Citation, Claim
from .pipeline import timeutil as tu
from .pipeline.references import IP_RE
from .pipeline.run import Runtime
from .security import injection

STOP = set("a an the is are was were be been of in on at to for from by with and or not as it its this that these those which who whom what when where why how "
           "did do does done has have had will would can could should may might there their they them he she his her any all some about into than then also "
           "tell me us please give show list explain describe happened happen between during after before our we you your i".split())
SYNONYMS = {
    "harmless": ["closed", "approved", "harmless", "change"], "benign": ["closed", "approved", "harmless"], "noise": ["closed", "approved", "harmless"],
    "false": ["closed", "approved"], "positive": ["closed", "approved"], "approved": ["approved", "change", "closed"], "maintenance": ["change", "approved", "window"],
    "notify": ["inform", "contact"], "notified": ["inform", "contact"], "inform": ["inform", "contact"], "informed": ["inform", "contact"], "escalate": ["inform", "contact", "escalation"],
    "escalation": ["inform", "contact"], "call": ["inform", "contact", "phone"], "deadline": ["deadline", "limit", "inform"], "sla": ["deadline", "limit", "inform"],
    "severity": ["severity", "matrix", "criticality"], "priority": ["severity", "matrix"], "critical": ["severity", "criticality"],
    "exfiltration": ["transfer", "exfiltration"], "exfiltrated": ["transfer", "exfiltration"], "stolen": ["transfer", "password", "files"], "leaked": ["transfer", "files"],
    "stole": ["transfer", "files"], "transferred": ["transfer", "bytes", "files"], "transfer": ["transfer", "bytes"], "moved": ["transfer", "bytes"], "taken": ["transfer"], "data": ["transfer", "data", "files"], "files": ["files", "audit", "transfer"],
    "timezone": ["zone", "utc", "pkt"], "zone": ["zone", "utc", "pkt"], "timezones": ["zone", "utc", "pkt"], "skew": ["clock", "skew"],
    "gap": ["gap", "logs", "missing", "collected"], "gaps": ["gap", "logs", "missing", "collected"], "missing": ["gap", "missing", "collected"], "blind": ["gap", "missing"],
    "runbook": ["runbook", "step"], "action": ["runbook", "step"], "actions": ["runbook", "step"], "steps": ["runbook", "step"], "next": ["runbook", "step"],
    "recommend": ["runbook", "step"], "recommended": ["runbook", "step"], "block": ["block", "step"],
    "phish": ["phishing", "email"], "phishing": ["phishing", "email", "link"], "clicked": ["click", "connected", "link"], "click": ["click", "connected", "link"],
    "sqli": ["sql", "injection"], "injection": ["injection", "sql"], "attacker": ["attacker", "source", "address"], "scan": ["scan", "port"], "scanning": ["scan", "port"],
    "mfa": ["mfa", "push"], "vpn": ["vpn", "session"], "login": ["login", "logon"], "logins": ["login", "logon"], "password": ["password", "reset"],
    "lockout": ["locked", "lockout"], "locked": ["locked", "lockout"], "rdp": ["remote", "desktop"], "incidents": ["incident", "severity"], "many": ["incident"],
    "quarantined": ["quarantined", "quarantine", "malformed"], "malformed": ["quarantined", "malformed"], "confirmed": ["confirmed"], "suspected": ["suspected"],
    "owner": ["owner"], "phone": ["phone"], "romania": ["ro", "geo"], "country": ["geo", "country"],
}
INTENT_BOOST = {
    "contact": (r"\b(inform|notify|notified|escalat\w*|contact|call|who (must|should|needs)|deadline|sla|time limit)\b", 2.2),
    "severity": (r"\b(severity|priority|p[1-4]|how (serious|severe)|criticality)\b", 2.0),
    "closed": (r"\b(harmless|benign|noise|false positive|approved|closed|maintenance|change (calendar|id)|legitimate)\b", 2.4),
    "action": (r"\b(runbook|action|steps?|what (should|do) we do|recommend\w*|next|contain\w*|remediat\w*)\b", 2.0),
    "gap": (r"\b(gap|missing|not collected|blind|coverage|cannot (see|tell)|unknown|not enough evidence)\b", 1.8),
    "time": (r"\b(time ?zone|utc|pkt|clock|skew|convert\w*)\b", 2.0),
    "incident": (r"\b(incidents?|summary|summar\w+|overview|what happened|kill chain)\b", 1.8),
    "audit": (r"\b(quarantin\w*|malformed|pars\w+|prompt.?injection|integrity|hash|sha)\b", 2.2),
}
ID_RE = re.compile(r"\b(?:CHG|ALT|RB|INC|VS|M|A)-[A-Za-z0-9-]+\b")


def tokens(text: str) -> list[str]:
    text = text.lower()
    out = re.findall(r"(?:\d{1,3}\.){3}\d{1,3}|[a-z0-9]+(?:[-_][a-z0-9]+)*", text)
    extra = [p for t in out if "-" in t or "_" in t for p in re.split(r"[-_]", t)]
    return [t for t in out + extra if t and t not in STOP]


class FactStore:
    def __init__(self, rt: Runtime):
        self.rt = rt
        self.facts: list[dict[str, Any]] = []
        self._build()
        self.df: dict[str, int] = {}
        for f in self.facts:
            f["tokens"] = set(tokens(f["text"] + " " + f.get("extra", "")))
            for t in f["tokens"]:
                self.df[t] = self.df.get(t, 0) + 1
        self.n = max(1, len(self.facts))

    def _add(self, kind: str, text: str, citations: list[Any], tier: Optional[str] = None, incident: Optional[str] = None, weight: float = 1.0, extra: str = "") -> None:
        cs = [c if isinstance(c, dict) else c.model_dump() for c in citations if c]
        self.facts.append(dict(id=f"C{len(self.facts) + 1}", kind=kind, text=text, citations=cs, tier=tier, incident=incident, weight=weight, extra=extra))

    def _build(self) -> None:
        case, rt = self.rt.case, self.rt
        loc_h, loc_l = case["company"]["local_tz_hours"], case["company"]["local_tz_label"]
        for inc in rt.incidents:
            iid = inc.incident_id
            self._add("incident", f"Incident {iid}: {inc.title}. Severity {inc.severity or 'not assigned'}; incident type: {inc.incident_type}; status {inc.status}. "
                                  f"SOC clock start {tu.fmt_utc(inc.detection_time_utc, True)}. {inc.detection_basis}", inc.detection_citations, "CONFIRMED", iid, 1.0,
                      extra="incident summary overview what happened how many incidents " + " ".join(inc.kill_chain))
            for p in inc.severity_parts:
                self._add("severity", f"Severity of {iid}, part '{p.part}': {p.result or 'no matrix result'}. " + " ".join(re.sub(r"\s*\[[^\]]+\]", "", s) for s in p.steps), p.citations, "CONFIRMED", iid, 1.3,
                          extra="severity matrix criticality why derivation")
            if inc.severity_steps:
                self._add("severity", f"Overall severity of {iid}: {inc.severity}. " + " ".join(re.sub(r"\s*\[[^\]]+\]", "", s) for s in inc.severity_steps),
                          [c for p in inc.severity_parts for c in p.citations][:6], "CONFIRMED", iid, 1.4, extra="severity overall highest rule 4.2")
            for c in inc.claims:
                self._add("claim", c.text + (f" ({'Guess / rule' if c.status == 'SUSPECTED' else 'Basis'}: {c.rule})" if c.rule else ""), c.citations, c.status, iid, 1.5, extra=c.topic)
            for a in inc.actions:
                self._add("action", f"Recommended action for {iid}: {a.runbook_id} step {a.step_no}: {a.text}" + (f" Evidence: {a.context}" if a.context else ""),
                          [a.citation] + a.context_citations, "CONFIRMED", iid, 1.0, extra="runbook step action recommended")
            for c in inc.contacts:
                dl = f"; deadline {tu.fmt_utc(c.deadline_utc, True)}" if c.deadline_utc else ""
                self._add("contact", f"People to inform for {iid} (severity {c.severity}): {c.role}" + (f" - {c.name}" if c.name else "") + (f" ({c.contact})" if c.contact else "")
                          + f", within {c.time_limit}, by: {c.how}{dl}." + (f" {c.note}" if c.note else ""), c.citations, "CONFIRMED", iid, 1.3,
                          extra="inform contact escalation notify who time limit phone")
            for a in inc.affected_assets:
                self._add("asset", f"Affected asset in {iid}: {a['hostname']} ({a.get('type')}, criticality {a.get('criticality')}, owner {a.get('owner')}) - {'; '.join(a['roles'])}. "
                                   f"{'Counted as reached' if a.get('reached') else ('Not counted as reached' if a.get('reached') is False else 'Targeted')}: {'; '.join(a['basis'])}.",
                          a["citations"], "CONFIRMED", iid, 1.2, extra="affected asset system reached")
        for x in case["exclusions"]:
            crit = "; ".join(f"{c['label']}: {'pass' if c['ok'] else 'FAIL'} ({c['detail']})" for c in x["criteria"])
            self._add("closed", f"Closed as harmless under {x['change_id']}: {x['title']}. {x['reason']} Checks: {crit}",
                      [x["change_citation"]] + x["events"] + x["alerts"] + x["rule_citations"], "CONFIRMED", None, 1.6, extra="harmless benign approved change calendar noise not an incident")
        for a in case["alert_dispositions"]:
            self._add("alert", f"IDS alert {a['alert_id']} ({a['description']}) raised at {a['ts'][:19].replace('T', ' ')} UTC: disposition {a['disposition']}; linked log lines: "
                               f"{', '.join(a['trigger_events']) or 'none'}.", [dict(file=a["ref"].split(":")[0], locator=a["ref"].split(":")[1], text="")], "CONFIRMED", None, 1.1, extra="alert ids disposition")
        for g in case["coverage"]["gaps"]:
            self._add("gap", f"Log gap: no {g['source'].lower()} logs from {g['start_utc'][:19].replace('T', ' ')} UTC to {g['end_utc'][:19].replace('T', ' ')} UTC ({g['kind'].replace('_', ' ')}). {g['reason']}",
                      [g["citation"]], "CONFIRMED", None, 1.2, extra="gap missing logs coverage blind")
        for m in case["coverage"]["missing_sources"]:
            self._add("gap", f"Log source not collected: {m['text']}", [m["citation"]], "CONFIRMED", None, 1.2, extra="gap missing not collected log source")
        for s in case["time_normalization"]["sources"]:
            ex = s.get("example") or {}
            self._add("time", f"Time zone of {s['file']}: {s['policy']}" + (f"; logged when the {'session closes' if s['logged_at'] == 'close' else 'connection starts'}" if s.get("logged_at") else "")
                      + (f". Example: '{ex.get('original')}' = {str(ex.get('utc'))[:19]} UTC ({ex.get('source')})." if ex else "."),
                      [s["citation"]] if s.get("citation") else [], "CONFIRMED", None, 1.0, extra="time zone utc pkt convert clock")
        self._add("time", "Clock skew check: " + case["time_normalization"]["clock_skew"]["verdict"], [], "CONFIRMED", None, 1.0, extra="clock skew time systems")
        pa = case["parsing_audit"]
        self._add("audit", f"Parsing audit: {pa['parsed']} of {pa['total_lines']} log lines parsed; {len(pa['quarantined'])} quarantined; {len(pa['duplicates'])} duplicate line(s); "
                           f"{len(pa['injection_hits'])} prompt-injection hit(s). " + " ".join(f"Quarantined {q['ref']}: {q['reason']}." for q in pa["quarantined"]),
                  [dict(file=q["ref"].split(":")[0], locator=q["ref"].split(":")[1], text=q["raw"]) for q in pa["quarantined"]], "CONFIRMED", None, 1.0,
                  extra="parsing quarantined malformed lines prompt injection")
        self._add("audit", f"Evidence integrity digest (SHA-256): {case['integrity']['evidence_integrity_digest']}. Line convention: {case['line_convention']}", [], "CONFIRMED", None, 0.8,
                  extra="integrity hash sha256 tamper citation convention line numbering")
        for f in rt.files.values():
            if f.file_type == "log":
                continue
            for u in f.units:
                if u.kind in ("row", "step", "rule", "text") and len(u.text) > 3:
                    self._add("reference", f"{f.title}: {u.text.strip('| ').replace(' | ', '; ')}", [Citation(file=f.filename, locator=u.locator, text=u.text)], "CONFIRMED", None, 0.7)
        for e in rt.ctx.all_events if rt.ctx else []:
            when = f"{tu.fmt_utc(e.ts_utc, True)} ({tu.fmt_local(e.ts_utc, loc_h, loc_l)})" if e.ts_utc else "unparsed"
            raw = injection.sanitize(e.raw_line)
            self._add("event", f"Log line {e.id} at {when}: {raw}", [Citation(file=e.source_file, locator=e.locator, text=e.raw_line)], "CONFIRMED", None, 0.55,
                      extra=f"{e.action} {e.outcome} {e.user_account or ''}")

    def search(self, question: str, k: int = 8) -> list[dict[str, Any]]:
        q = tokens(question)
        expanded: dict[str, float] = {}
        for t in q:
            expanded[t] = max(expanded.get(t, 0), 1.0)
            for s in SYNONYMS.get(t, []):
                expanded[s] = max(expanded.get(s, 0), 0.6)
        entities = set(IP_RE.findall(question)) | {m.lower() for m in ID_RE.findall(question)}
        if self.rt.refs:
            entities |= {u.username for u in self.rt.refs.users if re.search(rf"\b{u.username}\b", question, re.I)}
            entities |= {a.hostname.lower() for a in self.rt.refs.assets if a.hostname.lower() in question.lower()}
            for u in self.rt.refs.users:  # "Ayesha" / "Malik" -> username
                if any(re.search(rf"\b{re.escape(part)}\b", question, re.I) for part in u.full_name.split()):
                    entities.add(u.username)
        boosts = {kind: mult for kind, (pat, mult) in INTENT_BOOST.items() if re.search(pat, question, re.I)}
        scored = []
        for f in self.facts:
            s = 0.0
            for t, w in expanded.items():
                if t in f["tokens"]:
                    s += w * math.log(1 + self.n / self.df.get(t, 1))
            ent_hits = sum(1 for e in entities if e in f["tokens"] or e in f["text"].lower())
            s += 4.0 * ent_hits
            if entities and not ent_hits and f["kind"] in ("event", "reference"):
                s *= 0.4
            s *= f["weight"] * boosts.get(f["kind"], 1.0)
            if s > 0:
                scored.append((s, f))
        scored.sort(key=lambda x: -x[0])
        if not scored:
            return []
        top = scored[0][0]
        out = [dict(f, score=round(s, 2)) for s, f in scored[:k] if s >= 0.35 * top]
        return out if top >= 3.0 else []


def answer(rt: Runtime, store: FactStore, question: str, use_llm: bool = True, verify: bool = True, engine: Optional[str] = None) -> dict[str, Any]:
    question = question.strip()[:600]
    flagged = injection.scan(question)
    hits = store.search(question)
    base = dict(question=question, injection_signatures=flagged)
    if not hits:
        return dict(base, source="deterministic", sentences=[dict(text="Not enough evidence in the logs: nothing in the case file or the 20 source files matches this question. "
                                                                         "I will not guess.", tier="INSUFFICIENT_EVIDENCE", citations=[])], facts=[], verifier=None)
    facts_out = [dict(id=f["id"], kind=f["kind"], tier=f["tier"], incident=f["incident"], text=f["text"], citations=f["citations"], score=f["score"]) for f in hits]
    det = [dict(text=f["text"], tier=f["tier"], citations=f["citations"], kind=f["kind"], incident=f["incident"]) for f in hits[:6]]
    gw = LLMGateway(engine) if engine else rt.gateway
    if use_llm and gw and rt.verifier and rt.refs and gw.mode != "off":
        claims = [Claim(claim_id=f["id"], text=f["text"], status=f["tier"] or "CONFIRMED", citations=[Citation(**c) for c in f["citations"]]) for f in hits]
        prose = write_prose(gw, "Answer the analyst's question in plain English.", claims, rt.refs, rt.verifier, n_sentences="2 to 4", question=question, verify=verify)
        if prose["sentences"]:
            by_id = {f["id"]: f for f in hits}
            sentences = []
            for s in prose["sentences"]:
                used = [by_id[i] for i in s["claim_ids"] if i in by_id]
                tiers = {u["tier"] for u in used}
                tier = "INSUFFICIENT_EVIDENCE" if "INSUFFICIENT_EVIDENCE" in tiers else ("SUSPECTED" if "SUSPECTED" in tiers else "CONFIRMED")
                seen: set[str] = set()
                cites = []
                for u in used:
                    for c in u["citations"]:
                        ref = f"{c['file']}:{c['locator']}"
                        if ref not in seen:
                            seen.add(ref)
                            cites.append(c)
                sentences.append(dict(text=s["text"], tier=tier, citations=cites[:10], fact_ids=s["claim_ids"]))
            return dict(base, source=prose["source"], sentences=sentences, facts=facts_out, verifier=prose["log"])
        return dict(base, source="deterministic (model answer rejected or unavailable)", sentences=det, facts=facts_out, verifier=prose["log"])
    return dict(base, source="deterministic", sentences=det, facts=facts_out, verifier=None)
