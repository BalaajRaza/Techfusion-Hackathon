# Security Incident Triage Assistant: Build Pipeline, Edge Cases and Security

Tech Fusion '26 AI Hackathon, Problem C (Orbit Logistics). This document covers the end-to-end pipeline, where each edge case is handled, the security features, and the reliability layer.

---

## 1. Why Problem C

All three problems test the same skill: stay grounded in the files, never guess, and admit gaps. Problem C is the least crowded and leaves the most room to stand out.

| | A: Policy Q&A | B: Lab Explainer | C: Incident Triage |
|---|---|---|---|
| Teams likely to pick it | Most | Many | Fewest |
| Difficulty in 4 hours | Low-medium | Medium | High |
| Room to differentiate | Low | Medium | Very high |
| Hidden test-set risk | Low | Low-medium | Medium-high (unknown log formats) |

Problem C rewards deterministic code, not prompting: timestamp normalization, entity matching, and window checks. A single-prompt approach fails here, which is what the Innovation criterion looks for.

**Main risk:** if the parsers break on an unseen log format, the leaderboard score suffers. Mitigation: format-tolerant parsers, with an LLM used only for format detection as a fallback.

**Fallback choice:** Problem B, if the timeline pipeline is not working within the first 90 minutes.

> Check the organizer's starter repo and README first. It likely defines the exact output schema the automated leaderboard (20%) expects. Build to that schema.

---

## 2. Design Principle

**The LLM writes language. Code establishes facts.**

Stages 1 to 10 are pure code and produce a structured JSON case file. The LLM appears only in stage 11 (report prose) and, optionally, in stage 2 (format detection). Everything the LLM sees is already verified.

---

## 3. Pipeline Overview

```
Raw files -> [1 Ingest] -> [2 Parse] -> [3 Time normalize] -> [4 Entity resolve]
          -> [5 Detect & cluster] -> [6 Context filter (change calendar)]
          -> [7 Severity] -> [8 Coverage/gaps] -> [9 Evidence ledger]
          -> [10 Runbook + escalation] -> [11 Report (LLM) + verifier] -> UI/API

Cross-cutting: security layer | rate-limit layer | edge-case test pack
```

### Core data model

Every parsed line becomes one `Event`. This is the backbone of all citations.

```
Event {
  id, source_file, line_no, raw_line,
  ts_utc, ts_original, tz_source, tz_assumed (bool),
  source_type, host, ip, user, action, outcome, fields{},
  parse_status
}
```

Everything downstream references `file:line`, so the citation requirement is satisfied automatically.

---

## 4. Stage-by-Stage Pipeline and Edge Cases

### Stage 1: Ingest and classify files

Separate log files (auth, web, firewall, email) from reference files (asset inventory, severity matrix, runbooks, escalation sheet, change calendar, security rules).

**Edge cases**
- UTF-8 BOM, CRLF line endings, gzip files, empty files.
- Repeated CSV headers mid-file.
- Multi-line entries (such as stack traces) must stay one event.
- Decide a line-numbering convention (1-based, header counts as line 1) and **state it in the report**.

### Stage 2: Parse per source

One parser per format, each outputting `Event`.

**Edge cases**
- **Malformed or truncated lines go to a quarantine list with file:line. Never drop silently.** The report states how many lines could not be parsed.
- Quoted commas, missing fields, extra whitespace.
- Duplicate lines (log shipping duplicates): dedupe for analysis but keep every original line reference.
- Unknown format: use the LLM on a few sample lines to detect the format and generate a regex, then validate it on the remaining lines. This protects against unseen test files.

### Stage 3: Time normalization

Convert everything to UTC while keeping `ts_original`. This stage is a likely source of trap questions.

**Edge cases**
- Formats: ISO 8601 with `Z` or offset, epoch seconds vs milliseconds, Apache style `[14/Nov/2026:03:22:11 +0500]`, 12-hour AM/PM.
- **Syslog with no year and no timezone:** infer the year from the other files. Take the timezone from a file header, the inventory, or the security rules.
- Ambiguous abbreviations (CST, IST) and ambiguous dates (`03/04/2026`): infer the format from other lines in the same file.
- DST transitions, including nonexistent or repeated local times.
- **If the timezone truly cannot be determined, never guess silently.** Mark `tz_assumed=true`, show both interpretations, and note the effect on ordering.
- **Clock skew:** compare the same event across two systems (for example, a firewall allow followed by a login). If a consistent offset appears, flag it and show the corrected timeline.
- Sorting ties: break by timestamp, then source priority, then line number, so ordering is deterministic.
- Year rollover (Dec 31 to Jan 1) in syslog.

### Stage 4: Entity resolution

Build an alias graph linking hostname, IP, asset tag, and user. Every link is an edge carrying its evidence.

**Edge cases**
- Hostname case differences and FQDN vs short name.
- IP formatting (leading zeros, IPv6).
- **IP-to-host mappings are valid only for a time window** (DHCP leases). Store the validity interval on each edge.
- User variants: `DOMAIN\user`, `user@domain`, email local part. Service and shared accounts.
- NAT: the firewall shows a public or translated address while the inventory has a private one.
- **Ambiguous match:** keep all candidates, mark `ambiguous`, and show it in the report. Never merge silently.
- Confidence tiers: inventory exact match is high; co-occurrence inference is medium; name similarity is low (suggest only).

### Stage 5: Detection and incident clustering

Rule-based detectors run over the normalized events:

- Brute force followed by a successful login
- Password spray (one IP, many users)
- Off-hours login
- Suspicious web paths (SQL injection patterns, traversal, scanner user agents)
- Firewall port scans and large outbound transfers
- Phishing email followed by a login or click
- Lateral movement

**Edge cases**
- Threshold boundaries: define `>=` vs `>` explicitly. Use thresholds from the security rules file when present; label any others as heuristics.
- Use a sliding window so bursts that straddle a window edge are still caught.
- Benign failed logins (expired password, typo then success) must not be flagged as attacks.
- Cluster events into incidents by shared entities within a time proximity, then order them as a kill chain (initial access, escalation, movement, impact).
- Multiple incidents in the same logs: keep them separate. Do not merge into one story.

### Stage 6: Context filter (change calendar and noise)

Test each candidate incident against the change calendar.

**Suppress only if all of these match:** time window (in the calendar's timezone), asset scope, actor or source IP, activity type, and approval status.

**Edge cases**
- Approved scanner, **but outside the window** or against an **out-of-scope asset**: not harmless, still escalated.
- Window overruns and partial overlap: split the activity. The covered part is suppressed; the remainder stays.
- Calendar entries that are requested, cancelled, or rejected (not "approved").
- Recurring entries (for example, every Sunday 02:00).
- **An attacker hiding inside a maintenance window:** suppress only the matching activity, and keep any residual anomaly (for example, an unfamiliar account logging in during the window).
- Suppressed items are never deleted. They appear in an "Excluded as benign" section with the calendar citation.

### Stage 7: Severity assignment

Look up each affected asset's criticality in the inventory, then the matrix lookup by incident type and asset criticality.

**Edge cases**
- Several assets involved: use the highest criticality and show which asset drove it.
- Asset not in the inventory: say "cannot assign criticality". Use a fallback only if the matrix defines one.
- Incident type does not match any matrix row: report the closest mapping and flag it, or escalate for human decision.
- Show every step: type, asset, criticality, matrix cell, result.

### Stage 8: Coverage and gap analysis

Build per-source time coverage from min and max timestamps and the typical inter-event interval.

**Edge cases**
- A gap is detected when the silence exceeds a multiple of the normal interval. State that this is heuristic.
- An asset in the inventory that has no logs at all.
- **A gap overlapping the incident window:** report "no logs for system X from T1 to T2". Never say "nothing happened".
- Use this gap list to cap what can be claimed in stage 9.

### Stage 9: Evidence ledger (confirmed / suspected / not enough evidence)

Each claim is an object: `{claim, status, evidence[], rule}`.

| Status | Meaning |
|---|---|
| Confirmed | A direct log line states it |
| Suspected | Inferred from correlation, with the inference rule shown |
| Not enough evidence in the logs | Asked about but not supported |

**Edge cases**
- Predefine claims that are never confirmable from logs alone: data exfiltrated or read, attacker identity or intent, credentials stolen (vs guessed), persistence. Large outbound bytes in a firewall log make "suspected", never "confirmed".
- A claim touching a coverage gap becomes at most "suspected", with the gap cited.
- Conflicting evidence across files: report both instead of picking one.

### Stage 10: Runbook actions and escalation

Parse the runbooks into step IDs ahead of time.

**Edge cases**
- The LLM may only choose from enumerated step IDs (JSON schema enum). Reject anything else in code.
- No runbook for the incident type: say "no approved runbook" and escalate per the sheet. Do not improvise.
- Preserve the runbook's ordering and cite step IDs.
- Escalation: severity maps to who must be informed and within what time. Compute the deadline from your defined detection time (first confirmed malicious event) in the correct timezone. State this definition.
- Contacts outside business hours or on-call rules, if the sheet has them.

### Stage 11: Report generation and verification

Send the LLM the structured case file (pseudonymized) and have it write prose using claim IDs.

**Verifier (code, after generation)**
- Every sentence maps to claim IDs, and each cited `file:line` actually contains the entities mentioned.
- No new IPs, hosts, users, or numbers appear that are not in the case file.
- Strong words ("compromised", "exfiltrated") appear only for claims with status "confirmed".
- On failure: regenerate once, then fall back to a template-based report.

**Report sections:** summary, timeline, affected assets and accounts, severity derivation, excluded as benign, confirmed / suspected / not enough evidence, data gaps, recommended actions with runbook steps, notifications and deadlines.

Also expose a question-answering endpoint that answers from the structured store (events and ledger), not from raw logs. Output both JSON and Markdown.

---

## 5. Unique Features Summary

These are features few other teams are likely to build:

1. **Claim verifier:** a code pass that checks every report sentence against its cited log lines.
2. **Evidence ledger** with strict confirmed / suspected / not enough evidence rules.
3. **Time-aware entity resolution** (IP-to-host mappings valid only for a time window).
4. **Clock-skew detection** across systems.
5. **Coverage and gap map** per source.
6. **Strict noise suppression** (window, scope, actor, approval, all must match).
7. **Runbook-constrained actions** enforced by schema.
8. **Escalation SLA countdown** from the detection time.
9. **Interactive timeline** colored by confidence, with click-through to the raw log line.

Avoid adding MITRE ATT&CK mapping unless the provided files contain it. It would break the "use only the files given" rule.

---

## 6. Security Features

- **Logs are attacker-controlled input.** Treat all log content as untrusted data. Wrap it in delimiters, never place it in the instruction part of a prompt, and run an injection detector. If a log line contains something like "ignore previous instructions", flag it as a **finding** in the report. Plant one in your own demo data to show this.
- **Pseudonymize before any API call.** Replace IPs, usernames, and emails with tokens, then restore them locally.
- **Redact secrets** (tokens, passwords, keys) found in logs from the output.
- **Tamper-evident report.** Include a SHA-256 hash of the evidence bundle and the report for chain of custody.
- **Data minimization.** Send the LLM only the structured case file or the minimum excerpts needed, not raw logs.

---

## 7. Reliability (Technical Implementation = 25%)

- Retry with exponential backoff on rate limits.
- Fall back across models (Groq, then OpenRouter).
- Cache LLM calls by input hash.
- If every LLM call fails, the template-based report still works, so the demo never fails.
- Handle errors cleanly: malformed input gives a clear message, never a crash.
- Commit small and often, since judges review the commit history.
- Docker as a backup if hosting fails.

---

## 8. Test Pack (build in hour 1)

Create a small synthetic dataset with **one planted example for each edge case** and an expected result:

- A mixed-timezone pair of logs
- An out-of-window scan
- An IP reused by two hosts
- A log gap during the incident
- A prompt-injection line
- A malformed row
- An unknown asset
- A scan by the approved scanner against an out-of-scope asset

Run it after every stage. Each passing case is also a clean commit for the repo review.

---

## 9. Suggested Repo Layout

```
ingest/  parsers/  timeutil/  entities/  detect/  context/
severity/  coverage/  ledger/  runbook/  report/  verify/
security/  api/  ui/  tests/edge_cases/
```

---

## 10. Suggested 4-Hour Plan

| Time | Goal |
|---|---|
| 0:00 - 1:30 | Parsers, UTC normalization, unified event schema with `file:line` provenance |
| 1:30 - 2:30 | Entity graph, severity matrix lookup, change-calendar suppression |
| 2:30 - 3:15 | Runbook-constrained actions, report generator, claim verifier |
| 3:15 - 4:00 | UI timeline, injection demo, README, demo video, deployment |

**Submission checklist:** GitHub repository link, live hosted link (Vercel or Netlify) or Docker setup, and a demo video, all uploaded to the ETL platform.
