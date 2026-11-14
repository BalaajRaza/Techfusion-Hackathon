-- Security Incident Triage Assistant - Supabase schema (plan section 4).
--
-- Differences from the plan's draft, all deliberate:
--   * Row Level Security is ENABLED on every table and no policy is created.
--     Security logs must not be readable with the public anon key; only the
--     backend (service-role key, which bypasses RLS) reads and writes them.
--   * quarantined_lines: the plan's "never drop a line" guarantee needs a home
--     for lines that have no timestamp (events.ts_utc is NOT NULL).
--   * Row ids are supplied by the backend as UUIDv5 of the citation, so a
--     re-run of the pipeline upserts instead of duplicating rows.
--   * Every foreign-key column is indexed; CHECK constraints pin the enums.
--   * events.locator holds the citation locator (L7, ALT-9002, ...).

create extension if not exists vector with schema extensions;

-- 1. raw files & ingestion metadata -----------------------------------------
create table if not exists public.raw_files (
    id uuid primary key default gen_random_uuid(),
    filename text not null unique,
    file_type text not null check (file_type in ('log', 'reference', 'runbook')),
    total_lines int not null,
    sha256_hash text not null,
    ingested_at timestamptz not null default now()
);

-- 2. unified parsed events (the grounding backbone) --------------------------
create table if not exists public.events (
    id uuid primary key default gen_random_uuid(),
    source_file text not null,
    line_no int not null,                 -- 1-based; for logs, line 1 = first line inside the code block
    locator text not null,                -- citation locator: L7, ALT-9002 ...
    raw_line text not null,
    ts_utc timestamptz not null,
    ts_start_utc timestamptz,             -- derived session start (close-logged sources)
    ts_end_utc timestamptz,
    ts_original text not null,
    tz_source text not null,
    tz_assumed boolean not null default false,
    source_type text not null,
    host text,
    ip_source inet,
    ip_dest inet,
    user_account text,
    action text not null,
    outcome text not null,
    fields jsonb not null default '{}'::jsonb,
    parse_status text not null default 'parsed' check (parse_status in ('parsed', 'quarantined')),
    quarantine_reason text,
    flags text[] not null default '{}',
    created_at timestamptz not null default now(),
    unique (source_file, locator)
);
create index if not exists idx_events_ts_utc on public.events (ts_utc);
create index if not exists idx_events_ip_src on public.events (ip_source);
create index if not exists idx_events_user on public.events (user_account);
create index if not exists idx_events_file_line on public.events (source_file, line_no);

-- 2b. lines no parser understood: kept, cited, shown in the parsing audit ----
create table if not exists public.quarantined_lines (
    id uuid primary key default gen_random_uuid(),
    source_file text not null,
    locator text not null,
    raw_line text not null,
    reason text not null,
    created_at timestamptz not null default now(),
    unique (source_file, locator)
);

-- 3. temporal entity graph ----------------------------------------------------
create table if not exists public.entity_nodes (
    id uuid primary key default gen_random_uuid(),
    entity_type text not null check (entity_type in ('IP', 'HOSTNAME', 'USER', 'ASSET_TAG')),
    entity_val text not null unique,
    metadata jsonb not null default '{}'::jsonb
);

create table if not exists public.entity_edges (
    id uuid primary key default gen_random_uuid(),
    source_entity text not null,
    target_entity text not null,
    relation text not null,               -- inventory_ip, dhcp_lease, vpn_assigned_ip, assigned_laptop ...
    valid_from timestamptz,               -- null = no time bound (static inventory mapping)
    valid_until timestamptz,
    confidence text not null check (confidence in ('HIGH', 'MEDIUM', 'LOW')),
    evidence_citation text not null       -- e.g. 19_dhcp_lease_log.md:L2
);
create index if not exists idx_entity_edges_source on public.entity_edges (source_entity);
create index if not exists idx_entity_edges_target on public.entity_edges (target_entity);

-- 4. change calendar (operational baseline for noise filtering) --------------
create table if not exists public.change_calendar (
    change_id text primary key,
    date date not null,
    window_start_pkt time not null,
    window_end_pkt time not null,
    window_start_utc timestamptz not null,
    window_end_utc timestamptz not null,
    system_target text not null,
    target_ip_cidr text,
    performed_by text not null,
    description text not null,
    status text not null
);

-- 5. triaged incidents --------------------------------------------------------
create table if not exists public.incidents (
    incident_id text primary key,
    title text not null,
    incident_type text not null,
    severity text check (severity in ('P1', 'P2', 'P3', 'P4')),   -- null = no matrix row, human decision
    severity_derivation jsonb not null,
    highest_criticality_asset text,
    detection_time_utc timestamptz,
    sla_deadline_utc timestamptz,
    status text not null default 'TRIAGED',
    created_at timestamptz not null default now()
);

-- 6. evidence ledger ----------------------------------------------------------
create table if not exists public.evidence_claims (
    id uuid primary key default gen_random_uuid(),
    incident_id text not null references public.incidents (incident_id) on delete cascade,
    claim_id text not null,
    claim_text text not null,
    status text not null check (status in ('CONFIRMED', 'SUSPECTED', 'INSUFFICIENT_EVIDENCE')),
    inference_rule text,
    cited_sources jsonb not null,         -- [{file, locator, text}]
    created_at timestamptz not null default now(),
    unique (incident_id, claim_id)
);
create index if not exists idx_evidence_claims_incident on public.evidence_claims (incident_id);

-- 7. noise exclusion log (suppressed, never deleted) --------------------------
create table if not exists public.benign_exclusions (
    id uuid primary key default gen_random_uuid(),
    event_id uuid not null references public.events (id) on delete cascade,
    change_id text not null references public.change_calendar (change_id) on delete cascade,
    exclusion_reason text not null,
    matched_criteria jsonb not null,      -- the five checks with pass/fail and detail
    created_at timestamptz not null default now(),
    unique (event_id, change_id)
);
create index if not exists idx_benign_exclusions_event on public.benign_exclusions (event_id);
create index if not exists idx_benign_exclusions_change on public.benign_exclusions (change_id);

-- 8. runbook steps ------------------------------------------------------------
create table if not exists public.runbook_actions (
    id uuid primary key default gen_random_uuid(),
    incident_id text not null references public.incidents (incident_id) on delete cascade,
    runbook_id text not null,
    step_no int not null,
    action_text text not null,
    status text not null default 'PENDING',
    citation text not null,
    unique (incident_id, runbook_id, step_no)
);
create index if not exists idx_runbook_actions_incident on public.runbook_actions (incident_id);

-- 9. reports & hashes ---------------------------------------------------------
create table if not exists public.reports (
    id uuid primary key default gen_random_uuid(),
    incident_id text not null unique references public.incidents (incident_id) on delete cascade,
    markdown_content text not null,
    json_payload jsonb not null,
    evidence_sha256 text not null,
    verifier_passed boolean not null,
    verifier_log jsonb not null,
    generated_at timestamptz not null default now()
);

-- Row Level Security: on everywhere, no policies -> the anon / authenticated
-- API roles see nothing. The backend uses the service-role key.
alter table public.raw_files enable row level security;
alter table public.events enable row level security;
alter table public.quarantined_lines enable row level security;
alter table public.entity_nodes enable row level security;
alter table public.entity_edges enable row level security;
alter table public.change_calendar enable row level security;
alter table public.incidents enable row level security;
alter table public.evidence_claims enable row level security;
alter table public.benign_exclusions enable row level security;
alter table public.runbook_actions enable row level security;
alter table public.reports enable row level security;
