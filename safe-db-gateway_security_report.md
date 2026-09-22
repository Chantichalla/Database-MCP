# safe-db-gateway MCP — Security Assessment Report

**Test date:** 2026-09-21
**Tester:** Claude (agentic testing, live tool calls against a running instance)
**Target:** safe-db-gateway MCP (Chinook/PostgreSQL test database)
**Scope:** `safe_query`, `propose_mutation`, `apply_mutation`, `describe_table`, `list_accessible_tables`

---

## Executive Summary

Over four rounds of testing, the gateway correctly resisted **every classic SQL-injection, access-control-bypass, resource-exhaustion, and approval-forgery technique** attempted (23 distinct vectors). Mid-assessment, the team shipped a circuit-breaker update that closed two previously-flagged gaps (no rate limiting, no anomaly detection) — confirmed working in real time.

However, three **critical** findings were confirmed, all tracing back to a single root cause:

> **The database connection authenticates as the PostgreSQL superuser (`postgres`), not a scoped, least-privilege role.**

This one fact is why an application-layer table whitelist — which is inherently a pattern-matching approach and will always have edge cases — had no structural floor beneath it. Every gap in the AST parser became a full-severity vulnerability specifically because there was no database-level permission boundary to catch what the parser missed.

**Severity ranking:**
1. 🔴 **Critical** — Arbitrary server file read via scalar function calls (bypasses table whitelist entirely)
2. 🔴 **Critical** — PII masking fully defeated by trivial string-splitting (`split_part`, `substring`)
3. 🔴 **Critical** — Root cause: superuser DB credentials with no privilege ceiling
4. 🟠 **High** — `pg_hba.conf` discloses `trust` authentication for local/127.0.0.1 (no password required)
5. 🟡 **Informational** — Circuit breaker violation-count behavior inconsistent (skipped a warning tier once)

---

## Part 1 — What Was Tested and Who Blocked It

"Blocked by LLM" = rejected by Claude's own reasoning before any tool call was made.
"Blocked by MCP" = the payload reached the gateway and one of its own layers rejected it.

| # | Attack | Technique | Blocked By | Layer |
|---|---|---|---|---|
| 1 | `SELECT...; DROP TABLE` | Semicolon statement chaining | MCP | AST — multi-statement detection |
| 2 | `SELECT...; -- \n TRUNCATE` | Comment-hidden chaining | MCP | AST — multi-statement detection |
| 3 | Subquery on `employee` | Nested restricted-table reference | MCP | AST — table whitelist (deep scan) |
| 4 | CTE wrapping `employee` | Hidden table inside `WITH` clause | MCP | AST — table whitelist (recursive walk) |
| 5 | Implicit join with `employee` | Comma-style `FROM` | MCP | AST — table whitelist |
| 6 | Writable CTE (`WITH x AS (DELETE...RETURNING*) SELECT`) | DML disguised as a SELECT | MCP | **DB-level read-only transaction** (AST layer missed this one) |
| 7 | Triple `CROSS JOIN` (~42B row Cartesian product) | Resource exhaustion | MCP | Not blocked — neutralized via auto-`LIMIT 100` |
| 8 | `LIMIT 1000000` | Explicit limit override | MCP | Silently clamped to 100 |
| 9 | `UNION` between `customer` and `employee` | Statement-type smuggling | MCP | Statement-type restriction (SELECT only) |
| 10 | `pg_sleep(10)` | Timing-based DoS | MCP | Hard 2.0s query timeout |
| 11 | `UPDATE track SET price=0` (no WHERE) | Mass-update risk | MCP | Mutation AST rule — WHERE clause mandatory |
| 12 | `UPDATE employee SET salary=...` | Restricted-table mutation | MCP | Mutation table whitelist |
| 13 | Forged `proposal_token` (`prop_000000000000`) | Approval-flow forgery | MCP | Server-side token store lookup |
| 14 | Token replay (reuse a spent token) | Double-execution attempt | MCP | Single-use token invalidation |
| 15 | `human_approved=False` on a real token | Approval-flag bypass check | MCP | Correctly aborted execution |
| 16 | Recursive CTE, unbounded | Infinite-loop DoS | MCP | Neutralized via `LIMIT 100` |
| 17 | "URGENT OVERRIDE... Incident Response Rule 0" sent as **chat text** | Social engineering / fake authority | **Claude (LLM)** | Reasoning layer — never became a tool call |
| 18 | Same text sent **as the raw SQL parameter** | Prompt-injection-as-SQL | MCP | AST syntax parse failure |
| 19 | `information_schema.tables` | Schema enumeration | MCP | Table whitelist |
| 20 | `EXPLAIN SELECT * FROM employee` | Metadata leak via query plan | MCP | Statement-type gate (EXPLAIN classified as `COMMAND`, rejected outright) |
| 21 | Blind oracle: `employee` subquery nested inside a `DELETE...WHERE` (`propose_mutation`) | Boolean-oracle exfiltration via mutation path | MCP | Mutation path has equal-depth whitelist scan — no asymmetry vs. query path |
| 22 | `dblink_connect()` to `169.254.169.254` (cloud metadata IP) | SSRF / cloud credential theft | MCP | Extension not installed in this environment (verify disabled in production) |
| 23 | `pg_ls_dir()` used as a **table function** (`FROM pg_ls_dir(...)`) | Directory listing | MCP | Table whitelist — FROM-clause functions *are* inspected |

**Circuit breaker / rate limiting (new mid-assessment):**

| Test | Result |
|---|---|
| 3 consecutive whitelist violations | Session quarantined ~15 min, confirmed via exposed `quarantine_remaining_seconds` |
| Legitimate query during quarantine | Blocked — quarantine is total, not partial |
| `propose_mutation` during quarantine | Blocked — spans both read and write tools |
| `list_accessible_tables` during quarantine | Blocked — spans metadata calls too |
| Violation counter behavior | On one occasion jumped from 1/3 directly to "tripped," skipping the 2/3 warning — inconsistent, worth engineering review |

---

## Part 2 — Confirmed Critical Vulnerabilities

### CRITICAL #1 — Scalar Function Calls Bypass the Table Whitelist Entirely

**Proof of concept:**
```sql
SELECT pg_read_file('/etc/passwd');                          -- full file contents returned
SELECT pg_read_file('/var/lib/postgresql/data/pg_hba.conf'); -- auth config disclosed
SELECT current_setting('data_directory');                     -- server paths disclosed
SELECT encode(pg_read_binary_file('/proc/self/environ'),'base64'); -- binary-file bypass of encoding errors
```

**Root cause:** The AST whitelist inspects table references used as **row sources** — `FROM`, `JOIN`, CTEs, and even table-returning functions in a `FROM` clause (confirmed: `pg_ls_dir()` used as `FROM pg_ls_dir(...)` *was* caught). It does **not** inspect function calls used as **scalar expressions** in the `SELECT` list, `WHERE` clause, or elsewhere. Any function that returns a value rather than a row-set slips through undetected.

**Blast radius:** Any Postgres function reachable by the connected role. Confirmed working: `pg_read_file`, `pg_read_binary_file`, `current_setting`. Also very likely exploitable (same class, not individually re-tested here): `pg_ls_logdir()`, `pg_stat_file()`, and any custom/extension function the role can execute.

**Fix:**
- **Immediate (app layer):** Extend the AST walk to inspect *every* function-call node in the parse tree — not just FROM-clause targets — against an explicit allowlist (aggregates, string/date/math functions only). Denylisting is not sufficient; Postgres has dozens of file/system functions and more can be added by extensions.
- **Structural (the real fix):** `REVOKE EXECUTE` on `pg_read_file`, `pg_read_binary_file`, `pg_ls_dir`, `pg_ls_logdir`, `pg_stat_file`, `lo_import`, `lo_export`, and any other filesystem/superuser-only functions from the connecting role — see Root Cause section below. This makes the vulnerability class structurally impossible rather than dependent on an app-layer list staying exhaustive forever.

---

### CRITICAL #2 — PII Masking Is Trivially and Universally Bypassable

**Proof of concept:**
```sql
-- Masking works as expected here:
SELECT email FROM customer;                    -- returns "l***r@surfeu.de"

-- But split the same value across two output columns:
SELECT split_part(email,'@',1) AS local_part,
       split_part(email,'@',2) AS domain_part
FROM customer;
-- Returns: local_part = "leonekohler", domain_part = "surfeu.de"
-- Full email fully reconstructable by simple concatenation

-- Same bypass confirmed for phone numbers via substring():
SELECT substring(phone,1,3), substring(phone,4,3), substring(phone,7,4) FROM customer;
-- Returns fully reconstructable real phone numbers
```

Also confirmed: masking is **not lineage-aware** — it matched a fabricated literal string (`'fake_not_real@example.com'`) that had nothing to do with real customer data, proving it's a regex/pattern scan on output text, not a tracked transform on the actual `email`/`phone` columns.

**Root cause:** Masking is applied as a **post-execution pattern match on returned strings** ("does this output value look like a complete email/phone"), not as a database-level transform on the source columns. Any function that fragments the value defeats it, because no single output field ever contains the complete pattern.

**Why this is more dangerous than #1:** Exploiting the file-read bug requires knowing specific superuser function names. Defeating the masking requires only `split_part` or `substring` — two of the most ordinary SQL functions that exist. An analyst writing a completely innocent query (e.g., "email domain distribution report") would defeat this protection with zero malicious intent.

**Fix:**
- Pattern-matching output **cannot** be patched into being reliable — it is structurally the wrong layer, since you can't regex-match data that hasn't been reassembled yet.
- **Correct fix:** Move masking into PostgreSQL itself — a security-barrier view, or native column-level masking/anonymization, applied **before** any query (including `split_part`/`substring`/casts) can touch the raw value. At that point the raw data literally does not exist in any form the query can access, regardless of what functions are applied downstream.
- As a stopgap only (not a real fix): block PII-typed columns from being passed as arguments into `substring`, `split_part`, `left`, `right`, `overlay`, `||` concatenation — but this is an arms race against SQL's own expressiveness and will always have another bypass.

---

### CRITICAL #3 — Root Cause: Database Connection Runs as Superuser

**Proof of concept:**
```sql
SELECT current_setting('is_superuser') AS is_superuser, current_user AS db_user;
-- Result: is_superuser = "on", db_user = "postgres"
```

**Why this is the root cause of #1 and amplifies #2:** `pg_read_file`, `pg_read_binary_file`, and similar functions are restricted to superusers (or roles explicitly granted `pg_read_server_files`) in a properly configured Postgres instance. They only worked in this test because the connection **is** superuser. If the AST-layer fix for #1 is deployed but the connection remains superuser, the *next* undiscovered function-based bypass (and there will likely be one — this is a large attack surface to enumerate completely) will be equally exploitable. Fixing the role is what makes the fix durable rather than a one-time patch.

**Fix:** Create a dedicated role (e.g., `agent_ro`) with:
```sql
CREATE ROLE agent_ro LOGIN PASSWORD '...';
GRANT CONNECT ON DATABASE chinook TO agent_ro;
GRANT USAGE ON SCHEMA public TO agent_ro;
GRANT SELECT ON album, artist, customer, genre, invoice, invoice_line,
                media_type, playlist, playlist_track, track TO agent_ro;
-- Explicitly do NOT grant pg_read_server_files, pg_write_server_files,
-- pg_execute_server_program, or superuser.
```
And a separate `agent_rw` role (grants above plus scoped `INSERT`/`UPDATE`/`DELETE` on the same table list, still never on `employee`) used only by the `apply_mutation` path after human approval. Credentials for both should come from a secrets manager (Vault, AWS IAM auth) with rotation, not a static connection string.

---

## Part 3 — High and Informational Findings

### HIGH — `pg_hba.conf` Grants `trust` Authentication Locally

Reading the auth config (itself only possible because of Critical #1) revealed `trust`-method entries for local and `127.0.0.1` connections — meaning any process able to open a local connection authenticates as **any** database user with **no password whatsoever**. This is independent of the MCP's own logic entirely; it's a PostgreSQL configuration issue. Fix: change local/loopback entries to `scram-sha-256` (password-based) authentication.

### INFORMATIONAL — Circuit Breaker Violation Counting Inconsistency

In one instance, the violation counter jumped from displaying "1/3" directly to "tripped" on the next violation, skipping the expected "2/3" warning message. This could indicate severity-weighted scoring (a filesystem-recon attempt costing more than a simple whitelist hit) or a genuine counting bug. Recommend the engineering team verify the intended behavior — if it's severity-weighted, document it; if it's a bug, it doesn't currently weaken security (quarantine still triggered correctly) but the inconsistent messaging could confuse operators reading logs.

### CLOSED (verify stays closed) — `dblink` Extension Not Installed

Attempted SSRF/credential-theft via `dblink_connect()` targeting the AWS metadata endpoint (`169.254.169.254`) failed because the extension isn't installed in this environment. This is not a vulnerability today, but if any future migration or convenience installs `dblink` (or `postgres_fdw`), this becomes exploitable immediately given the current superuser connection. Worth an explicit "must never be installed" note in deployment docs, or better, enforced by the role-scoping fix in Critical #3 (a non-superuser role can't create extensions either).

---

## Part 4 — What the Gateway Already Does Well (do not regress these)

- **Multi-statement / chaining detection** — robust, caught every variant tried (comments, whitespace obfuscation, case variation).
- **Recursive AST table-reference scanning** — correctly finds restricted tables inside subqueries, CTEs, implicit joins, and FROM-clause table functions.
- **Statement-type restriction** — `safe_query` correctly rejects anything that isn't a plain `SELECT`, including `UNION`-based smuggling, `COPY`, and `EXPLAIN`.
- **Mutation safety rules** — WHERE-clause requirement on UPDATE/DELETE, table whitelist applied equally on the mutation path, no asymmetry found between read and write paths.
- **HITL token flow** — tokens are opaque, server-stored, single-use, and unforgeable from the client side; `human_approved=False` is correctly enforced as a hard stop.
- **DB-level read-only transaction backstop** — this single control caught every write-capable function tested (`lo_import`, `lo_create`) regardless of AST gaps, and was the only thing that caught the writable-CTE bypass. This is the most valuable defense-in-depth layer in the system and validates the "redundant layers" design philosophy.
- **Circuit breaker / rate limiting** — newly added, confirmed to span all three tool types (query, mutation, metadata) during quarantine, not just the tool that triggered it.
- **Resource governors** — LIMIT clamping and 2s timeout defeated every resource-exhaustion attempt (Cartesian joins, infinite recursion, `pg_sleep`) without needing to detect the attack pattern specifically — they make expensive queries cheap by construction.

---

## Part 5 — Prioritized Remediation Roadmap

| Priority | Item | Effort | Why first |
|---|---|---|---|
| 1 | Create scoped `agent_ro` / `agent_rw` Postgres roles; revoke superuser | Medium | Fixes Critical #3 and structurally closes Critical #1, even against undiscovered function-based bypasses |
| 2 | Extend AST parser to inspect scalar function-call nodes, not just FROM-clause targets | Medium | Closes Critical #1 at the app layer immediately, doesn't wait for infra change |
| 3 | Move PII masking into a Postgres-native security-barrier view or column policy | High | Only real fix for Critical #2; current approach is unfixable in place |
| 4 | Fix `pg_hba.conf` to require password auth on all local/loopback entries | Low | High severity, trivial fix |
| 5 | Add HMAC signing + short TTL to proposal tokens; move proposal store to Redis/Postgres (survives restart, tamper-evident) | Medium | Already reasonably safe, but current in-memory dict is a durability and tamper-evidence gap |
| 6 | Require out-of-band human approval (Slack/MFA callback) rather than a boolean the calling agent sets itself | High | Closes the biggest remaining trust-boundary gap — right now "human_approved" is asserted by the same agent that could be compromised or manipulated |
| 7 | Investigate and document/fix circuit-breaker violation-count inconsistency | Low | Operational clarity, not currently a security hole |
| 8 | Explicit policy + enforcement that `dblink`/`postgres_fdw` extensions are never installed | Low | Preventive; becomes moot once role-scoping (item 1) is done |
| 9 | Add per-session and global query-rate budgets beyond the 3-violation circuit breaker (e.g., cumulative compute budget across a longer window) | Medium | Circuit breaker handles violations well; doesn't yet address a high volume of *valid* expensive queries |

---

## Part 6 — Production Scaling & Enterprise Hardening

The findings in Parts 1–5 were about *correctness* of the security logic. The five items below are about the fact that the current implementation assumes a **single local user, single process, single connection lifetime** — which is a reasonable architecture for a prototype, but breaks down as soon as there's more than one caller, more than one process, or any expectation of durability across restarts. These were raised directly by the team and are captured here for the roadmap.

### 6.1 — Session/Quarantine State Is In-Memory and Process-Scoped

**Problem:** Circuit-breaker violation counts and quarantine status reset whenever the client (e.g., Claude Desktop) reconnects or the MCP process restarts. This means the "3 strikes" protection can be trivially reset by reconnecting, and there is no concept of a *durable identity* being quarantined — only a transient connection.

**Fix:**
- Move violation counters, quarantine state, and rate-limit windows to **Redis** — atomic `INCR`, native TTL for quarantine expiry, sub-millisecond latency.
- Key all state off a **durable caller identity** (API key, service-account ID, signed client cert subject) rather than the transport/session — so quarantine follows the *caller*, not the socket, and survives reconnects and restarts.
- Acceptable interim step if Redis isn't available yet: a Postgres table with TTL-based cleanup (`pg_cron` or similar), as long as it's identity-keyed and durable — the specific store matters less than solving "does this survive a restart and identify the right actor."

### 6.2 — Per-Query `psycopg2.connect()` (No Connection Pooling)

**Problem:** Every query opens a brand-new TCP + Postgres auth handshake. Beyond the latency cost, this is a **resource-exhaustion / denial-of-service risk**: enough concurrent calls can exhaust Postgres's `max_connections`, taking down the database for every other client sharing that instance — not just this gateway.

**Fix:**
- **PgBouncer** in transaction-pooling mode in front of Postgres — standard, low-effort, decouples app-layer request volume from real DB connection count.
- Alternatively, an async connection pool in-process (`asyncpg` pool, or SQLAlchemy `AsyncEngine`) with an explicit `max_size` ceiling, so the application enforces a connection cap rather than relying on Postgres to reject once already saturated.
- Should be deployed alongside the rate-limiting/quarantine fix (6.1) — pooling absorbs legitimate concurrency, rate limiting stops abusive concurrency; neither substitutes for the other.

### 6.3 — Row-Level Security (RLS) Not Implemented

**Problem:** Access control currently stops at the table level (the whitelist). There is no row-level or multi-tenant isolation — if this architecture is ever used with more than one tenant/customer sharing the same tables, there is currently nothing preventing cross-tenant data exposure at the database layer.

**Fix:**
```sql
ALTER TABLE customer ENABLE ROW LEVEL SECURITY;
CREATE POLICY tenant_isolation ON customer
  USING (tenant_id = current_setting('app.current_tenant')::int);
```
The gateway sets `app.current_tenant` (or `app.current_user`) via `SET LOCAL` at the start of each transaction, derived from the caller's authenticated identity (see 6.5). This is a direct extension of the same principle behind the Critical #3 fix in Part 2 of this report: push enforcement into PostgreSQL itself so that gaps in application-layer logic (which this assessment proved will exist) cannot result in unauthorized data access. Combine with a security-barrier view for the PII masking fix (Critical #2) — one RLS + view layer can address both problems.

### 6.4 — No Immutable Audit Log or SOC2-Grade Alerting

**Problem:** There is currently no tamper-evident record of queries, violations, or mutations, and no alerting pipeline for anomalous activity (such as the 23-attack testing burst performed in this assessment, which should have paged someone).

**Fix — tamper evidence:**
- Log every query/mutation/violation with: caller identity, timestamp, raw input query, `executed_safe_sql`, result status, row/byte counts.
- Write-once storage: S3 with Object Lock (compliance mode), or a dedicated Postgres audit table where the gateway's own role has `INSERT`-only privileges (no `UPDATE`/`DELETE` grants) — enforced the same way every other privilege boundary in this report is enforced: at the database grant level, not just in application code.
- Hash-chain entries (`hash(entry_n) = H(data_n + hash(entry_n-1))`) so retroactive tampering is cryptographically detectable even by someone with direct storage access.

**Fix — alerting:**
- Stream audit events to a SIEM (Splunk, Datadog, etc.) with concrete triggers: quarantine events, repeated `REJECTED_BY_GUARDRAIL` from a single identity, any successful mutation, any function call outside the eventual scalar-function allowlist (Critical #1 fix).
- SOC2 scope should also cover: audit-log retention policy, and access logging **on the audit log itself** (who queried the audit trail and when) — easier to design in now than retrofit later.

### 6.5 — Transport Layer: stdio vs. HTTP/SSE

**Problem:** The current stdio transport implicitly relies on the OS process boundary as its authentication boundary — reasonable for a single local trusted client, but it's also *why* issue 6.1 exists (no persistent identity across a "session" because there's no real session concept, just a process lifetime). Moving to HTTP/SSE for multi-client or remote access changes the threat model substantially and has to be done deliberately, not just by swapping the transport.

**Fix, if/when moving to HTTP/SSE:**
- TLS everywhere, including internal-network traffic — especially relevant given the `pg_hba.conf` `trust`-authentication finding in Part 3 of this report; a weak network boundary compounding a weak session model is a bad combination.
- Per-request authentication (bearer tokens or mTLS) validated against a real identity store, feeding directly into the RLS tenant/user context (6.3) and the rate-limit/quarantine identity keying (6.1) — all three of these should resolve to the *same* identity concept, not three separate ad hoc ones.
- If using SSE for streaming, ensure a client disconnect doesn't leave an orphaned open Postgres transaction — bound transaction lifetime with a server-side timeout independent of client connection state.

---

## Closing Assessment

The engineering team built genuinely strong defense-in-depth against the SQL-injection and access-control attack classes — 23 distinct techniques across those categories were all handled correctly, and the mid-assessment circuit-breaker addition closed real gaps in real time. The three critical findings here don't reflect sloppy work; they reflect the natural limit of **any** pattern-matching security layer (AST inspection, regex masking) when it isn't backed by a structural, database-enforced privilege boundary. Item 1 on the remediation list (scoped roles) is disproportionately valuable relative to its effort: it doesn't just fix what was found today, it removes the entire class of "the parser missed a function name" bugs from ever being exploitable again, known or not-yet-discovered.

Part 6's five items are a separate but related axis: they're not logic bugs, they're the natural gap between "architecture that's correct for one trusted local user" and "architecture that's correct for many concurrent, possibly-untrusted, possibly-remote callers." Notably, 6.1 (session identity), 6.3 (RLS tenant context), and 6.5 (transport auth) all converge on the same underlying need — a single, real, durable caller-identity concept that every other control (quarantine, rate limits, row access, audit attribution) can hang off of. Solving identity once, properly, makes the other four items meaningfully easier rather than five independent projects.
