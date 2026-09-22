# Safe DB Gateway — Phase 2 Hardening Plan
## (Security Report Parts 3 High + Part 6 Scaling)

All 3 Critical findings are **closed and verified** (13/13 tests passing).
This plan addresses what remains: the **HIGH** finding, 5 remaining **roadmap items (4–9)**,
and the **5 Part 6 scaling gaps**.

---

## Status of Previous Work

| Finding | Status |
|---|---|
| Critical #1 — Scalar function bypass (`pg_read_file`) | ✅ CLOSED — AST function allowlist |
| Critical #2 — PII masking bypassed by `split_part` | ✅ CLOSED — security-barrier view |
| Critical #3 — Superuser connection | ✅ CLOSED — `agent_ro` / `agent_rw` roles |

---

## What Remains — Grouped by Impact

### Group A — Security Hardening (Report Items 4–6, Part 3 HIGH)

**These are real security gaps, implement first.**

| Item | Source | Severity | Effort |
|---|---|---|---|
| A1: `pg_hba.conf` trust auth → password auth | Report Part 3 HIGH / Roadmap #4 | 🟠 HIGH | Low |
| A2: HMAC-signed proposal tokens + short TTL | Roadmap #5 | 🟡 Medium | Medium |
| A3: Durable audit log (JSON, append-only) | Roadmap #6, Report 6.4 | 🟡 Medium | Medium |

---

### Group B — Scaling & Reliability (Report Part 6)

**Not security logic bugs — architecture gaps that break under load or multi-user.**

| Item | Source | Severity | Effort |
|---|---|---|---|
| B1: Durable session identity (in-memory CB → Postgres table) | Report 6.1 | 🟠 HIGH | Medium |
| B2: Connection pooling (per-query connect → pool) | Report 6.2 | 🟠 HIGH | Low |
| B3: Row-Level Security (RLS) for multi-tenant isolation | Report 6.3 | 🟡 Medium | Medium |
| B4: SIEM-ready structured alerting | Report 6.4 | 🟡 Low now | Low |
| B5: Transport: stdio → HTTP/SSE readiness checklist | Report 6.5 | 🟡 Future | Low (docs) |

---

## Open Questions

> [!IMPORTANT]
> **B1 (Durable CB): SQLite vs Postgres table?**
> A Postgres audit/state table is the simplest durable option that needs zero new dependencies.
> Redis would be faster for high throughput but adds a deployment dependency.
> **Recommendation:** Postgres table (same Docker container, zero new infra).

> [!IMPORTANT]
> **A1 (pg_hba.conf trust → scram-sha-256): Is the Docker PostgreSQL instance modifiable?**
> This requires editing `pg_hba.conf` inside the Docker container and reloading Postgres.
> If the container is ephemeral (recreated from `docker run`), we add this to `setup_roles.py`
> via a Postgres `pg_reload_conf()` call (superuser-only, done once during provisioning).

> [!NOTE]
> **B3 (RLS) only matters if more than one tenant/user shares tables.**
> For a single-owner Chinook demo, RLS adds no protection today but is zero-cost to enable
> and mandatory for any future multi-tenant use. Plan: enable + policy, but don't block on it.

---

## Proposed Changes — Ordered by Group

---

### Group A: Security Hardening

---

#### A1 — `pg_hba.conf` Trust Auth Fix

**Problem:** Any local process can authenticate as any Postgres user with no password.
This is independent of the MCP layer — it's a Postgres config issue.

##### [MODIFY] [`scripts/setup_roles.py`](file:///c:/DB_MCP/scripts/setup_roles.py)
Add a provisioning step that uses `ALTER SYSTEM` + `pg_reload_conf()` to switch
local connections from `trust` to `scram-sha-256`.

```sql
ALTER SYSTEM SET hba_file = '...';  -- Not portable
-- Instead: directly execute:
SELECT pg_reload_conf();
```

> [!WARNING]
> `pg_hba.conf` cannot be modified via SQL — it's a filesystem file.
> The practical fix: document this as a **Docker run flag** to the user.
> In `setup_roles.py`, add a check that validates the current auth method and
> prints a warning + exact fix command if `trust` is detected.
> The actual fix instruction: edit `pg_hba.conf` to replace `trust` → `scram-sha-256`
> for all local/127.0.0.1 entries.

**Deliverable:** `setup_roles.py` gains a Step 5 that detects trust auth and prints
the exact `pg_hba.conf` lines to change and the `docker exec` command to run.

---

#### A2 — HMAC-Signed Proposal Tokens with TTL

**Problem:** Current tokens are UUIDs stored in a plain in-memory dict.
They're unforgeable externally but have no expiry (a token proposed 3 hours ago
is still valid) and no tamper-evidence (someone with memory access could forge state).

##### [MODIFY] [`src/db_mcp/server.py`](file:///c:/DB_MCP/src/db_mcp/server.py)

Replace `str(uuid.uuid4())` token generation with an HMAC-SHA256 signed token:

```python
import hmac, hashlib, time, secrets

TOKEN_SECRET = secrets.token_hex(32)  # Generated at startup, not from .env
TOKEN_TTL_SECONDS = 300  # 5 minutes

def _make_token(mutation_id: str) -> str:
    ts = int(time.time())
    payload = f"{mutation_id}:{ts}"
    sig = hmac.new(TOKEN_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()
    return f"{payload}:{sig}"

def _verify_token(token: str) -> bool:
    try:
        mutation_id, ts_str, sig = token.rsplit(":", 2)
        ts = int(ts_str)
        if time.time() - ts > TOKEN_TTL_SECONDS:
            return False  # Expired
        expected = hmac.new(TOKEN_SECRET.encode(),
                            f"{mutation_id}:{ts}".encode(),
                            hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False
```

Token store (`_pending_mutations`) is still used for single-use invalidation,
but the token itself is now self-verifying and time-bounded.

---

#### A3 — Append-Only Structured Audit Log

**Problem:** No record of what queries ran, what was blocked, or who triggered quarantine.
Without this, there is no way to investigate incidents or demonstrate SOC2 compliance.

##### [NEW] [`src/db_mcp/audit.py`](file:///c:/DB_MCP/src/db_mcp/audit.py)

A minimal, zero-dependency audit logger:

```python
# audit.py — append-only JSON lines, one event per line
import json, time, hashlib
from pathlib import Path

AUDIT_LOG = Path("audit.log")

def log_event(event_type: str, **fields):
    entry = {"ts": time.time(), "type": event_type, **fields}
    line = json.dumps(entry, default=str)
    with open(AUDIT_LOG, "a") as f:
        f.write(line + "\n")
```

Events to log:
- `QUERY_ACCEPTED` — session_id, safe_sql, tables_accessed, row_count, exec_ms
- `QUERY_REJECTED` — session_id, raw_input, rejection_reason, stage (AST/CB/DB)
- `MUTATION_PROPOSED` — session_id, proposal_token, safe_sql
- `MUTATION_APPLIED` — session_id, proposal_token, operator (redacted), row_count
- `MUTATION_REJECTED` — session_id, reason (bad key / expired token)
- `CIRCUIT_BREAKER_TRIP` — session_id, violation_count, quarantine_until
- `SESSION_QUARANTINED_HIT` — session_id (every blocked query during quarantine)

##### [MODIFY] [`src/db_mcp/server.py`](file:///c:/DB_MCP/src/db_mcp/server.py)
Import `audit.log_event` and call at every exit point of `safe_query`,
`propose_mutation`, `apply_mutation`.

##### [NEW] `get_audit_summary` MCP tool
A read-only tool that returns the last N events from `audit.log`,
so the operator can ask the agent "what happened in the last 10 minutes"
without opening files manually.

---

### Group B: Scaling & Reliability

---

#### B1 — Durable Circuit Breaker State (Postgres Table)

**Problem:** All CB violation counts and quarantine state live in Python `dict` in memory.
A reconnect or process restart resets everything — the 3-strikes protection is bypassed
by simply disconnecting and reconnecting.

##### [MODIFY] [`scripts/setup_roles.py`](file:///c:/DB_MCP/scripts/setup_roles.py)
Add a Step 6 that creates the state table using the `postgres` superuser connection
(before switching to `agent_ro`):

```sql
CREATE TABLE IF NOT EXISTS gateway_session_state (
    session_id   TEXT PRIMARY KEY,
    violations   INT NOT NULL DEFAULT 0,
    quarantine_until TIMESTAMPTZ,
    query_count  INT NOT NULL DEFAULT 0,
    compute_ms   BIGINT NOT NULL DEFAULT 0,
    last_seen    TIMESTAMPTZ DEFAULT NOW()
);
-- agent_ro can read its own row; only gateway can write
GRANT SELECT, INSERT, UPDATE ON gateway_session_state TO agent_ro;
```

##### [MODIFY] [`src/db_mcp/guardrails/circuit_breaker.py`](file:///c:/DB_MCP/src/db_mcp/guardrails/circuit_breaker.py)
Replace in-memory dicts with a thin DB-backed wrapper.
Keep in-memory as an L1 cache to avoid adding a DB round-trip to every query:

```
check_session() → L1 cache hit? → return cached result
               → cache miss or stale → SELECT FROM gateway_session_state → update L1
record_violation() → UPDATE gateway_session_state SET violations += 1 ...
                   → also update L1 cache
```

The Postgres table is the source of truth. The in-memory dict is a 30-second TTL cache.

---

#### B2 — Connection Pooling

**Problem:** Every `safe_query` call opens a new TCP connection + Postgres auth handshake.
Under any concurrency (multiple agents or rapid sequential calls), this exhausts
`max_connections` and creates measurable latency.

##### [MODIFY] [`src/db_mcp/database.py`](file:///c:/DB_MCP/src/db_mcp/database.py)
Replace direct `psycopg2.connect()` per-call with a `psycopg2.pool.ThreadedConnectionPool`:

```python
from psycopg2 import pool

_RO_POOL = pool.ThreadedConnectionPool(
    minconn=1, maxconn=5,   # 5 is the ceiling — never exhaust max_connections
    dsn=RO_DSN
)

def get_ro_connection():
    return _RO_POOL.getconn()

def release_connection(conn):
    _RO_POOL.putconn(conn)
```

Use `contextlib.contextmanager` so every call site gets `with get_ro_connection() as conn:`
and the pool automatically reclaims connections on exit/exception.

---

#### B3 — Row-Level Security (RLS)

**Problem:** Access control is table-scoped only. If multiple tenants ever share tables,
there is no row-level isolation at the database layer.

> [!NOTE]
> Chinook is a single-tenant demo, so RLS adds no functional change today.
> This is a zero-regression preparation step: enable RLS, add a policy that
> passes all rows when `app.current_tenant` is not set (preserving existing behavior),
> and document the hook for future multi-tenant use.

##### [MODIFY] [`scripts/setup_roles.py`](file:///c:/DB_MCP/scripts/setup_roles.py)
```sql
ALTER TABLE customer ENABLE ROW LEVEL SECURITY;
-- Default-open policy: all rows visible when no tenant context set (single-tenant mode)
CREATE POLICY rls_passthrough ON customer
  USING (
    current_setting('app.current_tenant', true) IS NULL
    OR tenant_id::text = current_setting('app.current_tenant', true)
  );
```

##### [MODIFY] [`src/db_mcp/database.py`](file:///c:/DB_MCP/src/db_mcp/database.py)
Add a `set_session_context(conn, caller_id)` helper that issues
`SET LOCAL app.current_tenant = '...'` at the start of each transaction.

---

#### B4 — Structured Alerting (SIEM-Ready)

**Problem:** Even with an audit log, there's no signal when something bad happens.
An operator has to manually grep the log file to discover a quarantine event.

This is a **low-effort add-on to A3** (the audit log):

##### [MODIFY] [`src/db_mcp/audit.py`](file:///c:/DB_MCP/src/db_mcp/audit.py)
Add a `ALERT_THRESHOLD` dict. When `log_event` is called with a high-severity type,
also print a structured `ALERT:` line to stderr:

```python
ALERT_EVENTS = {"CIRCUIT_BREAKER_TRIP", "MUTATION_REJECTED", "QUERY_REJECTED"}

def log_event(event_type, **fields):
    entry = {...}
    # Write to audit.log
    ...
    # Also alert to stderr for SIEM ingestion
    if event_type in ALERT_EVENTS:
        print(f"ALERT [{event_type}] {json.dumps(fields)}", file=sys.stderr)
```

Operators running this in Docker/systemd can redirect stderr to Datadog/CloudWatch/Splunk
with zero additional code in the gateway itself.

---

#### B5 — Transport Readiness Documentation

**Problem:** Moving from stdio to HTTP/SSE changes the threat model substantially.
There is no checklist today for what must be verified before making that move.

##### [NEW] `docs/transport_migration_checklist.md`
A short document listing:
- TLS requirement (cert provisioning, no self-signed in prod)
- Per-request bearer token auth (JWT or mTLS) wired into RLS `SET LOCAL` context
- Client-disconnect → orphaned transaction handling (server-side statement timeout already exists)
- Load balancer sticky sessions (CB state in B1 removes this requirement)
- Health endpoint for load balancer probes (already: `get_gateway_health`)

---

## Implementation Order

```
A1 (pg_hba.conf detection)  ←── easiest, one function in setup_roles.py
A2 (HMAC tokens)            ←── self-contained, only touches server.py
A3 (Audit log)              ←── foundational; B4 builds on it
B2 (Connection pool)        ←── high leverage, low risk, ~20 lines
B1 (Durable CB)             ←── depends on setup_roles.py schema step
B3 (RLS)                    ←── depends on setup_roles.py
B4 (Alerting)               ←── depends on A3 (audit.py)
B5 (Transport docs)         ←── no code, last
```

**Estimated total:** ~350–400 lines of new/modified code across 5 files + 1 new doc.

---

## Verification Plan

### Automated Tests (extend `test_chinook_gateway.py`)
- **A1:** `setup_roles.py` output includes trust-auth warning when `trust` is detected
- **A2:** Token with expired TTL is rejected; forged-signature token is rejected
- **A3:** After 3 queries, `audit.log` contains 3 `QUERY_ACCEPTED` entries in JSON lines format
- **B1:** Kill and restart gateway process; verify quarantine state survives (Postgres table)
- **B2:** Connection pool is reused (verify via `pg_stat_activity` row count stays ≤ 5)
- **B3:** RLS passthrough: existing queries still return all rows in single-tenant mode

### Manual Verification
- Confirm `audit.log` is human-readable and a SIEM tool can ingest JSON lines format
- Confirm `get_audit_summary` MCP tool returns last N events correctly
