# Safe Database Gateway MCP: Pragmatic Roadmap (`next_fix.md`)

This document is the definitive, de-cluttered roadmap for the **Safe Database Gateway MCP**. It separates the **must-implement essentials** from the **over-engineered noise** that should be avoided.

---

## Part 1: What to Implement (The Pragmatic 3-Phase Roadmap)

These are the high-impact, battle-tested changes that deliver 95% of enterprise-grade security without adding unnecessary complexity.

```
┌─────────────────────────────────────────────────────────────┐
│ PHASE 1: Database-Native Hardening (The #1 Priority)       │
│ • Dedicated unprivileged 'agent_reader' role in PostgreSQL │
│ • Revoke access to 'employee' at the engine level           │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ PHASE 2: Gateway Defense & Anti-Abuse (Python Layer)       │
│ • AST Blocker: Disallow DML in WITH / CTE clauses           │
│ • Security Circuit Breaker (Quarantine after 3 violations)  │
│ • Rate Limiting & Cumulative Compute Budget                 │
│ • Fix HITL: Stop letting LLM approve its own mutations      │
└──────────────────────────────┬──────────────────────────────┘
                               │
┌──────────────────────────────▼──────────────────────────────┐
│ PHASE 3: Audit & Observability                              │
│ • Structured JSON audit logging of all queries & rejections │
│ • Tool to view session audit summary                        │
└─────────────────────────────────────────────────────────────┘
```

---

### Phase 1: Database-Native Hardening (High Impact, Low Effort)

#### 1. Dedicated Least-Privilege PostgreSQL Role
* **The Problem:** We currently connect as the `postgres` superuser. If an attacker finds any flaw, they have full control over the database.
* **The Fix:** Create an unprivileged user inside PostgreSQL that only has `SELECT` access to business tables:
  ```sql
  -- Run once in Docker PostgreSQL:
  CREATE ROLE agent_reader WITH LOGIN PASSWORD 'agent_secret_pass';
  GRANT CONNECT ON DATABASE chinook TO agent_reader;
  GRANT USAGE ON SCHEMA public TO agent_reader;
  GRANT SELECT ON album, artist, customer, genre, invoice, invoice_line, media_type, playlist, playlist_track, track TO agent_reader;
  REVOKE ALL ON employee FROM agent_reader;
  ```
* **Why it matters:** Even if Python AST parsing completely fails, PostgreSQL itself will physically reject any attempt to read `employee` or write data.

---

### Phase 2: Gateway Defense & Anti-Abuse (Python Layer)

#### 2. AST Blocker for Writable CTEs
* **The Problem:** `WITH ... AS (DELETE FROM customer ...)` was caught by the database runtime fallback rather than static AST analysis.
* **The Fix:** In `ast_guard.py`, inspect all `exp.CTE` subqueries. If any CTE contains `INSERT`, `UPDATE`, or `DELETE`, reject it immediately before reaching the database:
  ```python
  for cte in stmt.find_all(exp.CTE):
      if not isinstance(cte.this, exp.Select):
          raise ASTGuardrailError("Writable CTEs containing DML are prohibited in read-only mode.")
  ```

#### 3. Security Violation Circuit Breaker
* **The Problem:** An attacker can fire 100 injection attempts in a row without penalty.
* **The Fix:** A lightweight sliding-window counter in Python:
  * If a session triggers **3 security rejections within 5 minutes**, quarantine the session for **15 minutes**.
  * Any subsequent query returns: `"GATEWAY_LOCKED: Too many security violations. Contact administrator."`

#### 4. Rate Limiter & Cumulative Compute Budget
* **The Problem:** The 2.0s timeout is per-query. A script running 300 queries at 1.9s each will exhaust the database.
* **The Fix:**
  * Cap query frequency to **30 queries per minute**.
  * Enforce a **cumulative compute budget**: Maximum **15.0 seconds of database execution time** per 10-minute session window.

#### 5. Close the HITL Self-Approval Loophole
* **The Problem:** Currently, the LLM can call `apply_mutation(token, human_approved=True)` itself without human involvement.
* **The Fix:** 
  * If this is a **read-only gateway**, simply remove `propose_mutation` and `apply_mutation` entirely (reducing attack surface to zero).
  * If mutations are required, verify an out-of-band secret or prompt the user interactively in the terminal `[y/N]` rather than accepting an unverified boolean from the agent.

---

### Phase 3: Audit & Observability

#### 6. Structured Local Audit Trail
* **The Problem:** No visibility into what queries ran, what was blocked, or who ran them.
* **The Fix:** Append every event (query, execution time, tables accessed, blocked status) to a local rotating JSON log file (`audit.log`):
  ```json
  {"timestamp": "2026-09-20T22:00:00Z", "query": "SELECT ...", "status": "BLOCKED", "reason": "AST_VIOLATION"}
  ```

---

## Part 2: What NOT to Implement (And Why It's Over-Engineered)

Do **not** waste time on these suggestions. Here is why each is unnecessary or counter-productive for an MCP server:

| Over-Engineered Idea | Why You Should Skip It |
| :--- | :--- |
| **1. ML / NLP PII Detection** *(Microsoft Presidio / spaCy / Comprehend)* | **Adds 500ms+ latency and 1.5GB of dependencies.** Relational SQL databases have structured, typed columns. Simple column names (`email`, `phone`) and regex are 1,000x faster, zero-memory, and 100% deterministic. |
| **2. Vector DB / RAG for Schema Discovery** *(Embeddings / ChromaDB)* | **Ridiculous overkill for small-to-medium databases.** Our Chinook DB has 10 tables. A well-formatted JSON catalog takes ~1,500 tokens—less than 1% of Claude's context window. Vector search adds retrieval hallucination risk for zero gain. |
| **3. Enterprise Secrets Managers** *(HashiCorp Vault / AWS IAM DB Auth)* | **Massive DevOps complexity.** Vault requires dynamic token exchange, renewer sidecars, and network bridges. Standard environment variables (`.env`) with a non-superuser account provide all the isolation an MCP server needs. |
| **4. Distributed Redis Token Storage** | **Unnecessary for single-instance MCP.** An MCP server runs locally as a single subprocess. Redis is only needed if you are load-balancing 10 container replicas behind a reverse proxy. |
| **5. Complex AST LIMIT Rewriting** | **Unnecessary static manipulation.** Instead of rewriting SQL AST strings using `sqlglot` to clamp limits, simply calling `cursor.fetchmany(100)` in Python caps rows at the database driver level without touching the SQL string. |

---

## The Clean Summary

If you want to make this gateway production-bulletproof today, you only need to do **4 practical tasks**:

1. **In PostgreSQL (Docker):** Run the script to create `agent_reader` without permissions on `employee`. Update `.env` to use `agent_reader`.
2. **In `ast_guard.py`:** Add the 5-line check blocking DML inside `WITH` expressions.
3. **In `executor.py`:** Add the 15-line violation counter that trips a 15-minute cooldown after 3 failed attacks.
4. **In `server.py`:** Add rate limiting and clean up the HITL mutation approval to prevent LLM self-approval.

Everything else is enterprise slide-deck bloat.
