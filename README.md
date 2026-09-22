# Safe DB Gateway

A security-hardened **MCP (Model Context Protocol) gateway** that lets AI agents query a PostgreSQL database without the ability to destroy it, leak it, or be tricked into either. Read-only by default, PII-masked at the view layer, rate-limited, quarantined on abuse — and writes only through human-approved, expiring, single-use tokens.

**The problem it solves:** giving an LLM a raw database connection is a loaded gun — hallucinated tables, leaked PII, prompt-injected `DROP`s. This gateway puts a policy-enforcing membrane between the agent and Postgres, with evidence (audit trail) for everything that happens.

## Defense in depth

| Layer | What it does |
|---|---|
| AST guardrail (`sqlglot`) | Blocks multi-statements, writable CTEs, dangerous functions (`pg_read_file`, …), non-whitelisted tables; clamps `LIMIT` to 100 |
| PII barrier | `customer_masked` security-barrier view masks email/phone *before* any SQL function sees the data (closes `split_part`/`substring` bypasses) |
| Least-privilege roles | Per-keycard Postgres roles (`gateway_reader`/`editor`/`admin`); raw `customer` + `employee` revoked where appropriate |
| Read-only sessions | Read path runs `readonly=True` — Postgres itself rejects writes even if a guardrail fails |
| Rate + compute limits | 30 queries/min, 15s compute budget per 10 min (`THROTTLED`, never a lockout, on reads) |
| Circuit breaker | 3 violations → 15-min write quarantine, persisted in Postgres so restarts can't bypass it |
| HITL mutations | Propose → human operator key → expiring (5-min) HMAC-signed single-use token → execute |
| Audit + alerting | Append-only JSON-lines `audit.log` + `ALERT [...]` stderr lines for SIEM ingestion |

## Access levels (keycards)

One `default_role` line in `roles.yaml` sets the whole deployment's access until restart. Forks edit YAML, never code.

| Role | Reads | Propose | Approve | Manage |
|---|---|---|---|---|
| `reader` | ✅ allowlisted tables, PII masked | ❌ | ❌ | ❌ |
| `editor` | ✅ | ✅ on listed tables | ❌ (proposer ≠ approver) | ❌ |
| `admin` | ✅ all business tables | ✅ | ✅ | ✅ (quarantine reset, audit) |

Rules that never bend, for any role: restricted tables stay blocked unless explicitly granted, and schema destruction (`DROP`/`ALTER`/…) is rejected by the AST layer. A missing or broken `roles.yaml` fails **closed** to `reader`.

## Quickstart (3 steps)

Prerequisites: Python 3.10+, Docker.

```powershell
python setup.py init --demo     # writes .env with fresh secrets
python setup.py up              # starts Postgres, provisions everything
```

Then paste the printed block from `mcp-servers.json` into your Claude Desktop config. That's it — `safe_query("SELECT * FROM track LIMIT 5")` should return masked Chinook rows.

Against your own database: `python setup.py init` (wizard) or set `DB_HOST/DB_PORT/DB_NAME/DB_SEED=empty` — table-specific steps degrade gracefully with `SKIP` messages.

## MCP tools

| Tool | Role | Description |
|---|---|---|
| `safe_query` | all | Validated read-only query, PII-masked, capped at 100 rows / 2s |
| `list_accessible_tables` | all | Allowlisted tables (prevents hallucinated names) |
| `describe_table` | all | Columns, types, primary keys |
| `propose_mutation` | editor, admin | Dry-run plan + expiring proposal token, executes nothing |
| `apply_mutation` | admin | Executes a proposal with the operator approval key |
| `get_gateway_health` | all | Health, circuit-breaker state, quotas |
| `get_audit_summary` | all | Last N audit events (never quarantined) |
| `reset_quarantine` | admin | Clear quarantine without restarting |

## Configuration

- `.env` — connection strings, generated secrets, `GATEWAY_ROLE`, thresholds. Never committed (see `.gitignore`). Server-side only.
- `roles.yaml` — role definitions and table grants. Your access policy lives here; the gateway only enforces it.
- `docker-compose.yml` — Postgres 16 (`scram-sha-256`, Chinook seed on first init).

## Security model (honest boundaries)

- **Threats closed and tested:** scalar-function file access, PII extraction via SQL functions, superuser runtime connections — see `safe-db-gateway_security_report.md` and the 22-test suite.
- **Current boundary is the machine:** over stdio there is no per-user auth — whoever holds `.env` and the MCP config holds the keycard in `GATEWAY_ROLE`. The `trust`-auth warning in provisioning (`setup_roles.py` step 5) must be resolved before any shared deployment.
- **Roadmap:** per-caller auth (API keys → OIDC), HTTP/SSE transport with TLS, per-request tenant RLS, forensic audit queries — see `docs/transport_migration_checklist.md`.

## Testing

```powershell
$env:PYTHONPATH='C:\DB_MCP'   # or export PYTHONPATH=/path/to/repo
python test_chinook_gateway.py   # 22 end-to-end tests against live Postgres
python -m unittest discover -s tests
```

Covers: injection/CTE/restricted-table rejections, PII masking incl. bypass attempts, HITL lifecycle, token expiry/forgery, durable quarantine + restart survival, read-survives-quarantine rescoping, role enforcement at tool *and* DB layers, fail-closed config, RLS passthrough, pool ceilings.

## Project structure

```
src/db_mcp/            gateway package (server, database pools, audit, config)
src/db_mcp/guardrails/ ast_guard, executor, circuit_breaker
scripts/setup_roles.py provisioning (views, roles, RLS, state table, keycards)
setup.py               init wizard + up orchestrator
roles.yaml             access-level definitions (the policy file you own)
docker-compose.yml     local Postgres stack
docs/                  transport migration checklist
tests/                 legacy SQLite unit suite
test_chinook_gateway.py  primary end-to-end suite (22 tests)
```

## Requirements

`pip install -r requirements.txt` — `sqlglot`, `pydantic`, `mcp`, `psycopg2-binary`, `python-dotenv`, `pyyaml`.
