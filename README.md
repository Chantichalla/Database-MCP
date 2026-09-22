# Safe DB Gateway

[![License: Apache-2.0](https://img.shields.io/badge/License-Apache--2.0-blue.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)](https://www.python.org/)
[![MCP](https://img.shields.io/badge/MCP-stdio-green.svg)](https://modelcontextprotocol.io/)

Secure MCP server for PostgreSQL. AI agents get read access with guardrails; writes require human approval.

## Quickstart

Prerequisites: Python 3.10+, Docker.

```powershell
pip install -r requirements.txt
python setup.py init --demo
python setup.py up
```

Paste the printed block from `mcp-servers.json` into Claude Desktop. Or install directly:

```powershell
pipx install git+https://github.com/Chantichalla/Database-MCP.git
safe-db-gateway
```

To use your own database: `python setup.py init` (wizard) or set `DB_HOST` / `DB_PORT` / `DB_NAME` with `DB_SEED=empty`.

## Tools

| Tool | Access | Description |
|---|---|---|
| `safe_query` | all | Validated read-only SQL. Max 100 rows, 2s timeout, PII masked |
| `list_accessible_tables` | all | Allowed tables with row estimates |
| `describe_table` | all | Columns, types, primary and foreign keys |
| `sample_rows` | all | Up to 3 masked sample rows |
| `propose_mutation` | editor, admin | Dry-run plan + expiring token. Executes nothing |
| `apply_mutation` | admin | Executes a proposal with the operator key |
| `get_gateway_health` | all | Health, quarantine state, quotas |
| `get_audit_summary` | all | Recent audit events |
| `reset_quarantine` | admin | Clear quarantine without restart |

## Access control

One line in `roles.yaml` sets the deployment's access level:

| Role | Reads | Propose | Approve | Manage |
|---|---|---|---|---|
| `reader` | ✅ | ❌ | ❌ | ❌ |
| `editor` | ✅ | ✅ | ❌ | ❌ |
| `admin` | ✅ | ✅ | ✅ | ✅ |

Enforced twice: at the tool layer and by dedicated Postgres roles. Invalid config fails closed to `reader`.

## Security

- SQL validated by AST (`sqlglot`): SELECT-only, table whitelist, dangerous functions blocked
- PII masked in a security-barrier view, before any SQL function sees the data
- 3 violations → 15-minute write quarantine (reads keep working, persisted across restarts)
- Writes need a human operator key plus a 5-minute single-use token
- Append-only audit log; credentials scrubbed from all logs and errors
- 28 end-to-end tests: `python tests/test_chinook_gateway.py`

## Configuration

| File | Purpose |
|---|---|
| `.env` | Connection strings, secrets, thresholds. Never committed |
| `roles.yaml` | Role definitions and table grants |
| `docker-compose.yml` | Local Postgres 16 stack with demo data |

## License

Apache-2.0. See [LICENSE](LICENSE).
