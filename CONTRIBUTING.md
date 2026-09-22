# Contributing

## Setup

```powershell
pip install -r requirements.txt
python setup.py init --demo
python setup.py up
```

## Tests

```powershell
$env:PYTHONPATH='C:\DB_MCP'   # or export PYTHONPATH=/path/to/repo
python tests/test_chinook_gateway.py   # 28 end-to-end tests, needs live Postgres
python -m unittest discover -s tests
```

The end-to-end suite must stay green. If you change enforcement behavior
(guardrails, roles, quarantine, masking, audit), update or extend the suite
in the same commit.

## Ground rules

- No secrets in code, configs, or tests — placeholders only (see `.env.example`).
- Access control changes must hold at **both** layers: tool gating in
  `src/db_mcp/server.py` and grants in `scripts/setup_roles.py`.
- New dependencies need a stated reason — this project stays lean on purpose.
- Keep the README minimal: tables over prose.
