Implementation Plan: Production-Grade Database MCP Server
This implementation plan outlines the steps to upgrade the Database-MCP repository into an open-source, token-efficient, and secure Model Context Protocol (MCP) server for PostgreSQL databases.

Architecture Overview
┌────────────────────────────────────────────────────────────────────────┐
│                              MCP HOST                                  │
│                 (Cursor / Claude Desktop / OpenCode)                   │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                         stdio (JSON-RPC 2.0)
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                             DATABASE-MCP                               │
│                                                                        │
│   ┌────────────────────────────────────────────────────────────────┐   │
│   │ 1. Schema Discovery Layer                                      │   │
│   │    - list_tables (Lightweight table & row estimation)          │   │
│   │    - describe_table (Columns, types, constraints, foreign keys) │   │
│   │    - sample_rows (3 representative rows)                       │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│   ┌───────────────────────────────▼────────────────────────────────┐   │
│   │ 2. Guardrail Engine (sqlglot)                                  │   │
│   │    - SELECT-only statement validation                          │   │
│   │    - DDL / DML mutation blocking (DROP, DELETE, UPDATE, ALTER) │   │
│   │    - Automatic LIMIT 100 injection                             │   │
│   └───────────────────────────────┬────────────────────────────────┘   │
│                                   │                                    │
│   ┌───────────────────────────────▼────────────────────────────────┐   │
│   │ 3. Bounded Execution Engine (AsyncPG)                          │   │
│   │    - Read-only transaction enforcement                         │   │
│   │    - 3-second statement execution timeout                      │   │
│   └────────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────────┘
                                    │
                      AsyncPG (Connection Pool)
                                    │
┌───────────────────────────────────▼────────────────────────────────────┐
│                         TARGET POSTGRES DB                             │
└────────────────────────────────────────────────────────────────────────┘
User Review Required
[!IMPORTANT]
Key Architectural Decisions

Default Row Capping: Automatic injection of LIMIT 100 on queries that do not explicitly declare a limit.

Execution Timeout: Hard execution timeout set to 3000ms (3 seconds) per query at the database session level.

Package Manager: pyproject.toml configuration structured for uv / uvx distribution.

Proposed Changes
1. Project Restructuring & Packaging
Reorganize the repository into a standard, packageable Python project layout.

[NEW] pyproject.toml
Define project metadata, dependencies (fastmcp, sqlglot, asyncpg, pydantic-settings).

Configure console scripts (database-mcp = "database_mcp.main:main") for single-command execution via uvx.

[NEW] src/database_mcp/
Package directory containing source code modules:

config.py: Environment variable management using Pydantic.

guardrails.py: AST parsing, statement validation, and limit injection.

db.py: AsyncPG connection pooling and session timeout configuration.

tools.py: FastMCP tool definitions (list_tables, describe_table, sample_rows, execute_query).

main.py: Application entrypoint.

2. AST Query Guardrails (src/database_mcp/guardrails.py)
Implement deterministic SQL parsing using sqlglot.

SELECT-Only Enforcement: Parse query into an AST and reject any statement root that is not exp.Select or exp.Union.

Automatic LIMIT Rewriting: Inspect the limit expression in the AST. If missing or exceeding 100, rewrite the AST node to enforce LIMIT 100.

Disallow Mutations: Explicitly block DROP, DELETE, UPDATE, INSERT, ALTER, TRUNCATE, and GRANT operations.

3. Progressive Schema Discovery (src/database_mcp/tools.py)
Split monolithic database schema dumping into token-efficient tools:

list_tables:

SQL
SELECT table_name, 
       coalesce(c.reltuples::bigint, 0) AS estimated_rows
FROM information_schema.tables t
LEFT JOIN pg_class c ON c.relname = t.table_name
WHERE table_schema = 'public';
describe_table(table_name: str):
Returns column names, data types, nullability, default values, primary keys, and foreign key relationships for a single table.

sample_rows(table_name: str):
Returns up to 3 sample rows using SELECT * FROM table_name LIMIT 3;.

execute_query(sql_query: str):
Executes validated and sanitized SQL through the sqlglot guardrail engine.

4. Database Connection & Bounded Execution (src/database_mcp/db.py)
Maintain an asynchronous connection pool using asyncpg.

Before executing any query, run session settings:

SQL
SET TRANSACTION READ ONLY;
SET statement_timeout = '3000ms';
Serialize query results cleanly into JSON arrays.

5. Developer Experience & Testing Setup
[NEW] docker/docker-compose.yml & docker/init.sql
Spin up a local PostgreSQL container on port 5432 with pre-seeded sample tables (users, orders, products) for testing.

[NEW] tests/test_guardrails.py
Unit tests asserting that:

Non-SELECT queries raise UnsafeQueryError.

Queries missing limits are properly rewritten with LIMIT 100.

Valid queries pass without modification.

[NEW] README.md
Include setup instructions, configuration snippets for Claude Desktop, Cursor, and OpenCode, and developer usage examples.

Verification Plan
Automated Tests
Run pytest to execute unit tests against AST guardrails:

Bash
uv run pytest tests/
Manual Verification
Spin up local PostgreSQL test container:

Bash
docker compose -f docker/docker-compose.yml up -d
Run MCP server in local environment:

Bash
DATABASE_URL="postgres://mcp_user:mcp_pass@localhost:5432/mcp_test" uv run database-mcp
Test Tool Execution via Client:

Invoke list_tables and verify returned schema list.

Invoke describe_table for table users.

Test execute_query with SELECT * FROM users (verify automatic LIMIT 100 injection).

Test execute_query with DROP TABLE users; (verify guardrail rejection).