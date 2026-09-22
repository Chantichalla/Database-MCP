"""
MCP Server implementation for Safe Database Gateway.
Provides tools for autonomous read-only querying, schema discovery,
circuit breaker anomaly monitoring, and authenticated Human-in-the-Loop (HITL) mutation controls.
"""
import os
import uuid
import json
import hmac
import hashlib
import time
import secrets
from typing import Dict, Any, Optional

try:
    from mcp.server.mcpserver import MCPServer
    mcp = MCPServer("SafeDatabaseGateway")
except ImportError:
    from mcp.server.fastmcp import FastMCP
    mcp = FastMCP("SafeDatabaseGateway")

from .database import (
    initialize_database,
    ALLOWED_BUSINESS_TABLES,
    RESTRICTED_TABLES,
    get_read_only_connection,
    is_postgres,
    DB_ENGINE,
    DB_NAME,
    DB_HOST,
    DB_PORT,
)
from .guardrails.ast_guard import (
    validate_and_transform_query,
    inspect_mutation_ast,
    ASTGuardrailError,
    DEFAULT_MAX_LIMIT,
)
from .guardrails.executor import (
    execute_bounded_query,
    execute_mutation_query,
    DEFAULT_TIMEOUT_SECONDS,
)
from .guardrails.circuit_breaker import (
    CIRCUIT_BREAKER,
    CircuitBreakerError,
    RateLimitExceededError,
)
from .audit import log_event, read_last_events, scrub_secrets
from .config import get_active_role, get_role_spec

# Secret key required for human operators to approve mutations (prevents LLM self-approval)
OPERATOR_APPROVAL_SECRET = os.getenv("OPERATOR_APPROVAL_SECRET", "SECURE_HITL_CONFIRMED_2026")

# Auto-initialize fallback database if running on SQLite
if not is_postgres():
    initialize_database()

# In-memory store for pending HITL mutation proposals: token -> proposal_dict
PENDING_PROPOSALS: Dict[str, Dict[str, Any]] = {}

# A2: HMAC-signed proposal tokens with short TTL.
# Generated at startup (not from .env) so a restart invalidates all tokens.
TOKEN_SECRET = secrets.token_hex(32)
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
        expected = hmac.new(
            TOKEN_SECRET.encode(),
            f"{mutation_id}:{ts}".encode(),
            hashlib.sha256,
        ).hexdigest()
        return hmac.compare_digest(sig, expected)
    except Exception:
        return False


def get_current_dialect() -> str:
    """Returns the SQL dialect for AST validation."""
    return "postgres" if is_postgres() else "sqlite"


def _estimate_table_rows(tables: set) -> dict:
    """Planner row estimates (pg_class.reltuples) for catalog tables.

    Estimates, not exact counts — they can lag after bulk loads. Good for
    "which tables are big", wrong for exact accounting. Restricted tables
    are never queried, so estimates leak nothing new. Best-effort: {} on
    any failure or non-Postgres engine.
    """
    if not is_postgres() or not tables:
        return {}
    try:
        with get_read_only_connection() as conn:
            cur = conn.cursor()
            cur.execute(
                "SELECT relname, reltuples::bigint FROM pg_class "
                "WHERE relname = ANY(%s);",
                (sorted(tables),),
            )
            return {name: int(count) for name, count in cur.fetchall()}
    except Exception:
        return {}


# ── A0: role-based access control (roles.yaml; fail-closed to reader) ─────
# Table-scope checks apply on Postgres only: the SQLite fallback uses a
# different table universe. Capability flags apply on every engine.

def _forbidden_response(message: str) -> str:
    return json.dumps({
        "status": "FORBIDDEN_ROLE",
        "category": "ROLE_ACCESS_DENIED",
        "error": message,
        "active_role": get_active_role(),
    }, indent=2)


def _tables_denied(role_tables, accessed) -> list:
    allowed = {t.lower() for t in role_tables}
    return sorted({t for t in accessed if t.lower() not in allowed})


def _sess() -> str:
    """Enforcement/audit session key: the active gateway role.

    One shared "default" let one actor's abuse lock out everyone. Keying by
    role isolates keycards (editor probes can no longer quarantine admin
    approvals). Per-user identity remains future work; this is the honest
    per-keycard step. Resolved live (env-overridable) so tests can switch.
    """
    return get_active_role()


def _safe_err(e: Exception) -> str:
    """Exception text safe to surface: credential patterns redacted."""
    return scrub_secrets(str(e))


@mcp.tool()
def get_gateway_health() -> str:
    """
    Returns the real-time health, anomaly circuit breaker state, and quota usage of the database gateway.
    """
    status = CIRCUIT_BREAKER.get_status(_sess())
    return json.dumps({
        "status": "HEALTHY" if not status["is_quarantined"] else "QUARANTINED",
        "engine": "PostgreSQL (Chinook)" if is_postgres() else "SQLite",
        "circuit_breaker": status,
        "policy": {
            "max_violations_threshold": 3,
            "quarantine_cooldown_seconds": 900,
            "max_queries_per_minute": 30,
            "max_compute_budget_seconds": 15.0
        }
    }, indent=2)


@mcp.tool()
def safe_query(sql: str) -> str:
    """
    Safely executes a read-only SQL query against the database.
    
    Guarantees:
    - Anomaly circuit breaker: Tracks security violations and quarantines abusive sessions.
    - Rate limiter: Maximum 30 queries/minute and 15s cumulative compute budget.
    - Static AST validation: Blocks SQL injection, multi-statements, and writable CTEs.
    - Strict table whitelisting.
    - Automatic row limit clamping (max 100 rows).
    - Native execution timeout and memory streaming.
    - Dynamic PII masking on sensitive fields.
    """
    # Pre-execution check: throttle-only for reads (quarantine gates writes).
    try:
        CIRCUIT_BREAKER.check_read_allowed(_sess())
        CIRCUIT_BREAKER.record_query_start(_sess())
    except CircuitBreakerError as e:
        log_event("SESSION_QUARANTINED_HIT", session_id=_sess())
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=sql,
                  rejection_reason=str(e), stage="CB")
        return json.dumps({
            "status": "CIRCUIT_BREAKER_ACTIVE",
            "category": "SESSION_QUARANTINED",
            "error": _safe_err(e),
            "circuit_breaker_status": CIRCUIT_BREAKER.get_status(_sess())
        }, indent=2)
    except RateLimitExceededError as e:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=sql,
                  rejection_reason=str(e), stage="RATE_LIMIT")
        return json.dumps({
            "status": "THROTTLED",
            "category": "RATE_LIMIT_EXCEEDED",
            "error": _safe_err(e),
            "circuit_breaker_status": CIRCUIT_BREAKER.get_status(_sess())
        }, indent=2)

    dialect = get_current_dialect()
    try:
        # Stage 1: AST Validation & Clamping (including CTE inspection)
        safe_sql, tables_accessed = validate_and_transform_query(
            raw_sql=sql,
            allowed_tables=ALLOWED_BUSINESS_TABLES,
            max_limit=DEFAULT_MAX_LIMIT,
            dialect=dialect
        )

        # Stage 1b: Role read-scope (A0). AST passed; now check the keycard.
        role = get_active_role()
        if is_postgres():
            denied = _tables_denied(get_role_spec(role)["tables_read"], tables_accessed)
            if denied:
                log_event("QUERY_REJECTED", session_id=_sess(), raw_input=sql,
                          rejection_reason=f"Role '{role}' may not read table(s): {denied}",
                          stage="ROLE")
                return _forbidden_response(
                    f"Role '{role}' may not read table(s): {denied}.")

        # Stage 2: Bounded Execution
        result = execute_bounded_query(
            safe_sql=safe_sql,
            timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
            max_rows=DEFAULT_MAX_LIMIT,
            mask_pii=True
        )

        result["original_query"] = sql
        result["executed_safe_sql"] = safe_sql
        result["tables_accessed"] = sorted(list(tables_accessed))
        result["status"] = "SUCCESS"
        result["engine"] = "PostgreSQL" if is_postgres() else "SQLite"

        log_event("QUERY_ACCEPTED", session_id=_sess(), safe_sql=safe_sql,
                  tables_accessed=sorted(list(tables_accessed)),
                  row_count=result.get("row_count", 0),
                  exec_ms=result.get("execution_time_ms", 0))
        return json.dumps(result, indent=2, default=str)

    except ASTGuardrailError as e:
        # Record violation in Circuit Breaker
        tripped = CIRCUIT_BREAKER.record_violation(_sess(), str(e))
        cb_status = CIRCUIT_BREAKER.get_status(_sess())
        warning = "ATTENTION: Circuit breaker tripped! Session is now quarantined." if tripped else f"Warning: {cb_status['violations_in_window']}/{cb_status['max_violations_threshold']} violations before session quarantine."

        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=sql,
                  rejection_reason=str(e), stage="AST")
        if tripped:
            log_event("CIRCUIT_BREAKER_TRIP", session_id=_sess(),
                      violation_count=cb_status["violations_in_window"],
                      quarantine_until=cb_status.get("quarantine_remaining_seconds", 0))
        return json.dumps({
            "status": "REJECTED_BY_GUARDRAIL",
            "category": "AST_SECURITY_VIOLATION",
            "error": _safe_err(e),
            "circuit_breaker": warning,
            "quarantined": tripped,
            "original_query": sql
        }, indent=2)

    except TimeoutError as e:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=sql,
                  rejection_reason=str(e), stage="TIMEOUT")
        return json.dumps({
            "status": "EXECUTION_TIMEOUT",
            "category": "BOUNDED_TIMEOUT_EXCEEDED",
            "error": _safe_err(e),
            "original_query": sql
        }, indent=2)
    except Exception as e:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=sql,
                  rejection_reason=str(e), stage="DB")
        return json.dumps({
            "status": "DATABASE_ERROR",
            "category": "EXECUTION_FAILURE",
            "error": _safe_err(e),
            "original_query": sql
        }, indent=2)


@mcp.tool()
def list_accessible_tables() -> str:
    """
    Lists the tables the agent is permitted to query, along with descriptions.
    Prevents the LLM from hallucinating queries against internal/restricted tables.
    """
    try:
        CIRCUIT_BREAKER.check_read_allowed(_sess())
    except (CircuitBreakerError, RateLimitExceededError) as e:
        return json.dumps({"status": "CIRCUIT_BREAKER_ACTIVE", "error": _safe_err(e)}, indent=2)

    if is_postgres():
        table_catalog = {
            "album": "Music albums containing album_id, title, artist_id.",
            "artist": "Music artists and bands containing artist_id, name.",
            "customer": "Customer profiles containing address, city, country (PII masked: email, phone).",
            "genre": "Music genres containing genre_id, name.",
            "invoice": "Billing invoices containing customer_id, invoice_date, total, billing address.",
            "invoice_line": "Invoice line items containing invoice_id, track_id, unit_price, quantity.",
            "media_type": "Audio/video media format definitions.",
            "playlist": "Curated music playlists containing playlist_id, name.",
            "playlist_track": "Mapping between playlists and tracks.",
            "track": "Songs and tracks containing name, album_id, media_type_id, genre_id, milliseconds, unit_price."
        }
        restricted_info = "Tables such as 'employee' (internal HR, birthdays, addresses) are strictly RESTRICTED."
    else:
        table_catalog = {
            "products": "Public catalog containing item id, name, category, price, and stock_quantity.",
            "orders": "E-commerce order transactions containing customer_id, product_id, quantity, total_amount, status.",
            "customers": "Customer account details (PII fields like email and phone are dynamically masked)."
        }
        restricted_info = "Tables 'salaries' and 'admin_tokens' are strictly RESTRICTED."

    return json.dumps({
        "status": "SUCCESS",
        "engine": "PostgreSQL (Chinook)" if is_postgres() else "SQLite",
        "accessible_tables": table_catalog,
        "estimated_rows": _estimate_table_rows(set(table_catalog)),
        "restricted_policy": restricted_info,
        "guardrail_policy": "Autonomous read-only access (SELECT queries only). Max 100 rows per query. Hard 2.0s timeout."
    }, indent=2)


@mcp.tool()
def describe_table(table_name: str) -> str:
    """
    Returns column names, data types, and primary key constraints for an accessible table.
    """
    try:
        CIRCUIT_BREAKER.check_read_allowed(_sess())
    except (CircuitBreakerError, RateLimitExceededError) as e:
        return json.dumps({"status": "CIRCUIT_BREAKER_ACTIVE", "error": _safe_err(e)}, indent=2)

    clean_name = table_name.strip().lower()
    if clean_name not in ALLOWED_BUSINESS_TABLES:
        CIRCUIT_BREAKER.record_violation(_sess(), f"Unauthorized table discovery: {clean_name}")
        return json.dumps({
            "status": "ACCESS_DENIED",
            "error": f"Table '{clean_name}' is not in the list of accessible business tables. (Permitted: {sorted(list(ALLOWED_BUSINESS_TABLES))})"
        }, indent=2)

    # A0: role read-scope (Postgres only; see safe_query Stage 1b).
    role = get_active_role()
    if is_postgres() and clean_name not in {t.lower() for t in get_role_spec(role)["tables_read"]}:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=table_name,
                  rejection_reason=f"Role '{role}' may not describe table '{clean_name}'",
                  stage="ROLE")
        return _forbidden_response(
            f"Role '{role}' may not describe table '{clean_name}'.")

    with get_read_only_connection() as conn:
        cur = conn.cursor()
        if is_postgres():
            pk_query = """
            SELECT kcu.column_name
            FROM information_schema.table_constraints tc
            JOIN information_schema.key_column_usage kcu
              ON tc.constraint_name = kcu.constraint_name
              AND tc.table_schema = kcu.table_schema
            WHERE tc.constraint_type = 'PRIMARY KEY' AND tc.table_name = %s;
            """
            cur.execute(pk_query, (clean_name,))
            pk_columns = {r[0] for r in cur.fetchall()}

            cur.execute("""
            SELECT a.attname, fr.relname, fa.attname
            FROM pg_constraint c
            JOIN pg_class t ON t.oid = c.conrelid
            JOIN pg_attribute a ON a.attrelid = c.conrelid
                               AND a.attnum = ANY(c.conkey)
            JOIN pg_class fr ON fr.oid = c.confrelid
            JOIN pg_attribute fa ON fa.attrelid = c.confrelid
                                AND fa.attnum = ANY(c.confkey)
            WHERE c.contype = 'f' AND t.relname = %s
            ORDER BY a.attnum;
            """, (clean_name,))
            # pg_catalog has no privilege filtering: hide FK targets outside
            # the allowlist (e.g. customer.support_rep_id -> employee) so
            # schema discovery never names restricted tables.
            foreign_keys = [
                {"column": col, "references_table": ref_t, "references_column": ref_c}
                for col, ref_t, ref_c in cur.fetchall()
                if ref_t in ALLOWED_BUSINESS_TABLES
            ]

            cur.execute("""
            SELECT ordinal_position, column_name, data_type, is_nullable, column_default
            FROM information_schema.columns
            WHERE table_name = %s
            ORDER BY ordinal_position;
            """, (clean_name,))
            columns = [
                {
                    "cid": row[0],
                    "name": row[1],
                    "type": row[2],
                    "notnull": (row[3] == "NO"),
                    "default_value": row[4],
                    "is_primary_key": (row[1] in pk_columns)
                }
                for row in cur.fetchall()
            ]
        else:
            cur.execute(f"PRAGMA table_info({clean_name})")
            columns = [
                {
                    "cid": row[0],
                    "name": row[1],
                    "type": row[2],
                    "notnull": bool(row[3]),
                    "default_value": row[4],
                    "is_primary_key": bool(row[5])
                }
                for row in cur.fetchall()
            ]
            foreign_keys = []

    return json.dumps({
        "status": "SUCCESS",
        "table": clean_name,
        "columns": columns,
        "foreign_keys": foreign_keys
    }, indent=2)


@mcp.tool()
def sample_rows(table_name: str) -> str:
    """
    Returns up to 3 representative rows from an accessible table.
    Lets the agent see real data shapes before writing queries.
    Same read pipeline as safe_query: throttle gate, whitelist, role
    read-scope, AST validation, PII masking, audit.
    """
    try:
        CIRCUIT_BREAKER.check_read_allowed(_sess())
        CIRCUIT_BREAKER.record_query_start(_sess())
    except RateLimitExceededError as e:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=table_name,
                  rejection_reason=str(e), stage="RATE_LIMIT")
        return json.dumps({
            "status": "THROTTLED",
            "category": "RATE_LIMIT_EXCEEDED",
            "error": _safe_err(e),
            "circuit_breaker_status": CIRCUIT_BREAKER.get_status(_sess())
        }, indent=2)

    clean_name = table_name.strip().lower()
    if clean_name not in ALLOWED_BUSINESS_TABLES:
        CIRCUIT_BREAKER.record_violation(_sess(), f"Unauthorized table sampling: {clean_name}")
        return json.dumps({
            "status": "ACCESS_DENIED",
            "error": f"Table '{clean_name}' is not in the list of accessible business tables. (Permitted: {sorted(list(ALLOWED_BUSINESS_TABLES))})"
        }, indent=2)

    # A0: role read-scope (Postgres only; see safe_query Stage 1b).
    role = get_active_role()
    if is_postgres() and clean_name not in {t.lower() for t in get_role_spec(role)["tables_read"]}:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=table_name,
                  rejection_reason=f"Role '{role}' may not sample table '{clean_name}'",
                  stage="ROLE")
        return _forbidden_response(
            f"Role '{role}' may not sample table '{clean_name}'.")

    dialect = get_current_dialect()
    try:
        safe_sql, tables_accessed = validate_and_transform_query(
            raw_sql=f"SELECT * FROM {clean_name} LIMIT 3",
            allowed_tables=ALLOWED_BUSINESS_TABLES,
            max_limit=DEFAULT_MAX_LIMIT,
            dialect=dialect
        )
        result = execute_bounded_query(
            safe_sql=safe_sql,
            timeout_seconds=DEFAULT_TIMEOUT_SECONDS,
            max_rows=3,
            mask_pii=True
        )
        result["table"] = clean_name
        result["status"] = "SUCCESS"
        result["engine"] = "PostgreSQL" if is_postgres() else "SQLite"

        log_event("QUERY_ACCEPTED", session_id=_sess(), safe_sql=safe_sql,
                  tables_accessed=sorted(list(tables_accessed)),
                  row_count=result.get("row_count", 0),
                  exec_ms=result.get("execution_time_ms", 0))
        return json.dumps(result, indent=2, default=str)

    except ASTGuardrailError as e:
        tripped = CIRCUIT_BREAKER.record_violation(_sess(), str(e))
        cb_status = CIRCUIT_BREAKER.get_status(_sess())
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=table_name,
                  rejection_reason=str(e), stage="AST")
        if tripped:
            log_event("CIRCUIT_BREAKER_TRIP", session_id=_sess(),
                      violation_count=cb_status["violations_in_window"],
                      quarantine_until=cb_status.get("quarantine_remaining_seconds", 0))
        return json.dumps({
            "status": "REJECTED_BY_GUARDRAIL",
            "category": "AST_SECURITY_VIOLATION",
            "error": _safe_err(e),
            "original_query": table_name
        }, indent=2)
    except TimeoutError as e:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=table_name,
                  rejection_reason=str(e), stage="TIMEOUT")
        return json.dumps({
            "status": "EXECUTION_TIMEOUT",
            "category": "BOUNDED_TIMEOUT_EXCEEDED",
            "error": _safe_err(e),
            "original_query": table_name
        }, indent=2)
    except Exception as e:
        log_event("QUERY_REJECTED", session_id=_sess(), raw_input=table_name,
                  rejection_reason=str(e), stage="DB")
        return json.dumps({
            "status": "DATABASE_ERROR",
            "category": "EXECUTION_FAILURE",
            "error": _safe_err(e),
            "original_query": table_name
        }, indent=2)


@mcp.tool()
def propose_mutation(sql: str) -> str:
    """
    Human-in-the-Loop (HITL) Proposal Tool:
    Submits a proposed data mutation (INSERT, UPDATE, DELETE) for review.
    Does NOT execute the mutation. Generates a proposal token and dry-run query plan.
    """
    try:
        CIRCUIT_BREAKER.check_allowed(_sess())
    except (CircuitBreakerError, RateLimitExceededError) as e:
        log_event("SESSION_QUARANTINED_HIT", session_id=_sess())
        return json.dumps({"status": "CIRCUIT_BREAKER_ACTIVE", "error": _safe_err(e)}, indent=2)

    # A0: role gate — proposing is an editor/admin power.
    role = get_active_role()
    spec = get_role_spec(role)
    if not spec["can_propose"]:
        log_event("MUTATION_REJECTED", session_id=_sess(),
                  reason=f"Role '{role}' may not propose mutations", stage="ROLE")
        return _forbidden_response(f"Role '{role}' may not propose mutations.")

    dialect = get_current_dialect()
    try:
        normalized_sql, stmt_type, target_tables = inspect_mutation_ast(
            raw_sql=sql,
            allowed_tables=ALLOWED_BUSINESS_TABLES,
            dialect=dialect
        )

        # A0: role write-scope (Postgres only). AST passed; check the keycard.
        if is_postgres():
            denied = _tables_denied(spec["tables_write"], target_tables)
            if denied:
                log_event("MUTATION_REJECTED", session_id=_sess(),
                          reason=f"Role '{role}' may not write table(s): {denied}",
                          stage="ROLE")
                return _forbidden_response(
                    f"Role '{role}' may not write table(s): {denied}.")

        explain_rows = []
        with get_read_only_connection() as conn:
            cur = conn.cursor()
            try:
                if is_postgres():
                    cur.execute(f"EXPLAIN {normalized_sql}")
                    explain_rows = [{"plan": r[0]} for r in cur.fetchall()]
                else:
                    cur.execute(f"EXPLAIN QUERY PLAN {normalized_sql}")
                    explain_rows = [dict(r) for r in cur.fetchall()]
            except Exception:
                pass

        proposal_token = _make_token(uuid.uuid4().hex)
        proposal_record = {
            "proposal_token": proposal_token,
            "statement_type": stmt_type,
            "target_tables": sorted(list(target_tables)),
            "normalized_sql": normalized_sql,
            "query_plan": explain_rows,
            "status": "AWAITING_OPERATOR_APPROVAL"
        }
        PENDING_PROPOSALS[proposal_token] = proposal_record
        log_event("MUTATION_PROPOSED", session_id=_sess(),
                  proposal_token=proposal_token, safe_sql=normalized_sql)

        return json.dumps({
            "status": "PROPOSAL_CREATED",
            "message": "Mutation proposal created. An authorized operator must provide their approval key to execute.",
            "proposal": proposal_record,
            "next_step": f"Call apply_mutation with proposal_token='{proposal_token}' and operator_approval_key='<KEY>'."
        }, indent=2)

    except ASTGuardrailError as e:
        CIRCUIT_BREAKER.record_violation(_sess(), str(e))
        log_event("MUTATION_REJECTED", session_id=_sess(), reason=str(e), stage="AST")
        return json.dumps({
            "status": "REJECTED_BY_GUARDRAIL",
            "category": "AST_MUTATION_VIOLATION",
            "error": _safe_err(e),
            "proposed_sql": sql
        }, indent=2)


@mcp.tool()
def apply_mutation(proposal_token: str, operator_approval_key: str) -> str:
    """
    Authenticated Human-in-the-Loop (HITL) Execution Tool:
    Executes a previously vetted mutation proposal IF AND ONLY IF a valid operator approval key is provided.
    The LLM cannot self-approve; a human administrator must provide the secret key.
    """
    try:
        CIRCUIT_BREAKER.check_allowed(_sess())
    except (CircuitBreakerError, RateLimitExceededError) as e:
        log_event("SESSION_QUARANTINED_HIT", session_id=_sess())
        return json.dumps({"status": "CIRCUIT_BREAKER_ACTIVE", "error": _safe_err(e)}, indent=2)

    # A0: role gate — approving is an admin power. The operator key below
    # stays as the second factor (proposer != approver).
    role = get_active_role()
    if not get_role_spec(role)["can_approve"]:
        log_event("MUTATION_REJECTED", session_id=_sess(),
                  reason=f"Role '{role}' may not approve mutations", stage="ROLE")
        return _forbidden_response(f"Role '{role}' may not approve mutations.")

    # Cryptographic / Operator Authentication Check
    if not operator_approval_key or operator_approval_key.strip() != OPERATOR_APPROVAL_SECRET:
        CIRCUIT_BREAKER.record_violation(_sess(), "Unauthorized mutation execution attempt without valid operator key.")
        log_event("MUTATION_REJECTED", session_id=_sess(), reason="bad operator key")
        return json.dumps({
            "status": "OPERATOR_AUTHENTICATION_REQUIRED",
            "error": "Execution rejected: Invalid or missing operator_approval_key. The LLM cannot self-approve mutations.",
            "quarantine_warning": "Repeated unauthorized approval attempts will trip the gateway circuit breaker."
        }, indent=2)

    proposal = PENDING_PROPOSALS.get(proposal_token)
    if not proposal:
        log_event("MUTATION_REJECTED", session_id=_sess(),
                  reason="unknown token", proposal_token=proposal_token)
        return json.dumps({
            "status": "INVALID_TOKEN",
            "error": f"No pending proposal found for token '{proposal_token}'. Proposals may have expired or already executed."
        }, indent=2)

    # A2: self-verifying HMAC + TTL check (tamper-evidence + expiry).
    # The dict lookup above enforces single-use; this enforces authenticity/expiry
    # even if memory were inspected/tampered with.
    if not _verify_token(proposal_token):
        # Invalidate expired/forged tokens to prevent replay attempts.
        PENDING_PROPOSALS.pop(proposal_token, None)
        log_event("MUTATION_REJECTED", session_id=_sess(),
                  reason="expired or forged token", proposal_token=proposal_token)
        return json.dumps({
            "status": "INVALID_TOKEN",
            "error": "Proposal token failed verification (bad signature or expired TTL). "
                     f"Tokens expire after {TOKEN_TTL_SECONDS}s. Propose again.",
            "category": "EXPIRED_OR_FORGED_TOKEN",
        }, indent=2)

    # Execute on write connection
    normalized_sql = proposal["normalized_sql"]
    try:
        exec_result = execute_mutation_query(normalized_sql)
        # Invalidate proposal token to prevent replay attacks
        del PENDING_PROPOSALS[proposal_token]
        log_event("MUTATION_APPLIED", session_id=_sess(),
                  proposal_token=proposal_token, operator="[REDACTED]",
                  row_count=exec_result.get("affected_rows", 0))

        return json.dumps({
            "status": "SUCCESS",
            "message": "Mutation successfully applied by authenticated operator.",
            "statement_type": proposal["statement_type"],
            "target_tables": proposal["target_tables"],
            "affected_rows": exec_result["affected_rows"],
            "execution_time_ms": exec_result["execution_time_ms"]
        }, indent=2)
    except Exception as e:
        log_event("MUTATION_REJECTED", session_id=_sess(),
                  reason=str(e), proposal_token=proposal_token)
        return json.dumps({
            "status": "EXECUTION_ERROR",
            "error": _safe_err(e)
        }, indent=2)


@mcp.tool()
def get_audit_summary(n: int = 20) -> str:
    """Read-only audit summary: returns the last N gateway audit events.

    Lets the operator ask 'what happened in the last 10 minutes'
    without opening files manually.
    """
    try:
        count = max(1, min(int(n), 200))
    except (TypeError, ValueError):
        count = 20
    events = read_last_events(count)
    return json.dumps({
        "status": "SUCCESS",
        "event_count": len(events),
        "events": events,
    }, indent=2, default=str)


@mcp.tool()
def reset_quarantine() -> str:
    """Management tool (admin role only): clears the session quarantine.

    Lets the owner recover the gateway without restarting the process.
    Never gated by the circuit breaker itself.
    """
    role = get_active_role()
    if not get_role_spec(role)["management"]:
        log_event("QUERY_REJECTED", session_id=_sess(),
                  raw_input="reset_quarantine",
                  rejection_reason=f"Role '{role}' lacks management rights",
                  stage="ROLE")
        return _forbidden_response(
            f"Role '{role}' lacks management rights.")
    CIRCUIT_BREAKER.reset_session(_sess())
    log_event("QUARANTINE_RESET", session_id=_sess(), role=role)
    return json.dumps({
        "status": "SUCCESS",
        "message": "Session quarantine cleared.",
        "active_role": role,
    }, indent=2)


def main():
    """Starts the database MCP server."""
    if not is_postgres():
        initialize_database()
    mcp.run()


if __name__ == "__main__":
    main()
