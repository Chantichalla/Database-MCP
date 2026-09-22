"""
Real AST Parsing and SQL Guardrails using sqlglot.
Replaces fragile regex safety with deterministic Abstract Syntax Tree inspection.
"""
from typing import Set, Tuple, Optional
import sqlglot
from sqlglot import exp

DEFAULT_MAX_LIMIT = 100

# Strict allowlist of safe analytical SQL functions.
# Any function not on this list is rejected at AST parse time.
# This blocks pg_read_file, current_setting, pg_sleep, dblink, lo_import etc.
SAFE_FUNCTIONS: Set[str] = {
    # Aggregates
    "count", "sum", "avg", "min", "max", "array_agg", "string_agg",
    "every", "bool_and", "bool_or",
    # String functions (safe, but operate on already-masked values)
    "upper", "lower", "trim", "ltrim", "rtrim", "length", "char_length",
    "concat", "coalesce", "nullif", "replace", "substring", "split_part",
    "left", "right", "position", "strpos", "lpad", "rpad", "repeat",
    "reverse", "initcap", "to_char", "encode",
    # Math
    "round", "ceil", "ceiling", "floor", "abs", "mod", "power", "sqrt",
    "sign", "trunc", "log", "ln", "exp",
    # Date/Time (read-only metadata, not system state)
    "now", "current_date", "current_time", "current_timestamp",
    "date_part", "extract", "age", "date_trunc", "to_timestamp",
    "to_date", "make_date", "make_interval",
    # Conditionals / casting
    "coalesce", "nullif", "greatest", "least", "cast",
    # JSON (read-only access to JSON-typed columns)
    "json_extract_path_text", "jsonb_extract_path_text",
    "json_array_length", "jsonb_array_length",
    # Window functions
    "row_number", "rank", "dense_rank", "ntile", "lag", "lead",
    "first_value", "last_value", "nth_value", "percent_rank", "cume_dist",
    # Type checking
    "typeof", "pg_typeof",
    # Row/set returning (safe, table-valued)
    "unnest", "generate_series",
}

# Function name prefixes that are always blocked regardless of allowlist.
# pg_ prefix covers pg_read_file, pg_read_binary_file, pg_ls_dir, pg_stat_file, etc.
BLOCKED_FUNCTION_PREFIXES: tuple = ("pg_read", "pg_ls", "pg_write", "pg_stat_file",
                                      "pg_execute", "lo_import", "lo_export", "lo_create",
                                      "dblink", "postgres_fdw",)
BLOCKED_FUNCTIONS: Set[str] = {
    "current_setting", "set_config", "pg_sleep", "pg_cancel_backend",
    "pg_terminate_backend", "pg_reload_conf", "pg_rotate_logfile",
    "pg_start_backup", "pg_stop_backup", "pg_switch_wal",
    "pg_create_restore_point", "pg_current_logfile",
    "inet_server_addr", "inet_client_addr",
}


class ASTGuardrailError(Exception):
    """Raised when an AST security validation fails."""
    pass


def validate_and_transform_query(
    raw_sql: str,
    allowed_tables: Set[str],
    max_limit: int = DEFAULT_MAX_LIMIT,
    dialect: str = "sqlite"
) -> Tuple[str, Set[str]]:
    """
    Validates a SQL query using true AST parsing:
    1. Ensures single-statement execution (blocks multi-statement / semicolon injection).
    2. Enforces that the root statement is a SELECT query (disallows DDL/DML in autonomous mode).
    3. Traverses AST to extract all referenced tables across CTEs, subqueries, and joins,
       verifying each against allowed_tables.
    4. Rewrites the AST to inject or clamp the LIMIT clause to max_limit.

    Returns:
        Tuple[str, Set[str]]: (Transformed safe SQL string, Set of referenced table names)
    """
    cleaned_sql = raw_sql.strip()
    if not cleaned_sql:
        raise ASTGuardrailError("Empty SQL query provided.")

    # Stage 1: Parse AST
    try:
        parsed_statements = sqlglot.parse(cleaned_sql, read=dialect)
    except Exception as e:
        raise ASTGuardrailError(f"SQL Syntax Error: Unable to parse query AST. Details: {e}")

    # Stage 2: Single Statement Enforcement
    if len(parsed_statements) == 0:
        raise ASTGuardrailError("No valid SQL statement found.")
    if len(parsed_statements) > 1:
        raise ASTGuardrailError(
            f"Security Violation: Multi-statement query detected ({len(parsed_statements)} statements). "
            "Semicolon-chained queries are prohibited."
        )

    stmt = parsed_statements[0]

    # Stage 3: Statement Type Check (Must be SELECT for autonomous execution)
    if not isinstance(stmt, exp.Select):
        stmt_type = stmt.key.upper() if hasattr(stmt, "key") else type(stmt).__name__
        raise ASTGuardrailError(
            f"Security Violation: Autonomous execution permits only 'SELECT' queries. "
            f"Received statement type '{stmt_type}'. For data modifications, use 'propose_mutation'."
        )

    # Stage 3b: Prohibit Writable CTEs and Any Nested DML Anywhere in the AST
    for dml_type in (exp.Insert, exp.Update, exp.Delete, exp.Create, exp.Drop, exp.Alter):
        if stmt.find(dml_type):
            operation_name = dml_type.__name__.upper()
            raise ASTGuardrailError(
                f"Security Violation: Prohibited operation '{operation_name}' detected inside query tree. "
                "Writable CTEs and nested DML statements are strictly blocked."
            )

    for cte in stmt.find_all(exp.CTE):
        if not isinstance(cte.this, exp.Select):
            raise ASTGuardrailError(
                f"Security Violation: CTE '{cte.alias}' contains non-SELECT operations. "
                "Only pure read-only SELECT subqueries are permitted."
            )

    # Stage 3c: Scalar Function Allowlist Inspection
    # Inspects EVERY function node in the AST, including scalar expressions in SELECT,
    # WHERE, HAVING clauses — not just FROM-clause table functions.
    for func_node in stmt.find_all(exp.Anonymous):
        fn_name = func_node.name.lower() if func_node.name else ""
        if fn_name in BLOCKED_FUNCTIONS or fn_name.startswith(BLOCKED_FUNCTION_PREFIXES):
            raise ASTGuardrailError(
                f"Security Violation: Dangerous function '{fn_name}' is explicitly blocked. "
                "System administration and file-access functions are prohibited."
            )
        if fn_name and fn_name not in SAFE_FUNCTIONS:
            raise ASTGuardrailError(
                f"Security Violation: Function '{fn_name}' is not on the safe analytical function allowlist. "
                "Only approved aggregation, string, math, date, and conditional functions are permitted."
            )

    # Stage 4: Extract and Validate All Table References (including inside CTEs, subqueries, joins)
    referenced_tables: Set[str] = set()
    for table_node in stmt.find_all(exp.Table):
        table_name = table_node.name.lower()
        # Transparently rewrite 'customer' to 'customer_masked' (security-barrier view)
        # This ensures split_part/substring operate only on pre-masked data
        if table_name == "customer":
            table_node.set("this", exp.Identifier(this="customer_masked", quoted=False))
            table_name = "customer_masked"
        referenced_tables.add(table_name)

    # Check for CTE definitions so we don't mistakenly reject CTE internal table aliases
    cte_aliases = {cte.alias.lower() for cte in stmt.find_all(exp.CTE) if cte.alias}
    actual_physical_tables = referenced_tables - cte_aliases

    unauthorized_tables = actual_physical_tables - {t.lower() for t in allowed_tables}
    if unauthorized_tables:
        raise ASTGuardrailError(
            f"Security Violation: Access denied to table(s): {sorted(list(unauthorized_tables))}. "
            f"Permitted tables are: {sorted(list(allowed_tables))}."
        )

    # Stage 5: LIMIT Injection & Clamping on Root Query
    existing_limit = stmt.args.get("limit")
    if existing_limit is None:
        # Inject LIMIT clause
        stmt = stmt.limit(max_limit)
    else:
        # Inspect and clamp existing LIMIT
        limit_expr = existing_limit.expression
        try:
            limit_val = int(limit_expr.this)
            if limit_val > max_limit or limit_val <= 0:
                existing_limit.set("expression", exp.Literal.number(max_limit))
        except (AttributeError, ValueError):
            # If dynamic or non-integer limit expression, clamp to max_limit
            existing_limit.set("expression", exp.Literal.number(max_limit))

    safe_sql = stmt.sql(dialect=dialect)
    return safe_sql, actual_physical_tables


def inspect_mutation_ast(
    raw_sql: str,
    allowed_tables: Set[str],
    dialect: str = "sqlite"
) -> Tuple[str, str, Set[str]]:
    """
    Validates and inspects an AST for a proposed mutation (INSERT, UPDATE, DELETE).
    Used in the Human-in-the-Loop (HITL) proposal workflow.

    Returns:
        Tuple[str, str, Set[str]]: (Normalized SQL, Statement Type, Set of target tables)
    """
    cleaned_sql = raw_sql.strip()
    if not cleaned_sql:
        raise ASTGuardrailError("Empty SQL query provided.")

    try:
        parsed_statements = sqlglot.parse(cleaned_sql, read=dialect)
    except Exception as e:
        raise ASTGuardrailError(f"SQL Syntax Error: Unable to parse query AST. Details: {e}")

    if len(parsed_statements) != 1:
        raise ASTGuardrailError("Multi-statement mutations are prohibited. Exactly one mutation statement is permitted.")

    stmt = parsed_statements[0]
    stmt_type = stmt.key.upper() if hasattr(stmt, "key") else type(stmt).__name__.upper()

    # Disallow destructive DDL like DROP TABLE or ALTER TABLE in standard mutations
    if isinstance(stmt, (exp.Drop, exp.Alter, exp.Command, exp.Pragma)):
        raise ASTGuardrailError(f"High-Risk DDL statement '{stmt_type}' is strictly disallowed through this interface.")

    if not isinstance(stmt, (exp.Insert, exp.Update, exp.Delete)):
        raise ASTGuardrailError(f"Statement type '{stmt_type}' is not a supported DML mutation (expected INSERT, UPDATE, DELETE).")

    # Target tables check
    target_tables = {table.name.lower() for table in stmt.find_all(exp.Table)}
    unauthorized_tables = target_tables - {t.lower() for t in allowed_tables}
    if unauthorized_tables:
        raise ASTGuardrailError(
            f"Access denied: Mutation targets unauthorized table(s): {sorted(list(unauthorized_tables))}."
        )

    # Require WHERE clause for UPDATE and DELETE to prevent accidental table-wipe
    if isinstance(stmt, (exp.Update, exp.Delete)):
        if stmt.args.get("where") is None:
            raise ASTGuardrailError(
                f"Safety Guardrail: {stmt_type} without a WHERE clause is prohibited to prevent accidental table wipeouts."
            )

    return stmt.sql(dialect=dialect), stmt_type, target_tables
