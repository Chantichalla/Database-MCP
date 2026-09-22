"""
Bounded execution engine with memory protection, query timeouts, and dynamic PII masking.
Supports PostgreSQL (with native statement_timeout) and SQLite (with opcode progress handlers).
"""
import time
import json
import re
import sqlite3
from typing import Dict, Any, List, Optional

from ..database import (
    get_read_only_connection,
    get_read_write_connection,
    is_postgres,
)

try:
    import psycopg2
    import psycopg2.errors
except ImportError:
    psycopg2 = None

DEFAULT_TIMEOUT_SECONDS = 2.0
DEFAULT_MAX_ROWS = 100
DEFAULT_MAX_BYTES = 512 * 1024  # 512 KB payload cap to protect LLM context window

# Regex patterns for dynamic PII masking
EMAIL_PATTERN = re.compile(r"^[\w\.-]+@[\w\.-]+\.\w+$")
PHONE_PATTERN = re.compile(r"^(\+?\d{1,3}[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}$")
PII_COLUMNS = {"email", "phone", "ssn", "password_hash", "token", "secret", "credit_card"}


def _normalize_col(name: str) -> str:
    """Lowercase letters only: 'E-Mail Address' -> 'emailaddress'."""
    return re.sub(r"[^a-z]", "", (name or "").lower())


# Variant-tolerant stems matched against the normalized column name, so
# real-world spellings (e_mail, mobile_no, phone-number, social_security_no)
# mask exactly like the canonical names. Curated conservatively: a stem must
# not occur inside common non-sensitive words (no bare "mail" -> "mailer",
# no bare "tel" -> "hotel", no "cell" -> "cellar"). Over-masking a rare
# word (e.g. "microphone") is accepted: safe direction for a masker.
_EMAIL_STEMS = ("email",)
_PHONE_STEMS = ("phone", "mobile", "telephone")
_SECRET_STEMS = ("token", "secret", "password", "passwd", "ssn",
                 "socialsecurity", "creditcard", "passcode")


def mask_pii_value(column_name: str, value: Any) -> Any:
    """Masks sensitive PII values based on column name or string pattern."""
    if not isinstance(value, str):
        return value

    norm = _normalize_col(column_name)
    if any(s in norm for s in _EMAIL_STEMS) or EMAIL_PATTERN.match(value):
        parts = value.split("@")
        if len(parts) == 2:
            name, domain = parts
            masked_name = name[0] + "***" + name[-1] if len(name) > 2 else "***"
            return f"{masked_name}@{domain}"
        return "***@masked.com"

    if any(s in norm for s in _PHONE_STEMS) or PHONE_PATTERN.match(value):
        digits = re.sub(r"\D", "", value)
        if len(digits) >= 4:
            return f"***-***-{digits[-4:]}"
        return "***-***-****"

    if any(s in norm for s in _SECRET_STEMS):
        return "[REDACTED_SENSITIVE]"

    return value


def execute_bounded_query(
    safe_sql: str,
    db_path: Optional[str] = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    max_rows: int = DEFAULT_MAX_ROWS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    mask_pii: bool = True
) -> Dict[str, Any]:
    """
    Executes a validated read-only SQL query with hard timeout and memory caps.

    Guarantees:
    - Hard cancellation after timeout_seconds (PostgreSQL statement_timeout / SQLite progress handler).
    - Result streaming in chunks of 25 rows to prevent server-side memory spikes.
    - Strict row count and byte size ceilings to protect LLM context windows.
    - Dynamic PII masking on sensitive fields (email, phone).
    """
    start_time = time.perf_counter()
    deadline = start_time + timeout_seconds

    with get_read_only_connection() as conn:
        cursor = conn.cursor()

        if is_postgres():
            # Enforce PostgreSQL backend statement timeout in milliseconds
            timeout_ms = max(100, int(timeout_seconds * 1000))
            cursor.execute(f"SET statement_timeout = '{timeout_ms}ms';")
            try:
                cursor.execute(safe_sql)
            except Exception as e:
                elapsed = round((time.perf_counter() - start_time) * 1000, 2)
                err_str = str(e).lower()
                if "timeout" in err_str or "canceling statement" in err_str:
                    raise TimeoutError(
                        f"Query exceeded execution deadline of {timeout_seconds:.1f}s and was terminated by PostgreSQL. "
                        f"(Elapsed: {elapsed}ms. Refine query predicates or join on indexed columns)."
                    )
                raise e
        else:
            # SQLite opcode progress handler
            def timeout_handler() -> int:
                if time.perf_counter() > deadline:
                    return 1
                return 0

            conn.set_progress_handler(timeout_handler, 100)
            try:
                cursor.execute(safe_sql)
            except sqlite3.OperationalError as e:
                if "interrupted" in str(e).lower():
                    elapsed = round((time.perf_counter() - start_time) * 1000, 2)
                    raise TimeoutError(
                        f"Query exceeded execution deadline of {timeout_seconds:.1f}s and was terminated. "
                        f"(Elapsed: {elapsed}ms. Consider refining predicates or joining on indexed columns)."
                    )
                raise e

        # Extract column headers
        col_names = [desc[0] for desc in cursor.description] if cursor.description else []

        results: List[Dict[str, Any]] = []
        accumulated_bytes = 0
        truncated = False
        truncation_reason = None

        # Chunked streaming fetch
        batch_size = 25
        while True:
            if time.perf_counter() > deadline:
                truncated = True
                truncation_reason = f"Execution interrupted: Timed out during row streaming at {timeout_seconds:.1f}s."
                break

            rows = cursor.fetchmany(batch_size)
            if not rows:
                break

            for row in rows:
                if len(results) >= max_rows:
                    truncated = True
                    truncation_reason = f"Result truncated: Reached maximum row limit ({max_rows})."
                    break

                row_dict = {}
                for col_name, val in zip(col_names, row):
                    if mask_pii:
                        val = mask_pii_value(col_name, val)
                    row_dict[col_name] = val

                row_bytes = len(json.dumps(row_dict, default=str))
                if (accumulated_bytes + row_bytes) > max_bytes:
                    truncated = True
                    truncation_reason = f"Result truncated: Exceeded maximum payload size ({max_bytes // 1024} KB)."
                    break

                results.append(row_dict)
                accumulated_bytes += row_bytes

            if truncated:
                break

        elapsed_s = time.perf_counter() - start_time
        elapsed_ms = round(elapsed_s * 1000, 2)
        try:
            from .circuit_breaker import CIRCUIT_BREAKER
            from ..config import get_active_role
            CIRCUIT_BREAKER.record_execution_time(get_active_role(), elapsed_s)
        except ImportError:
            pass

        return {
            "columns": col_names,
            "rows": results,
            "row_count": len(results),
            "payload_bytes": accumulated_bytes,
            "truncated": truncated,
            "truncation_reason": truncation_reason,
            "execution_time_ms": elapsed_ms,
        }


def execute_mutation_query(
    normalized_sql: str,
    db_path: Optional[str] = None
) -> Dict[str, Any]:
    """Executes an approved mutation query on a read-write connection."""
    start_time = time.perf_counter()
    with get_read_write_connection() as conn:
        cursor = conn.cursor()
        cursor.execute(normalized_sql)
        affected_rows = cursor.rowcount
        conn.commit()

    elapsed_ms = round((time.perf_counter() - start_time) * 1000, 2)
    return {
        "status": "SUCCESS",
        "affected_rows": affected_rows,
        "execution_time_ms": elapsed_ms
    }
