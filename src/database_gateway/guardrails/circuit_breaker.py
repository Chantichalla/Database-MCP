"""
Circuit breaker, rate limiter, and cumulative compute budget governor for Safe DB MCP.
Protects backend database from brute-force attacks, runaway loops, and sustained micro-DoS.

B1 durability: violation counts + quarantine state are write-through persisted to the
Postgres gateway_session_state table (source of truth). In-memory dicts remain as a
30s-TTL L1 cache so steady-state queries cost no extra DB round-trip. A process
restart (or reconnect) reloads state from Postgres, so the 3-strikes protection
cannot be bypassed by reconnecting. All DB I/O is best-effort: any failure falls
back to memory-only behavior and never breaks query execution.
"""
import time
from typing import Dict, List, Tuple, Set, Optional


class CircuitBreakerError(Exception):
    """Raised when the gateway circuit is tripped due to excessive security violations."""
    pass


class RateLimitExceededError(Exception):
    """Raised when a session exceeds the query rate limit or cumulative compute budget."""
    pass


# B1: durable-state settings
_STATE_TABLE = "gateway_session_state"
_L1_TTL_SECONDS = 30.0


def _fetch_db_state(session_id: str) -> Optional[Tuple[int, Optional[float]]]:
    """Load (violations, quarantine_until_epoch|None) from Postgres. None on any failure."""
    try:
        from ..database import get_postgres_connection_params, is_postgres
        if not is_postgres():
            return None
        import psycopg2
        conn = psycopg2.connect(**get_postgres_connection_params())
        try:
            cur = conn.cursor()
            try:
                cur.execute(
                    f"SELECT violations, EXTRACT(EPOCH FROM quarantine_until) "
                    f"FROM {_STATE_TABLE} WHERE session_id = %s;",
                    (session_id,),
                )
                row = cur.fetchone()
            finally:
                cur.close()
        finally:
            conn.close()
        if row is None:
            return None
        violations, q_epoch = row
        return (int(violations or 0),
                float(q_epoch) if q_epoch is not None else None)
    except Exception:
        return None


def _store_db_state(session_id: str, violations: int,
                    quarantine_until_epoch: Optional[float]) -> None:
    """Best-effort UPSERT of CB state. Never raises."""
    try:
        from ..database import get_postgres_connection_params, is_postgres
        if not is_postgres():
            return
        import psycopg2
        conn = psycopg2.connect(**get_postgres_connection_params())
        try:
            conn.autocommit = True
            cur = conn.cursor()
            try:
                cur.execute(
                    f"INSERT INTO {_STATE_TABLE} "
                    f"(session_id, violations, quarantine_until, last_seen) "
                    f"VALUES (%s, %s, to_timestamp(%s), NOW()) "
                    f"ON CONFLICT (session_id) DO UPDATE SET "
                    f"violations = EXCLUDED.violations, "
                    f"quarantine_until = EXCLUDED.quarantine_until, "
                    f"last_seen = NOW();",
                    (session_id, int(violations), quarantine_until_epoch),
                )
            finally:
                cur.close()
        finally:
            conn.close()
    except Exception:
        pass


def _delete_db_state(session_id: str) -> None:
    """Best-effort delete of a session row (test reset). Never raises."""
    try:
        from ..database import get_postgres_connection_params, is_postgres
        if not is_postgres():
            return
        import psycopg2
        conn = psycopg2.connect(**get_postgres_connection_params())
        try:
            conn.autocommit = True
            cur = conn.cursor()
            try:
                cur.execute(
                    f"DELETE FROM {_STATE_TABLE} WHERE session_id = %s;",
                    (session_id,),
                )
            finally:
                cur.close()
        finally:
            conn.close()
    except Exception:
        pass


class SecurityCircuitBreaker:
    def __init__(
        self,
        max_violations: int = 3,
        violation_window_seconds: float = 300.0,    # 5 minutes
        quarantine_duration_seconds: float = 900.0, # 15 minutes
        max_queries_per_minute: int = 30,
        max_compute_seconds: float = 15.0,          # 15s DB time per 10 minutes
        compute_window_seconds: float = 600.0       # 10 minutes
    ):
        self.max_violations = max_violations
        self.violation_window_seconds = violation_window_seconds
        self.quarantine_duration_seconds = quarantine_duration_seconds
        self.max_queries_per_minute = max_queries_per_minute
        self.max_compute_seconds = max_compute_seconds
        self.compute_window_seconds = compute_window_seconds

        # session_id -> list of violation timestamps
        self._violations: Dict[str, List[float]] = {}
        # session_id -> quarantine_expiry_timestamp
        self._quarantines: Dict[str, float] = {}
        # session_id -> list of query timestamps
        self._query_timestamps: Dict[str, List[float]] = {}
        # session_id -> list of (timestamp, duration_seconds)
        self._compute_history: Dict[str, List[Tuple[float, float]]] = {}
        # B1: L1-cache bookkeeping for durable state
        self._l1_loaded_at: Dict[str, float] = {}
        self._restored: Set[str] = set()

    def _sync_from_db(self, session_id: str = "default") -> None:
        """Refresh L1 from Postgres if stale/missing. Merges conservatively (max wins)."""
        now = time.time()
        last = self._l1_loaded_at.get(session_id, 0.0)
        if session_id in self._restored and (now - last) < _L1_TTL_SECONDS:
            return
        row = _fetch_db_state(session_id)
        self._l1_loaded_at[session_id] = now
        self._restored.add(session_id)
        if row is None:
            return
        db_violations, db_q_until = row
        mem = [t for t in self._violations.get(session_id, [])
               if (now - t) < self.violation_window_seconds]
        if db_violations > len(mem):
            # Pad with now-timestamps (conservative: counts toward threshold).
            mem = (mem + [now] * (db_violations - len(mem)))[-self.max_violations * 2:]
            self._violations[session_id] = mem
        if db_q_until is not None and db_q_until > now:
            if db_q_until > self._quarantines.get(session_id, 0.0):
                self._quarantines[session_id] = db_q_until

    def _persist_to_db(self, session_id: str = "default") -> None:
        """Write-through persist of violations + quarantine. Best-effort."""
        now = time.time()
        violations = [t for t in self._violations.get(session_id, [])
                      if (now - t) < self.violation_window_seconds]
        q_until = self._quarantines.get(session_id)
        if q_until is not None and q_until <= now:
            q_until = None
        _store_db_state(session_id, len(violations), q_until)

    def reset_session(self, session_id: str = "default") -> None:
        """Clear memory + L1 + durable row (used by tests). Best-effort on DB."""
        self._violations.pop(session_id, None)
        self._quarantines.pop(session_id, None)
        self._query_timestamps.pop(session_id, None)
        self._compute_history.pop(session_id, None)
        self._l1_loaded_at.pop(session_id, None)
        self._restored.discard(session_id)
        _delete_db_state(session_id)

    def _raise_if_quarantined(self, session_id: str = "default") -> None:
        """Quarantine gate only (writes). Syncs durable state, then enforces."""
        self._sync_from_db(session_id)
        now = time.time()
        quarantine_expiry = self._quarantines.get(session_id)
        if quarantine_expiry and now < quarantine_expiry:
            remaining = int(quarantine_expiry - now)
            raise CircuitBreakerError(
                f"GATEWAY_CIRCUIT_TRIPPED: Session quarantined due to {self.max_violations} "
                f"consecutive security policy violations. Cooldown active for another {remaining}s."
            )
        elif quarantine_expiry and now >= quarantine_expiry:
            # Quarantine expired, reset
            del self._quarantines[session_id]
            self._violations[session_id] = []
            self._persist_to_db(session_id)

    def check_allowed(self, session_id: str = "default") -> None:
        """Full gate for writes: quarantine + rate limit + compute budget."""
        self._raise_if_quarantined(session_id)
        now = time.time()

        # 2. Check Query Rate Limit (Queries per minute)
        timestamps = self._query_timestamps.get(session_id, [])
        # Prune older than 60s
        timestamps = [t for t in timestamps if (now - t) < 60.0]
        self._query_timestamps[session_id] = timestamps

        if len(timestamps) >= self.max_queries_per_minute:
            raise RateLimitExceededError(
                f"RATE_LIMIT_EXCEEDED: Session exceeded maximum rate of {self.max_queries_per_minute} queries/minute. "
                "Please throttle requests."
            )

        # 3. Check Cumulative Compute Budget
        compute_records = self._compute_history.get(session_id, [])
        # Prune older than compute_window_seconds
        compute_records = [(t, d) for t, d in compute_records if (now - t) < self.compute_window_seconds]
        self._compute_history[session_id] = compute_records

        total_compute = sum(d for _, d in compute_records)
        if total_compute >= self.max_compute_seconds:
            raise RateLimitExceededError(
                f"COMPUTE_BUDGET_EXHAUSTED: Session consumed {total_compute:.2f}s of database execution time "
                f"(limit: {self.max_compute_seconds:.1f}s per {int(self.compute_window_seconds/60)}m window). Throttling active."
            )

    def check_read_allowed(self, session_id: str = "default") -> None:
        """Throttle-only gate for reads: rate limit + compute budget, NO quarantine.

        Reads are harmless-by-construction (read-only role, AST whitelist, row
        caps, statement timeout), so a quarantine must not kill legitimate
        reads or monitoring. Violations still accumulate via record_violation
        and gate future *writes* through check_allowed.
        """
        now = time.time()
        timestamps = self._query_timestamps.get(session_id, [])
        timestamps = [t for t in timestamps if (now - t) < 60.0]
        self._query_timestamps[session_id] = timestamps

        if len(timestamps) >= self.max_queries_per_minute:
            raise RateLimitExceededError(
                f"RATE_LIMIT_EXCEEDED: Session exceeded maximum rate of {self.max_queries_per_minute} queries/minute. "
                "Please throttle requests."
            )

        compute_records = self._compute_history.get(session_id, [])
        compute_records = [(t, d) for t, d in compute_records if (now - t) < self.compute_window_seconds]
        self._compute_history[session_id] = compute_records

        total_compute = sum(d for _, d in compute_records)
        if total_compute >= self.max_compute_seconds:
            raise RateLimitExceededError(
                f"COMPUTE_BUDGET_EXHAUSTED: Session consumed {total_compute:.2f}s of database execution time "
                f"(limit: {self.max_compute_seconds:.1f}s per {int(self.compute_window_seconds/60)}m window). Throttling active."
            )

    def record_query_start(self, session_id: str = "default") -> None:
        """Records the timestamp of an initiated query."""
        now = time.time()
        self._query_timestamps.setdefault(session_id, []).append(now)

    def record_execution_time(self, session_id: str = "default", duration_seconds: float = 0.0) -> None:
        """Tracks the database execution compute time consumed by a query."""
        now = time.time()
        self._compute_history.setdefault(session_id, []).append((now, duration_seconds))

    def record_violation(self, session_id: str = "default", reason: str = "") -> bool:
        """
        Records a security violation. If threshold is reached, trips the circuit breaker.
        Returns True if the circuit was tripped.
        """
        now = time.time()
        violations = self._violations.get(session_id, [])
        # Prune old violations outside the sliding window
        violations = [t for t in violations if (now - t) < self.violation_window_seconds]
        violations.append(now)
        self._violations[session_id] = violations

        if len(violations) >= self.max_violations:
            self._quarantines[session_id] = now + self.quarantine_duration_seconds
            self._persist_to_db(session_id)
            return True
        self._persist_to_db(session_id)
        return False

    def get_status(self, session_id: str = "default") -> dict:
        """Returns the current health and quota status for a session."""
        now = time.time()
        quarantine_expiry = self._quarantines.get(session_id, 0)
        is_quarantined = now < quarantine_expiry

        recent_violations = [t for t in self._violations.get(session_id, []) if (now - t) < self.violation_window_seconds]
        recent_queries = [t for t in self._query_timestamps.get(session_id, []) if (now - t) < 60.0]
        compute_records = [d for t, d in self._compute_history.get(session_id, []) if (now - t) < self.compute_window_seconds]

        return {
            "is_quarantined": is_quarantined,
            "quarantine_remaining_seconds": max(0, int(quarantine_expiry - now)) if is_quarantined else 0,
            "violations_in_window": len(recent_violations),
            "max_violations_threshold": self.max_violations,
            "queries_last_minute": len(recent_queries),
            "max_queries_per_minute": self.max_queries_per_minute,
            "compute_seconds_consumed": round(sum(compute_records), 3),
            "max_compute_budget_seconds": self.max_compute_seconds
        }


# Global singleton instance for the MCP server process
CIRCUIT_BREAKER = SecurityCircuitBreaker()
