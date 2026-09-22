# Scaling: deferred concurrency hardening

## Status

Documented, **not fixed**. Correct for single-agent stdio traffic today;
mandatory before any HTTP / multi-agent milestone.

## Verified facts

- The MCP framework can dispatch tool calls on concurrent worker threads —
  nothing stops two tool calls from running at the same time.
- The `psycopg2` connection pool (`ThreadedConnectionPool`) is thread-safe:
  concurrent queries each get their own connection. This part holds.
- All shared in-memory state is **unlocked**. The only lock in the codebase
  guards pool creation. Affected state:
  - circuit-breaker violation counters, quarantine flags, rate-limit windows,
    compute-budget history (`SecurityCircuitBreaker` dicts),
  - the pending-approvals store (`PENDING_PROPOSALS`),
  - L1-cache bookkeeping (`_l1_loaded_at`, `_restored`).
- Failure mode is silent miscounting (read-then-write races: lost violations,
  quota overruns, replay-window drift) — worse than crashing for a security
  tool, because nothing visibly breaks.

## Why deferred

- Single-agent stdio traffic is effectively sequential (agentic loops wait on
  each result before deciding the next step).
- Queries finish in milliseconds under a 2s hard cap — parallel dispatch
  saves milliseconds, not seconds. No meaningful speed gain today.
- Fixing it now buys correctness risk reduction for traffic that does not
  exist yet, while every fix must be re-verified under the future transport.

## Trigger to fix

HTTP/SSE transport, or any second concurrent client (second agent, live
monitoring poller, background job) hitting the gateway.

## Fix sketch (when triggered)

1. Add locks around circuit-breaker state mutations — or move hot state
   behind the existing `gateway_session_state` Postgres table with atomic
   `UPDATE ... SET violations = violations + 1`-style statements.
2. Guard the proposals store (lock, or key-scoped atomic operations).
3. Load-test with parallel clients asserting: 3-strikes trips exactly once,
   rate limits hold under contention, no replay acceptance.
4. Re-run the full suite plus a new concurrency stress test.
5. Explicitly NOT fixed by migrating to async drivers — the bottleneck is
   shared-state locking, not the database driver.
