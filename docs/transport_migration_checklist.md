# Transport Migration Checklist: stdio → HTTP/SSE

Moving the gateway from stdio to HTTP/SSE substantially changes the threat
model (network-reachable, concurrent, multi-client). Verify every item below
before exposing the gateway on a socket.

## 1. TLS (required, no self-signed in prod)
- [ ] Terminate TLS with a proper certificate (ACM / Let's Encrypt / internal CA).
- [ ] Enforce TLS 1.2+, redirect or refuse plaintext HTTP.
- [ ] Confirm `DB_SSLMODE` is `verify-full` (or at minimum `require`) for
      Postgres connections — `prefer` is only acceptable for local Docker dev.

## 2. Authentication & session context (per request)
- [ ] Require a per-request bearer credential (JWT or mTLS client cert) on
      every MCP endpoint — stdio inherits OS process identity, HTTP does not.
- [ ] Map the verified identity to a `session_id` (never trust a client-sent
      session id blindly) and wire it into `SET LOCAL app.current_tenant`
      via `database.set_session_context()` so RLS isolates tenants.
- [ ] Keep `OPERATOR_APPROVAL_SECRET` server-side only; re-verify it on
      `apply_mutation` (already enforced) and rotate it independently of
      transport credentials.

## 3. Orphaned transactions on client disconnect
- [ ] Server-side `statement_timeout` is already set per query
      (`executor.execute_bounded_query`, default 2.0s) — confirm it still
      applies on the HTTP worker path.
- [ ] On SSE disconnect, roll back the open transaction and return the pooled
      connection (`database._return_ro_conn` rolls back before `putconn`).
- [ ] Load-test abrupt disconnects; assert `pg_stat_activity` shows no idle-in-
      transaction growth.

## 4. Sticky sessions — NOT required
- [ ] Circuit-breaker state is durable (B1: `gateway_session_state` Postgres
      table is the source of truth, 30s L1 cache). Any replica/worker sees the
      same quarantine state, so no load-balancer affinity is needed.
- [ ] HMAC proposal tokens (A2) are process-local (`TOKEN_SECRET` generated at
      startup): either share the secret across replicas via env/secret manager
      or keep propose→apply affinity. Recommended: move `TOKEN_SECRET` to a
      shared secret when running >1 replica.

## 5. Health probes
- [ ] `get_gateway_health` already exists — expose it as the load-balancer
      `/health` endpoint (200 HEALTHY, 429/503 when QUARANTINED).
- [ ] Alert on `ALERT [CIRCUIT_BREAKER_TRIP ...]` stderr lines (B4) in
      Datadog / CloudWatch / Splunk.

## 6. Pre-migration verification
- [ ] `scripts/setup_roles.py` reports no `trust` auth (A1) on the reachable
      Postgres — HTTP exposure with `trust` auth is a straight compromise.
- [ ] `audit.log` JSON-lines ingest verified in the SIEM (A3/B4).
- [ ] Connection pool ceiling (`maxconn=5`, B2) sized against Postgres
      `max_connections` × replica count; verify via `pg_stat_activity`.
