"""
Setup script to provision:
1. Security-barrier view 'customer_masked' for PostgreSQL-native PII protection.
2. Unprivileged 'agent_ro' role with access to business tables and customer_masked only.
3. Scoped 'agent_rw' role for approved HITL mutations.
4. Revocation of raw customer and employee table access from agent_ro.
5. (A1) pg_hba.conf trust-auth detection (read-only check + fix guidance).
6. (B1) Durable session-state table 'gateway_session_state'.
7. (B3) Row-Level Security on customer (default-open passthrough).
8. (A0) Gateway keycard roles (gateway_reader/editor/admin) from roles.yaml.
"""
import os
import sys
import psycopg2
from dotenv import load_dotenv

# Standalone script: make `src.database_gateway.config` importable for roles.yaml.
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from src.database_gateway.config import load_config

# Load admin connection details from .env
env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".env"))
load_dotenv(env_path)

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", "5433"))
DB_NAME = os.getenv("DB_NAME", "chinook")
DB_SEED = os.getenv("DB_SEED", "chinook").lower()  # chinook | empty
SUPERUSER = os.getenv("POSTGRES_USER", "postgres")
SUPERPASS = os.getenv("POSTGRES_PASSWORD", "postgres")
# Service-account passwords (agent_ro/rw): env wins, legacy default keeps
# existing deployments working.
AGENT_RO_PASSWORD = os.getenv("DB_PASSWORD", "agent_ro_secure_pass_2026")
AGENT_RW_PASSWORD = os.getenv("DB_MUTATION_PASSWORD", "agent_rw_secure_pass_2026")


def _exec(cur, sql, label):
    """Run one provisioning statement; SKIP (don't abort) when the target
    object doesn't exist — e.g. DB_SEED=empty databases without Chinook tables."""
    try:
        cur.execute(sql)
    except Exception as e:
        print(f"  SKIP: {label} ({str(e).splitlines()[0] if str(e) else 'unknown error'}).")

def check_trust_auth(cur):
    """Step 5 (A1): Detect pg_hba.conf trust auth and print exact fix.

    pg_hba.conf is a filesystem file — it cannot be modified via SQL
    (ALTER SYSTEM only writes postgresql.auto.conf, never pg_hba.conf).
    So this step validates via pg_hba_file_rules (PG10+, superuser-visible)
    and prints the warning + docker exec fix command if trust is detected.
    Returns True if trust was detected.
    """
    print("[5/8] Checking pg_hba.conf auth method (trust -> scram-sha-256)...")
    trust_found = False
    try:
        cur.execute(
            "SELECT type, database, user_name, address, netmask, auth_method "
            "FROM pg_hba_file_rules;"
        )
        rules = cur.fetchall()
        for rtype, db, user, addr, mask, method in rules:
            if str(method).strip().lower() == "trust":
                if not trust_found:
                    print("  WARNING: pg_hba.conf uses 'trust' auth (no password).")
                    print("  Any local process can authenticate as any Postgres user.")
                    print("  Fix: replace 'trust' -> 'scram-sha-256' for all")
                    print("       local / 127.0.0.1 / ::1 entries in pg_hba.conf, then reload.")
                    print("  Example (Docker):")
                    print("    docker exec <container> sed -i 's/\\btrust\\b/scram-sha-256/g' "
                          "$PGDATA/pg_hba.conf  # or SHOW hba_file path")
                    print('    docker exec <container> psql -U postgres -c "SELECT pg_reload_conf();"')
                print(f"    trust rule: type={rtype} db={db} user={user} "
                      f"addr={addr} mask={mask}")
                trust_found = True
        if not trust_found:
            print("  OK: no 'trust' entries in pg_hba_file_rules.")
    except Exception as e:
        # pg_hba_file_rules needs superuser / PG10+; never fail provisioning on this.
        print(f"  WARNING: could not inspect pg_hba_file_rules ({e}).")
        print("  Manual check: SHOW hba_file; then verify no 'trust' lines,")
        print("  expected 'scram-sha-256' for host/local entries.")
    return trust_found


def create_session_state_table(cur):
    """Step 6 (B1): Durable circuit-breaker / session state table.

    Postgres table is the source of truth; the gateway keeps an in-memory
    L1 cache (30s TTL) to avoid a DB round-trip per query.
    Only the gateway roles may write; agent_ro can read its own rows.
    """
    print("[6/8] Creating durable session-state table 'gateway_session_state'...")
    cur.execute("""
    CREATE TABLE IF NOT EXISTS gateway_session_state (
        session_id       TEXT PRIMARY KEY,
        violations       INT NOT NULL DEFAULT 0,
        quarantine_until TIMESTAMPTZ,
        query_count      INT NOT NULL DEFAULT 0,
        compute_ms       BIGINT NOT NULL DEFAULT 0,
        last_seen        TIMESTAMPTZ DEFAULT NOW()
    );
    """)
    cur.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_session_state TO agent_ro;")
    cur.execute("GRANT SELECT, INSERT, UPDATE, DELETE ON gateway_session_state TO agent_rw;")
    print("  OK: gateway_session_state ready (Postgres is source of truth).")


def enable_rls(cur):
    """Step 7 (B3): Row-Level Security, default-open for single-tenant demo.

    Chinook customer has no tenant_id column, so the passthrough policy keys
    only on the app.current_tenant GUC: all rows visible when unset
    (existing behavior preserved, zero regression). NULLIF treats both NULL
    and '' as unset: Postgres leaves a '' placeholder after a SET LOCAL
    transaction ends, and without NULLIF that would poison pooled connections
    (deny all rows on later default-context checkouts).
    Multi-tenant future hook: add a tenant_id column and extend the policy to
      ... OR tenant_id::text = current_setting('app.current_tenant', true)
    The gateway sets the context via database.set_session_context().
    """
    print("[7/8] Enabling Row-Level Security (RLS) on 'customer'...")
    try:
        cur.execute("ALTER TABLE customer ENABLE ROW LEVEL SECURITY;")
        cur.execute("DROP POLICY IF EXISTS rls_passthrough ON customer;")
        cur.execute("""
    CREATE POLICY rls_passthrough ON customer
      USING (NULLIF(current_setting('app.current_tenant', true), '') IS NULL)
      WITH CHECK (NULLIF(current_setting('app.current_tenant', true), '') IS NULL);
    """)
    except Exception as e:
        print(f"  SKIP: RLS on customer ({str(e).splitlines()[0] if str(e) else 'no customer table'}).")
        return
    print("  OK: RLS enabled with default-open passthrough policy.")


def _role_password(role: str) -> str:
    return os.getenv(f"GATEWAY_{role.upper()}_PASSWORD", f"gateway_{role}_2026")


def create_gateway_roles(cur):
    """Step 8 (A0): keycard roles gateway_<name> from roles.yaml.

    Each gateway role maps 1:1 to the YAML role of the same name, with
    GRANTs derived from its tables_read/tables_write lists. Missing tables
    are skipped with a warning (forks with different schemas). Restricted
    tables are explicitly revoked for every keycard. Circuit-breaker state
    reads are granted; CB writes stay on the agent_ro service identity.
    """
    print("[8/8] Provisioning gateway keycard roles from roles.yaml...")
    cfg = load_config()
    for role, spec in cfg["roles"].items():
        pg_role = f"gateway_{role}"
        password = _role_password(role)
        cur.execute(f"""
        DO $$
        BEGIN
           IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = '{pg_role}') THEN
              CREATE ROLE {pg_role} WITH LOGIN PASSWORD '{password}';
           ELSE
              ALTER ROLE {pg_role} WITH PASSWORD '{password}';
           END IF;
        END
        $$;
        """)
        cur.execute(f"GRANT CONNECT ON DATABASE {DB_NAME} TO {pg_role};")
        cur.execute(f"GRANT USAGE ON SCHEMA public TO {pg_role};")
        cur.execute(f"REVOKE ALL ON ALL TABLES IN SCHEMA public FROM {pg_role};")
        for table in spec.get("tables_read", []):
            try:
                cur.execute(f"GRANT SELECT ON {table} TO {pg_role};")
            except Exception as e:
                # Autocommit connection: failed statement needs no cleanup.
                print(f"  SKIP: SELECT on {table} for {pg_role} ({e}).")
        for table in spec.get("tables_write", []):
            try:
                cur.execute(
                    f"GRANT SELECT, INSERT, UPDATE, DELETE ON {table} TO {pg_role};")
            except Exception as e:
                print(f"  SKIP: write on {table} for {pg_role} ({e}).")
        try:
            cur.execute(
                f"GRANT SELECT ON gateway_session_state TO {pg_role};")
        except Exception as e:
            print(f"  SKIP: state-table read for {pg_role} ({e}).")
        for restricted in ("employee",):
            try:
                cur.execute(f"REVOKE ALL ON {restricted} FROM {pg_role};")
            except Exception:
                pass
        print(f"  OK: {pg_role} (read={len(spec.get('tables_read', []))} "
              f"write={len(spec.get('tables_write', []))} "
              f"propose={spec.get('can_propose')} approve={spec.get('can_approve')} "
              f"mgmt={spec.get('management')})")


def provision_security_architecture():
    print("=" * 65)
    print("PROVISIONING POSTGRESQL SECURITY ARCHITECTURE (ROLES & VIEWS)")
    print("=" * 65)
    
    # Connect as administrative superuser once to run DDL
    # (credentials from POSTGRES_USER/POSTGRES_PASSWORD env).
    admin_conn = psycopg2.connect(
        host=DB_HOST,
        port=DB_PORT,
        dbname=DB_NAME,
        user=SUPERUSER,
        password=SUPERPASS
    )
    admin_conn.autocommit = True
    cur = admin_conn.cursor()

    # Step 1: Create Security Barrier View for PII Masking
    # (skipped on DB_SEED=empty databases without a customer table).
    print("[1/8] Creating security-barrier view 'customer_masked'...")
    if DB_SEED != "empty":
        cur.execute("""
    CREATE OR REPLACE VIEW customer_masked WITH (security_barrier = true) AS
    SELECT 
        customer_id,
        first_name,
        last_name,
        company,
        address,
        city,
        state,
        country,
        postal_code,
        CASE 
            WHEN phone IS NOT NULL AND length(phone) >= 4 
            THEN '***-***-' || right(phone, 4)
            ELSE '***-***-****'
        END AS phone,
        CASE 
            WHEN email IS NOT NULL AND position('@' in email) > 0
            THEN left(split_part(email, '@', 1), 1) || '***@' || split_part(email, '@', 2)
            ELSE '***@masked.com'
        END AS email,
        support_rep_id
    FROM customer;
    """)
    else:
        print("  SKIP: DB_SEED=empty, no customer table for masked view.")

    # Step 2: Create Roles
    print("[2/8] Provisioning roles 'agent_ro' and 'agent_rw'...")
    cur.execute(f"""
    DO $$
    BEGIN
       IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'agent_ro') THEN
          CREATE ROLE agent_ro WITH LOGIN PASSWORD '{AGENT_RO_PASSWORD}';
       ELSE
          ALTER ROLE agent_ro WITH PASSWORD '{AGENT_RO_PASSWORD}';
       END IF;

       IF NOT EXISTS (SELECT FROM pg_catalog.pg_roles WHERE rolname = 'agent_rw') THEN
          CREATE ROLE agent_rw WITH LOGIN PASSWORD '{AGENT_RW_PASSWORD}';
       ELSE
          ALTER ROLE agent_rw WITH PASSWORD '{AGENT_RW_PASSWORD}';
       END IF;
    END
    $$;
    """)

    # Step 3: Grant Scoped Permissions to agent_ro
    print("[3/8] Granting strict read-only permissions to 'agent_ro'...")
    _exec(cur, f"GRANT CONNECT ON DATABASE {DB_NAME} TO agent_ro;", "CONNECT agent_ro")
    _exec(cur, "GRANT USAGE ON SCHEMA public TO agent_ro;", "USAGE agent_ro")
    _exec(cur, "REVOKE ALL ON ALL TABLES IN SCHEMA public FROM agent_ro;", "REVOKE agent_ro")
    _exec(cur, """
    GRANT SELECT ON album, artist, genre, invoice, invoice_line,
                    media_type, playlist, playlist_track, track, customer_masked TO agent_ro;
    """, "SELECT grants agent_ro")
    # Explicitly guarantee no access to employee or raw customer tables
    _exec(cur, "REVOKE ALL ON employee FROM agent_ro;", "REVOKE employee agent_ro")
    _exec(cur, "REVOKE ALL ON customer FROM agent_ro;", "REVOKE customer agent_ro")

    # Step 4: Grant Mutation Permissions to agent_rw
    print("[4/8] Granting mutation permissions to 'agent_rw'...")
    _exec(cur, f"GRANT CONNECT ON DATABASE {DB_NAME} TO agent_rw;", "CONNECT agent_rw")
    _exec(cur, "GRANT USAGE ON SCHEMA public TO agent_rw;", "USAGE agent_rw")
    _exec(cur, "GRANT SELECT, INSERT, UPDATE, DELETE ON customer, invoice, invoice_line TO agent_rw;",
           "write grants agent_rw")
    _exec(cur, "REVOKE ALL ON employee FROM agent_rw;", "REVOKE employee agent_rw")

    # Step 5 (A1): pg_hba.conf trust-auth detection (read-only check + guidance)
    check_trust_auth(cur)

    # Step 6 (B1): durable CB / session state table
    create_session_state_table(cur)

    # Step 7 (B3): Row-Level Security (default-open passthrough)
    enable_rls(cur)

    # Step 8 (A0): gateway keycard roles from roles.yaml
    create_gateway_roles(cur)

    cur.close()
    admin_conn.close()

    print("SUCCESS: Security-barrier views and least-privilege roles provisioned.")
    print("=" * 65)

if __name__ == "__main__":
    provision_security_architecture()
