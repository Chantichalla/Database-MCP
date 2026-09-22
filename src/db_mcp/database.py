"""
Database management and connection pooling for Safe DB MCP.
Supports PostgreSQL (with live Chinook DB) and SQLite, with secrets securely loaded via .env.
"""
import os
import sqlite3
import threading
from typing import Generator, Any, Set
import contextlib

try:
    from dotenv import load_dotenv
    # Load .env from project root
    env_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env"))
    load_dotenv(env_path)
except ImportError:
    pass

try:
    import psycopg2
    import psycopg2.extras
    PSYCOPG2_AVAILABLE = True
except ImportError:
    PSYCOPG2_AVAILABLE = False

try:
    from psycopg2 import pool as _pg_pool
    _POOL_AVAILABLE = PSYCOPG2_AVAILABLE
except ImportError:
    _pg_pool = None
    _POOL_AVAILABLE = False


# Database Engine & Connection Configuration
DB_ENGINE = os.getenv("DB_ENGINE", "postgresql").lower()
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_PORT = int(os.getenv("DB_PORT", "5432"))
DB_NAME = os.getenv("DB_NAME", "chinook")
DB_USER = os.getenv("DB_USER", "postgres")
DB_PASSWORD = os.getenv("DB_PASSWORD", "postgres")
DB_SSLMODE = os.getenv("DB_SSLMODE", "prefer")

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL and DB_ENGINE == "postgresql":
    DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@{DB_HOST}:{DB_PORT}/{DB_NAME}"

# Scoped mutation credentials for approved HITL execution
DB_MUTATION_USER = os.getenv("DB_MUTATION_USER")
DB_MUTATION_PASSWORD = os.getenv("DB_MUTATION_PASSWORD")
DB_MUTATION_URL = os.getenv("DB_MUTATION_URL")

# SQLite fallback path
SQLITE_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "ecommerce.db"))


def is_postgres() -> bool:
    """Returns True if the gateway is configured to use PostgreSQL."""
    return DB_ENGINE in ("postgres", "postgresql") and PSYCOPG2_AVAILABLE


def get_postgres_connection_params() -> dict:
    """Returns connection parameters sanitized for psycopg2 (read-only role)."""
    if DATABASE_URL:
        return {"dsn": DATABASE_URL}
    return {
        "host": DB_HOST,
        "port": DB_PORT,
        "dbname": DB_NAME,
        "user": DB_USER,
        "password": DB_PASSWORD,
        "sslmode": DB_SSLMODE,
    }


def get_postgres_mutation_params() -> dict:
    """Returns connection parameters for approved mutation operations (agent_rw role)."""
    if DB_MUTATION_URL:
        return {"dsn": DB_MUTATION_URL}
    if DB_MUTATION_USER and DB_MUTATION_PASSWORD:
        return {
            "host": DB_HOST,
            "port": DB_PORT,
            "dbname": DB_NAME,
            "user": DB_MUTATION_USER,
            "password": DB_MUTATION_PASSWORD,
            "sslmode": DB_SSLMODE,
        }
    return get_postgres_connection_params()


# ── A0: per-keycard Postgres credentials ──────────────────────────────────
# Each gateway role connects as its own Postgres role (gateway_<name>,
# provisioned by setup_roles.py from roles.yaml). Passwords come from env
# (GATEWAY_<ROLE>_PASSWORD) so forks never hardcode them; defaults match
# setup_roles.py defaults for zero-config demo. Unknown roles fail closed
# to the reader physical role (least privilege).


def pg_user_for_role(role: str) -> str:
    """Postgres role for a gateway role; unknown roles map to gateway_reader."""
    from .config import load_config
    if role in load_config()["roles"]:
        return f"gateway_{role}"
    return "gateway_reader"


def _role_password(role: str) -> str:
    return os.getenv(f"GATEWAY_{role.upper()}_PASSWORD", f"gateway_{role}_2026")


def get_role_ro_params(role: str) -> dict:
    """Read-connection params for a gateway role (its own Postgres role)."""
    return {
        "host": DB_HOST,
        "port": DB_PORT,
        "dbname": DB_NAME,
        "user": pg_user_for_role(role),
        "password": _role_password(role if pg_user_for_role(role) == f"gateway_{role}" else "reader"),
        "sslmode": DB_SSLMODE,
    }


def get_role_rw_params(role: str) -> dict:
    """Write-connection params. Only approver roles get them (fail-closed).

    Note editor (can_propose, no can_approve) has no RW connection: proposing
    uses a read-only EXPLAIN, and apply_mutation is tool-gated to approvers.
    """
    from .config import get_role_spec
    if not get_role_spec(role)["can_approve"]:
        raise RuntimeError(
            f"Role '{role}' has no write credentials (fail-closed).")
    return get_role_ro_params(role)


# Allowed business tables vs restricted internal tables
if is_postgres():
    ALLOWED_BUSINESS_TABLES: Set[str] = {
        "album",
        "artist",
        "customer",
        "customer_masked",
        "genre",
        "invoice",
        "invoice_line",
        "media_type",
        "playlist",
        "playlist_track",
        "track"
    }
    RESTRICTED_TABLES: Set[str] = {"employee"}
else:
    ALLOWED_BUSINESS_TABLES: Set[str] = {"products", "orders", "customers"}
    RESTRICTED_TABLES: Set[str] = {"salaries", "admin_tokens"}


@contextlib.contextmanager
def get_read_only_connection() -> Generator[Any, None, None]:
    """
    Opens a strict read-only database connection (pooled on Postgres).
    - PostgreSQL: checks out from ThreadedConnectionPool (max 5), sets
      session readonly=True. The engine rejects any mutation.
    - SQLite: Opens URI with mode=ro.
    """
    if is_postgres():
        conn = _borrow_ro_conn()
        # Hard engine-level guarantee: set session to read-only
        conn.set_session(readonly=True, autocommit=False)
        try:
            yield conn
        finally:
            _return_ro_conn(conn)
    else:
        uri = f"file:{SQLITE_DB_PATH}?mode=ro"
        conn = sqlite3.connect(uri, uri=True, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()


# Plan-compatible aliases
get_ro_connection = get_read_only_connection


def release_connection(conn) -> None:
    """Return a read-only pooled connection (no-op for SQLite)."""
    if is_postgres():
        _return_ro_conn(conn)
    else:
        try:
            conn.close()
        except Exception:
            pass


# ── B2: connection pools (lazy, thread-safe) ──────────────────────────────
# A0: pools are keyed by (kind, gateway-role) so each keycard gets its own
# connections. _CHECKED_OUT maps id(conn) -> pool key for correct return.
_POOLS = {}
_CHECKED_OUT = {}
_POOL_LOCK = threading.Lock()


def _pool_key(kind: str, role: str) -> tuple:
    return (kind, role)


def _get_or_create_pool(kind: str, role: str, params: dict):
    key = _pool_key(kind, role)
    pool = _POOLS.get(key)
    if pool is not None:
        return pool
    with _POOL_LOCK:
        pool = _POOLS.get(key)
        if pool is None:
            pool = _pg_pool.ThreadedConnectionPool(
                minconn=1, maxconn=5, **params
            )
            _POOLS[key] = pool
    return pool


def _borrow_pooled(kind: str, role: str, params: dict):
    """Check out a connection, remembering its pool. Direct-connect fallback."""
    if _POOL_AVAILABLE:
        try:
            pool = _get_or_create_pool(kind, role, params)
            conn = pool.getconn()
            with _POOL_LOCK:
                _CHECKED_OUT[id(conn)] = _pool_key(kind, role)
            return conn
        except Exception:
            pass
    return psycopg2.connect(**params)


def _return_pooled(conn) -> None:
    """Return a connection to its home pool (rollback first)."""
    with _POOL_LOCK:
        key = _CHECKED_OUT.pop(id(conn), None)
        pool = _POOLS.get(key) if key else None
    if _POOL_AVAILABLE and pool is not None:
        try:
            try:
                conn.rollback()
            except Exception:
                pass
            if getattr(conn, "closed", 0) != 0:
                pool.putconn(conn, close=True)
            else:
                pool.putconn(conn)
            return
        except Exception:
            pass
    try:
        conn.close()
    except Exception:
        pass


def _get_or_create_ro_pool(role: str = "reader"):
    return _get_or_create_pool("ro", role, get_role_ro_params(role))


def _get_or_create_rw_pool(role: str = "editor"):
    return _get_or_create_pool("rw", role, get_role_rw_params(role))


def _borrow_ro_conn():
    from .config import get_active_role
    role = get_active_role()
    return _borrow_pooled("ro", role, get_role_ro_params(role))


def _return_ro_conn(conn) -> None:
    _return_pooled(conn)


def _borrow_rw_conn():
    from .config import get_active_role
    role = get_active_role()
    return _borrow_pooled("rw", role, get_role_rw_params(role))


def _return_rw_conn(conn) -> None:
    _return_pooled(conn)


def close_pools() -> None:
    """Close all pooled connections (tests / shutdown)."""
    with _POOL_LOCK:
        pools = list(_POOLS.values())
        _POOLS.clear()
        _CHECKED_OUT.clear()
    for p in pools:
        try:
            p.closeall()
        except Exception:
            pass


def set_session_context(conn, tenant_id: str) -> None:
    """B3: bind the current transaction to a tenant for RLS.

    Issues SET LOCAL app.current_tenant = '...' so the
    rls_passthrough policy isolates rows at the DB layer.
    Transaction-scoped: auto-reset on commit/rollback (pool-safe).
    No-op on SQLite. Empty tenant_id issues RESET to clear any
    leftover '' placeholder on reused pooled connections.
    """
    if not is_postgres():
        return
    cur = conn.cursor()
    try:
        if tenant_id:
            cur.execute("SELECT set_config('app.current_tenant', %s, true)",
                        (str(tenant_id),))
        else:
            cur.execute("RESET app.current_tenant")
    finally:
        cur.close()


@contextlib.contextmanager
def get_read_write_connection() -> Generator[Any, None, None]:
    """
    Opens a read-write database connection exclusively for approved Human-in-the-Loop mutations.
    """
    if is_postgres():
        conn = _borrow_rw_conn()
        conn.set_session(readonly=False, autocommit=False)
        try:
            yield conn
        finally:
            _return_rw_conn(conn)
    else:
        conn = sqlite3.connect(SQLITE_DB_PATH, timeout=5.0)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
        finally:
            conn.close()


def initialize_database(db_path: str = SQLITE_DB_PATH) -> None:
    """Initializes SQLite seed database if running in SQLite fallback mode."""
    if is_postgres():
        return  # PostgreSQL is externally managed (e.g. Docker Chinook DB)

    if os.path.exists(db_path):
        try:
            os.remove(db_path)
        except OSError:
            pass

    conn = sqlite3.connect(db_path)
    cur = conn.cursor()

    cur.execute("""
    CREATE TABLE IF NOT EXISTS products (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        category TEXT NOT NULL,
        price REAL NOT NULL,
        stock_quantity INTEGER NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        email TEXT NOT NULL,
        phone TEXT NOT NULL,
        loyalty_tier TEXT DEFAULT 'Standard'
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_id INTEGER NOT NULL,
        product_id INTEGER NOT NULL,
        quantity INTEGER NOT NULL,
        total_amount REAL NOT NULL,
        status TEXT NOT NULL,
        order_date TEXT DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (customer_id) REFERENCES customers(id),
        FOREIGN KEY (product_id) REFERENCES products(id)
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS salaries (
        employee_id INTEGER PRIMARY KEY,
        employee_name TEXT NOT NULL,
        department TEXT NOT NULL,
        base_salary REAL NOT NULL,
        bonus REAL NOT NULL
    );
    """)

    cur.execute("""
    CREATE TABLE IF NOT EXISTS admin_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        service_name TEXT NOT NULL,
        token_hash TEXT NOT NULL,
        access_level TEXT NOT NULL
    );
    """)

    products_data = [
        (f"Product {i}", ["Electronics", "Books", "Apparel", "Home"][i % 4], round(19.99 + (i * 3.5), 2), 50 + (i * 2))
        for i in range(1, 101)
    ]
    cur.executemany("INSERT INTO products (name, category, price, stock_quantity) VALUES (?, ?, ?, ?)", products_data)

    customers_data = [
        (f"Customer {i}", f"customer_{i}@example.com", f"+1-555-01{i:02d}", "Gold" if i % 5 == 0 else "Standard")
        for i in range(1, 51)
    ]
    cur.executemany("INSERT INTO customers (name, email, phone, loyalty_tier) VALUES (?, ?, ?, ?)", customers_data)

    orders_data = [
        ((i % 50) + 1, (i % 100) + 1, (i % 3) + 1, round(45.0 + (i * 5.2), 2), "Completed" if i % 2 == 0 else "Pending")
        for i in range(1, 151)
    ]
    cur.executemany("INSERT INTO orders (customer_id, product_id, quantity, total_amount, status) VALUES (?, ?, ?, ?, ?)", orders_data)

    salaries_data = [
        (101, "Alice Smith", "Engineering", 160000.0, 25000.0),
        (102, "Bob Jones", "Executive", 250000.0, 75000.0),
        (103, "Carol White", "Marketing", 110000.0, 12000.0),
    ]
    cur.executemany("INSERT INTO salaries VALUES (?, ?, ?, ?, ?)", salaries_data)

    tokens_data = [
        ("prod-auth-gateway", "sha256:e3b0c44298fc1c149afbf4c8996fb924", "SUPERADMIN"),
        ("billing-webhook", "sha256:ca978112ca1bbdcafac231b39a23dc4d", "SERVICE_ROLE"),
    ]
    cur.executemany("INSERT INTO admin_tokens (service_name, token_hash, access_level) VALUES (?, ?, ?)", tokens_data)

    conn.commit()
    conn.close()
