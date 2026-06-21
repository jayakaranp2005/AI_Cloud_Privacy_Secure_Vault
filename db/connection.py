"""
PrivaVault — MySQL connection pool
Phase 1-2 | branch: feature/auth-upload

Responsibilities:
  - Read DB credentials from environment variables
  - Create a pool of reusable MySQL connections on startup
  - Give routes a clean context manager to borrow + return connections
  - Tear down gracefully on shutdown

Why a pool and not one connection per request?
  Opening a TCP connection to MySQL takes ~5–15ms. Under any real load,
  doing that on every request kills throughput. A pool keeps N connections
  alive and hands them out in < 1ms. We use pool_size=5 — enough for
  concurrent uploads without exhausting the B2s VM's RAM.
"""

import os
from contextlib import contextmanager

import mysql.connector
from mysql.connector import pooling
from dotenv import load_dotenv  

# Load .env so credentials are available as environment variables.
# In production on the Azure VM, you'd export these in the shell instead —
# load_dotenv() is a no-op if no .env file is present, so it's safe either way.
load_dotenv()


# ---------------------------------------------------------------------------
# Pool factory — called once in main.py lifespan startup
# ---------------------------------------------------------------------------
def init_pool() -> pooling.MySQLConnectionPool:
    """
    Reads DB config from env vars and returns a live connection pool.

    The pool_name is just a label for mysql-connector's internal registry —
    pick any string, it doesn't affect behaviour.
    pool_size=5 means up to 5 concurrent DB operations before new callers
    block and wait for a connection to free up.
    """
    pool = pooling.MySQLConnectionPool(
        pool_name="privavault_pool",
        pool_size=5,
        pool_reset_session=True,   # cleans session state when conn returns to pool
        host=os.getenv("MYSQL_HOST", "127.0.0.1"),
        user=os.getenv("MYSQL_USER"),
        password=os.getenv("MYSQL_PASSWORD"),
        database=os.getenv("MYSQL_DATABASE"),
        charset="utf8mb4",         # full Unicode — handles Devanagari, emoji, etc.
        collation="utf8mb4_unicode_ci",
    )
    return pool


# ---------------------------------------------------------------------------
# Pool teardown — called once in main.py lifespan shutdown
# ---------------------------------------------------------------------------
def close_pool(pool: pooling.MySQLConnectionPool) -> None:
    """
    mysql-connector-python has no pool.close() method — the pool lives
    until Python's GC collects it. What we CAN do is forcibly close every
    idle connection sitting in the pool right now.

    This prevents the 'Aborted connection' warnings MySQL logs when the
    process exits with open sockets.
    """
    try:
        # Drain all idle connections from the pool and close each one.
        # _cnx_queue is an internal deque — not public API, but it's the
        # only reliable way to reach idle connections before GC does.
        while not pool._cnx_queue.empty():
            cnx = pool._cnx_queue.get_nowait()
            try:
                cnx.close()
            except Exception:
                pass  # already dead — fine
    except Exception as e:
        # Don't crash shutdown over a pool teardown error
        print(f"[PrivaVault] Warning: pool teardown issue: {e}")


# ---------------------------------------------------------------------------
# Per-request connection helper — used inside every route
# ---------------------------------------------------------------------------
@contextmanager
def get_db(pool: pooling.MySQLConnectionPool):
    """
    Context manager that borrows a connection from the pool, yields it to
    the caller, then returns it cleanly whether the route succeeded or crashed.

    Usage in a route:
        with get_db(request.app.state.db_pool) as conn:
            cursor = conn.cursor(dictionary=True)
            cursor.execute("SELECT ...")
            rows = cursor.fetchall()
            cursor.close()

    Why dictionary=True?
        Rows come back as {"email": "x", "user_id": 1} instead of ("x", 1).
        Much safer — column order in SQL queries can shift during refactors.

    Commit/rollback:
        The caller is responsible for conn.commit().
        If an exception bubbles out of the `with` block, this manager
        rolls back automatically so you never leave MySQL in a dirty state.
    """
    conn = pool.get_connection()
    try:
        yield conn
        # If the caller forgot to commit, we don't auto-commit here —
        # that would silently swallow bugs. The route must be explicit.
    except Exception:
        conn.rollback()  # undo any partial writes before returning conn to pool
        raise            # re-raise so FastAPI still returns the right HTTP error
    finally:
        conn.close()     # does NOT destroy the connection — returns it to the pool


print("[PrivaVault] MySQL connection pool initialized.")