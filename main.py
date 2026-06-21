"""
PrivaVault — FastAPI entry point
Phase 1-2 | branch: feature/auth-upload

Responsibilities:
  - Boot the MySQL connection pool on startup, tear it down on shutdown
  - Register route modules (auth, upload)
  - Add CORS middleware so a browser frontend can hit the API
  - Expose a /health endpoint for quick smoke-tests
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from db.connection import init_pool, close_pool
from routes.auth import router as auth_router
from routes.upload import router as upload_router


# ---------------------------------------------------------------------------
# Lifespan — runs once on startup and once on shutdown
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    """
    FastAPI's modern replacement for @app.on_event("startup/shutdown").

    Everything BEFORE the `yield` runs at startup.
    Everything AFTER the `yield` runs at shutdown.
    """
    # --- STARTUP ---
    print("[PrivaVault] Starting up...")
    pool = init_pool()          # create the MySQL connection pool
    app.state.db_pool = pool    # attach it to app.state so routes can reach it
    print("[PrivaVault] MySQL pool ready.")

    yield  # <-- server is live and handling requests between these two points

    # --- SHUTDOWN ---
    print("[PrivaVault] Shutting down...")
    close_pool(app.state.db_pool)
    print("[PrivaVault] MySQL pool closed. Bye.")


# ---------------------------------------------------------------------------
# App instance
# ---------------------------------------------------------------------------
app = FastAPI(
    title="PrivaVault",
    description=(
        "Dual-Stream Zero-Knowledge Cloud Storage "
        "with Context-Preserving PII Anonymization for Secure GenAI Ingestion"
    ),
    version="0.1.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# CORS middleware
# ---------------------------------------------------------------------------
# During development allow all origins so you can test from Postman / localhost.
# Lock this down to your actual frontend domain before going to production.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],        # TODO: replace "*" with your frontend URL in prod
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ---------------------------------------------------------------------------
# Routers
# ---------------------------------------------------------------------------
app.include_router(auth_router,   prefix="/auth",   tags=["Auth"])
app.include_router(upload_router, prefix="/vault",  tags=["Vault"])


# ---------------------------------------------------------------------------
# Health check — the first thing you hit after `uvicorn main:app --reload`
# ---------------------------------------------------------------------------
@app.get("/health", tags=["Health"])
def health_check():
    """
    Returns 200 OK if the server is running.
    Use this to confirm the app booted correctly before touching any other route.
    """
    return {"status": "ok", "service": "PrivaVault"}