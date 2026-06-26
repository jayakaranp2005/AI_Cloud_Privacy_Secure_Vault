"""
PrivaVault — Auth routes
Phase 1-2 | branch: feature/auth-upload

Endpoints:
  POST /auth/register  →  creates account, stores BCrypt hash + PBKDF2 salt
  POST /auth/login     →  verifies identity, returns JWT

Also exports:
  verify_token(token)  →  used by upload.py and download.py for JWT checks
"""

import os
import secrets
from datetime import datetime, timedelta, timezone

import bcrypt
import jwt
from dotenv import load_dotenv
from fastapi import APIRouter, HTTPException, Request, status

from db.connection import get_db
from models.schemas import RegisterRequest, RegisterResponse, LoginRequest, LoginResponse

load_dotenv()

JWT_SECRET  = os.getenv("JWT_SECRET_KEY")
JWT_EXPIRY  = int(os.getenv("JWT_EXPIRY_HOURS", 24))
JWT_ALG     = "HS256"

router = APIRouter()



# ---------------------------------------------------------------------------
# Shared JWT verifier — imported by upload.py and download.py
# ---------------------------------------------------------------------------
def verify_token(token: str) -> int:
    """
    Decodes and validates a JWT. Returns the user_id on success.
    Raises HTTP 401 on any failure (expired, tampered, missing).

    Called at the top of every protected route — upload and download
    both run this before touching any data.
    """
    if not JWT_SECRET:
        raise RuntimeError("JWT_SECRET_KEY not set in environment")
    try:
        payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALG])
        return int(payload["user_id"])
    except jwt.ExpiredSignatureError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token expired — please log in again"
        )
    except jwt.InvalidTokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token"
        )


# ---------------------------------------------------------------------------
# POST /auth/register
# ---------------------------------------------------------------------------
@router.post("/register", status_code=status.HTTP_201_CREATED, response_model=RegisterResponse)
def register(body: RegisterRequest, request: Request):
    """
    Registration flow:
      1. Check email is not already taken
      2. BCrypt hash the password  ─┐ both written to DB
      3. Generate random PBKDF2 salt ┘ in the same INSERT
      4. Raw password leaves scope (Python GC handles it)
      5. Log REGISTER action to access_logs
      6. Return 201

    The PBKDF2 salt is NOT used here — it is stored now so that
    upload and download can re-derive the wrapping key later without
    us ever storing the actual key anywhere.
    """
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)

        # 1. Duplicate email check
        cursor.execute(
            "SELECT user_id FROM users WHERE email = %s",
            (body.email,)
        )
        if cursor.fetchone():
            cursor.close()
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="An account with this email already exists"
            )

        # 2. BCrypt hash — gensalt() picks a random salt internally (cost factor 12)
        password_hash = bcrypt.hashpw(
            body.password.encode("utf-8"),
            bcrypt.gensalt(rounds=12)
        ).decode("utf-8")

        # 3. PBKDF2 salt — 32 bytes of randomness, stored as 64-char hex string
        #    This is a SEPARATE salt from BCrypt's internal salt.
        #    BCrypt salt  →  verifying who you are (identity check)
        #    PBKDF2 salt  →  re-deriving the file wrapping key (cryptographic key custody)
        pbkdf2_salt = secrets.token_hex(32)

        # 4. Insert user — password never written to disk, only the hash
        cursor.execute(
            """
            INSERT INTO users (email, password_hash, pbkdf2_salt)
            VALUES (%s, %s, %s)
            """,
            (body.email, password_hash, pbkdf2_salt)
        )
        conn.commit()
        user_id = cursor.lastrowid

        # 5. Audit log
        cursor.execute(
            """
            INSERT INTO access_logs (user_id, doc_id, action, ip_address)
            VALUES (%s, NULL, 'REGISTER', %s)
            """,
            (user_id, request.client.host)
        )
        conn.commit()
        cursor.close()

    # Password string goes out of scope here — GC will collect it.
    # Python can't guarantee immediate RAM zeroing for str (immutable),
    # but we never log it, persist it, or pass it further.
    return {"message": "Account created", "user_id": user_id}


# ---------------------------------------------------------------------------
# POST /auth/login
# ---------------------------------------------------------------------------
@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest, request: Request):
    """
    Login flow:
      1. Fetch user row by email
      2. BCrypt verify password against stored hash
      3. Issue JWT (payload: user_id + expiry ONLY)
      4. Log LOGIN action
      5. Return token

    We always return the same 401 message whether the email doesn't exist
    or the password is wrong — this prevents user enumeration attacks
    (attacker can't tell which one failed).
    """
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT user_id, password_hash FROM users WHERE email = %s",
            (body.email,)
        )
        user = cursor.fetchone()
        cursor.close()

    # Generic error for both "email not found" and "wrong password"
    GENERIC_401 = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid email or password"
    )

    if not user:
        raise GENERIC_401

    # BCrypt verify — checkpw needs bytes on both sides
    password_matches = bcrypt.checkpw(
        body.password.encode("utf-8"),
        user["password_hash"].encode("utf-8")
    )
    if not password_matches:
        raise GENERIC_401

    # Issue JWT — payload contains user_id and expiry ONLY
    # Never put email, password, or document data in the JWT payload
    expiry = datetime.now(timezone.utc) + timedelta(hours=JWT_EXPIRY)
    token = jwt.encode(
        {"user_id": user["user_id"], "exp": expiry},
        JWT_SECRET,
        algorithm=JWT_ALG
    )

    # Audit log
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO access_logs (user_id, doc_id, action, ip_address)
            VALUES (%s, NULL, 'LOGIN', %s)
            """,
            (user["user_id"], request.client.host)
        )
        conn.commit()
        cursor.close()

    return {"access_token": token, "token_type": "bearer"}