"""
PrivaVault — Upload route
Phase 1-2 skeleton | branch: feature/auth-upload

What this file does NOW (Phase 1-2):
  - Double auth: JWT verify + BCrypt re-verify
  - Read file bytes into RAM
  - Write a stub record to the documents table
  - Audit log

What gets ADDED in later phases by plugging into the stubs below:
  Phase 3-5  →  Stream A: extractor.py + anonymizer.py + gemini.py
  Phase 6-7  →  Stream B: encryption.py + blob.py

The route's structure won't change — only the stub sections get filled in.
"""

import os
from datetime import datetime

import bcrypt
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db.connection import get_db
from routes.auth import verify_token

router   = APIRouter()
security = HTTPBearer()   # reads "Authorization: Bearer <token>" header


# ---------------------------------------------------------------------------
# POST /vault/upload
# ---------------------------------------------------------------------------
@router.post("/upload", status_code=status.HTTP_201_CREATED)
async def upload(
    request:     Request,
    file:        UploadFile                    = File(...),
    password:    str                           = Form(...),
    credentials: HTTPAuthorizationCredentials  = Depends(security),
):
    """
    Three inputs required:
      - file      (multipart) — the document being stored
      - password  (form field) — user's raw password for BCrypt re-verify + key derivation
      - JWT       (Authorization header) — proves the session is valid

    Both auth checks must pass before any data is touched.
    """

    # -----------------------------------------------------------------------
    # STEP 1 — JWT verification (extracts user_id from token)
    # -----------------------------------------------------------------------
    user_id = verify_token(credentials.credentials)
    # If the token is expired or tampered, verify_token raises 401 here.
    # We never reach Step 2 in that case.

    # -----------------------------------------------------------------------
    # STEP 2 — BCrypt re-verification (confirms the password is also correct)
    # -----------------------------------------------------------------------
    # Why verify BOTH? JWT alone proves "this session was valid when it was issued."
    # BCrypt re-verify proves "the person making THIS request knows the password RIGHT NOW."
    # This matters for key derivation — the password is needed to unwrap the Fernet key.
    # An attacker with a stolen JWT token but not the password cannot decrypt anything.
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT password_hash, pbkdf2_salt FROM users WHERE user_id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        cursor.close()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )

    pbkdf2_salt = user["pbkdf2_salt"]   # needed by Stream B for key wrapping

    # -----------------------------------------------------------------------
    # STEP 3 — Read file bytes into RAM
    # -----------------------------------------------------------------------
    # Using bytearray (mutable) so we can explicitly zero the buffer later.
    # Regular bytes objects are immutable — you can't overwrite them in place.
    raw_bytes = bytearray(await file.read())
    original_filename = file.filename

    # -----------------------------------------------------------------------
    # STREAM A — AI & Privacy (Phase 3-5)
    # Uncomment and import services when feature/ai_privacy_flow is ready.
    # -----------------------------------------------------------------------
    ai_summary = None   # placeholder until Gemini integration is wired in
    ai_tags    = []     # placeholder until Gemini integration is wired in

    # --- Phase 3-5 block (uncomment when services exist) ---
    # from services.extractor  import extract_text
    # from services.anonymizer import anonymize
    # from services.gemini     import get_summary_and_tags
    #
    # raw_text       = extract_text(bytes(raw_bytes))
    # sanitized_text = anonymize(raw_text)
    # gemini_result  = get_summary_and_tags(sanitized_text)
    # ai_summary     = gemini_result["summary"]
    # ai_tags        = gemini_result["tags"]
    # del sanitized_text, raw_text   # wipe from RAM

    # -----------------------------------------------------------------------
    # STREAM B — Encryption & Blob Storage (Phase 6-7)
    # Uncomment and import services when feature/encryption is ready.
    # -----------------------------------------------------------------------
    cloud_storage_url  = "PENDING"    # placeholder until blob.py is wired in
    encrypted_key_blob = b"PENDING"   # placeholder until encryption.py is wired in

    # --- Phase 6-7 block (uncomment when services exist) ---
    # from services.encryption import encrypt_file
    # from services.blob       import upload_to_blob
    #
    # ciphertext, encrypted_key_blob = encrypt_file(
    #     file_bytes=bytes(raw_bytes),
    #     password=password,
    #     pbkdf2_salt=pbkdf2_salt,
    # )
    # cloud_storage_url = upload_to_blob(ciphertext, original_filename)
    # del ciphertext   # wipe encrypted bytes from RAM after upload

    # -----------------------------------------------------------------------
    # STEP 4 — Commit to database (atomic — rolls back if anything above failed)
    # -----------------------------------------------------------------------
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor()

        # Insert into documents table
        cursor.execute(
            """
            INSERT INTO documents
              (user_id, original_filename, cloud_storage_url,
               ai_summary, encrypted_key_blob, upload_status)
            VALUES (%s, %s, %s, %s, %s, %s)
            """,
            (
                user_id,
                original_filename,
                cloud_storage_url,
                ai_summary,
                encrypted_key_blob,
                "processing",          # flipped to 'ready' once both streams complete
            )
        )
        doc_id = cursor.lastrowid

        # Insert AI tags — one row per tag (populated in Phase 3-5)
        for tag in ai_tags:
            cursor.execute(
                "INSERT INTO document_tags (doc_id, tag_name) VALUES (%s, %s)",
                (doc_id, tag)
            )

        # Audit log
        cursor.execute(
            """
            INSERT INTO access_logs (user_id, doc_id, action, ip_address)
            VALUES (%s, %s, 'UPLOAD', %s)
            """,
            (user_id, doc_id, request.client.host)
        )

        conn.commit()
        cursor.close()

    # -----------------------------------------------------------------------
    # STEP 5 — Wipe everything sensitive from RAM
    # -----------------------------------------------------------------------
    # Zero out the mutable bytearray before deleting it.
    # This is defense-in-depth — Python's GC is non-deterministic, so we
    # can't guarantee the memory is immediately reclaimed, but we can zero
    # the buffer while we still hold a reference to it.
    for i in range(len(raw_bytes)):
        raw_bytes[i] = 0
    del raw_bytes, password, pbkdf2_salt, encrypted_key_blob

    return {
        "message": "Upload successful",
        "doc_id": doc_id,
        "filename": original_filename,
        "status": "processing",
    }