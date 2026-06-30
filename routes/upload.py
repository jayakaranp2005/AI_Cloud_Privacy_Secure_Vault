"""
PrivaVault — Upload route
Phase 3-5 | branch: feature/ai_privacy_flow

Stream A is now ACTIVE:
  extractor.py → anonymizer.py → gemini.py → summary + tags stored in DB

Stream B still stubbed (Phase 6-7):
  encryption.py + blob.py not yet wired in
  cloud_storage_url and encrypted_key_blob remain as PENDING placeholders
"""

import bcrypt
from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db.connection import get_db
from models.schemas import UploadResponse
from routes.auth import verify_token
from services.extractor import extract_text, validate_pdf
from services.anonymizer import anonymize
from services.gemini import get_summary_and_tags

router   = APIRouter()
security = HTTPBearer()


# ---------------------------------------------------------------------------
# POST /vault/upload
# ---------------------------------------------------------------------------
@router.post("/upload", status_code=status.HTTP_201_CREATED, response_model=UploadResponse)
async def upload(
    request:     Request,
    file:        UploadFile                   = File(...),
    password:    str                          = Form(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Three inputs required:
      - file      (multipart) — the document being stored
      - password  (form field) — raw password for BCrypt re-verify + key derivation
      - JWT       (Authorization header) — proves the session is valid

    Both auth checks must pass before any data is touched.
    Stream A runs fully. Stream B is stubbed until Phase 6-7.
    """

    # -----------------------------------------------------------------------
    # STEP 1 — JWT verification
    # -----------------------------------------------------------------------
    user_id = verify_token(credentials.credentials)

    # -----------------------------------------------------------------------
    # STEP 2 — BCrypt re-verification
    # -----------------------------------------------------------------------
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT password_hash, pbkdf2_salt FROM users WHERE user_id = %s",
            (user_id,)
        )
        user = cursor.fetchone()
        cursor.close()

    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )

    pbkdf2_salt = user["pbkdf2_salt"]

    # -----------------------------------------------------------------------
    # STEP 3 — Read file bytes into RAM
    # -----------------------------------------------------------------------
    raw_bytes         = bytearray(await file.read())
    original_filename = file.filename

    # Validate PDF before doing any heavy processing
    # Fails fast with a clean 400 rather than a cryptic extraction error
    if not validate_pdf(bytes(raw_bytes)):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or corrupted PDF file"
        )

    # -----------------------------------------------------------------------
    # STREAM A — AI & Privacy (Phase 3-5) — NOW ACTIVE
    #
    # Boundary rule enforced here:
    #   raw_text  → anonymizer  → sanitized_text  → gemini
    #   Gemini NEVER receives raw_text directly.
    # -----------------------------------------------------------------------
    ai_summary = None
    ai_tags    = []

    try:
        # 1. Extract raw text from PDF bytes
        raw_text = extract_text(bytes(raw_bytes))

        # 2. Detect + replace all PII with deterministic placeholders
        anonymize_result = anonymize(raw_text)
        sanitized_text   = anonymize_result["sanitized_text"]

        # 3. Send ONLY sanitized text to Gemini — zero raw PII crosses this line
        gemini_result = get_summary_and_tags(sanitized_text)
        ai_summary    = gemini_result["summary"]
        ai_tags       = gemini_result["tags"]

        # Wipe text strings from RAM as soon as we're done with them
        del sanitized_text, raw_text

    except ValueError as e:
        # PDF extraction failure — bad file, image-only scan, etc.
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=f"Could not process document: {e}"
        )
    except Exception as e:
        # Gemini API failure, Presidio crash, etc.
        # We raise 503 rather than silently storing a record with no AI metadata
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"AI processing failed: {e}"
        )

    # -----------------------------------------------------------------------
    # STREAM B — Encryption & Blob Storage (Phase 6-7) — STILL STUBBED
    # -----------------------------------------------------------------------
    cloud_storage_url  = "PENDING"
    encrypted_key_blob = b"PENDING"

    # --- Phase 6-7 block (uncomment when services/encryption.py + blob.py exist) ---
    # from services.encryption import encrypt_file
    # from services.blob       import upload_to_blob
    #
    # ciphertext, encrypted_key_blob = encrypt_file(
    #     file_bytes=bytes(raw_bytes),
    #     password=password,
    #     pbkdf2_salt=pbkdf2_salt,
    # )
    # cloud_storage_url = upload_to_blob(ciphertext, original_filename, user_id)
    # del ciphertext

    # -----------------------------------------------------------------------
    # STEP 4 — Atomic DB commit
    # Both streams must succeed before anything is written.
    # get_db rolls back automatically if an exception escapes.
    # -----------------------------------------------------------------------
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor()

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
                "processing",   # flipped to 'ready' once Stream B is also live
            )
        )
        doc_id = cursor.lastrowid

        # One row per tag in document_tags
        for tag in ai_tags:
            cursor.execute(
                "INSERT INTO document_tags (doc_id, tag_name) VALUES (%s, %s)",
                (doc_id, tag)
            )

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
    # STEP 5 — RAM wipe
    # -----------------------------------------------------------------------
    for i in range(len(raw_bytes)):
        raw_bytes[i] = 0
    del raw_bytes, password, pbkdf2_salt, encrypted_key_blob

    return {
        "message":  "Upload successful",
        "doc_id":   doc_id,
        "filename": original_filename,
        "status":   "processing",
    }