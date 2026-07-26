"""
PrivaVault — Download route
Phase 6-7 | branch: feature/encryption

Responsibilities:
  - Verify JWT and re-check BCrypt password (double auth)
  - Confirm document ownership (prevents cross-user access)
  - Fetch encrypted ciphertext from Azure Blob Storage
  - Unwrap the Fernet key using PBKDF2-derived wrapping key
  - Decrypt ciphertext and stream original file bytes to the client
  - Write DOWNLOAD audit log
  - Wipe all sensitive data from RAM before returning

Security boundaries:
  - Raw password is only present in RAM during the request
  - The server never stores the raw Fernet key
  - The user can only download documents they own (403 on mismatch)
  - No Presidio, no Gemini — download is a fast path only
"""

import io

# pyrefly: ignore [missing-import]
import bcrypt
from cryptography.fernet import Fernet, InvalidToken
from typing import Optional
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
# pyrefly: ignore [missing-import]
from fastapi.responses import StreamingResponse
# pyrefly: ignore [missing-import]
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from db.connection import get_db
from routes.auth import verify_token
from services.blob import download_from_blob
from services.encryption import unwrap_file_key

router   = APIRouter()
security = HTTPBearer(auto_error=False)


# ---------------------------------------------------------------------------
# POST /vault/download/{doc_id}
# ---------------------------------------------------------------------------
@router.post("/download/{doc_id}")
def download_document(
    doc_id:      int,
    request:     Request,
    password:    str                          = Form(...),
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
):
    """
    Downloads an encrypted document after verifying identity and ownership.

    Flow:
      1. JWT verify → extract user_id
      2. BCrypt re-verify → confirm password is correct right now
      3. Ownership check → confirm doc belongs to this user
      4. Fetch encrypted_key_blob + cloud_storage_url from DB
      5. unwrap_file_key() → raw Fernet key
      6. download_from_blob() → ciphertext from Azure
      7. Fernet.decrypt(ciphertext) → original file bytes
      8. StreamingResponse → stream bytes to client
      9. Audit log DOWNLOAD
      10. Wipe ciphertext + Fernet key from RAM
    """

    # -----------------------------------------------------------------------
    # STEP 1 — JWT verification (header or cookie fallback)
    # -----------------------------------------------------------------------
    token = None
    if credentials and credentials.credentials:
        token = credentials.credentials
    elif request.cookies.get("access_token"):
        token = request.cookies["access_token"]
    else:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    user_id = verify_token(token)

    # -----------------------------------------------------------------------
    # STEP 2 — Fetch user + document in one DB trip
    # -----------------------------------------------------------------------
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)

        cursor.execute(
            "SELECT password_hash, pbkdf2_salt FROM users WHERE user_id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        cursor.execute(
            """
            SELECT doc_id, user_id, original_filename,
                   cloud_storage_url, encrypted_key_blob
            FROM documents
            WHERE doc_id = %s
            """,
            (doc_id,)
        )
        document = cursor.fetchone()
        cursor.close()

    # -----------------------------------------------------------------------
    # STEP 3 — Auth + ownership checks
    # Order matters:
    #   401 before 404 — don't reveal document existence to unauthed users
    #   403 after 404  — document must exist before ownership can be checked
    # -----------------------------------------------------------------------
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found"
        )

    if not bcrypt.checkpw(
        password.encode("utf-8"),
        user["password_hash"].encode("utf-8")
    ):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid password"
        )

    if not document:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Document not found"
        )

    if document["user_id"] != user_id:
        # This should never happen via normal use — only a crafted request
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You do not own this document"
        )

    # -----------------------------------------------------------------------
    # STEP 4 — Decrypt pipeline
    # Initialize to None so finally block doesn't NameError if something
    # fails before the assignment
    # -----------------------------------------------------------------------
    ciphertext = None
    fernet_key = None

    try:
        # Unwrap the Fernet key from the encrypted blob
        fernet_key = unwrap_file_key(
            encrypted_key_blob=document["encrypted_key_blob"],
            password=password,
            pbkdf2_salt=user["pbkdf2_salt"],
        )

        # Fetch ciphertext from Azure into RAM as mutable bytearray
        # (mutable so we can zero it in the finally block)
        ciphertext = bytearray(download_from_blob(document["cloud_storage_url"]))

        # Decrypt → original file bytes
        file_bytes = Fernet(fernet_key).decrypt(bytes(ciphertext))

    except InvalidToken:
        # Wrong password or tampered key blob / ciphertext
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Decryption failed — invalid password or corrupted key"
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Download pipeline failed: {e}"
        )
    finally:
        # Zero ciphertext buffer before GC collects it
        if ciphertext is not None:
            for i in range(len(ciphertext)):
                ciphertext[i] = 0
        # Del Fernet key reference — can't zero bytes (immutable) but remove ref
        if fernet_key is not None:
            del fernet_key

    # -----------------------------------------------------------------------
    # STEP 5 — Audit log
    # Written after successful decryption only
    # -----------------------------------------------------------------------
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor()
        cursor.execute(
            """
            INSERT INTO access_logs (user_id, doc_id, action, ip_address)
            VALUES (%s, %s, 'DOWNLOAD', %s)
            """,
            (user_id, doc_id, request.client.host)
        )
        conn.commit()
        cursor.close()

    # -----------------------------------------------------------------------
    # STEP 6 — Stream file to client
    # Content-Disposition tells the browser to download with the original
    # filename rather than display it inline
    # -----------------------------------------------------------------------
    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type="application/octet-stream",
        headers={
            "Content-Disposition":
                f'attachment; filename="{document["original_filename"]}"'
        },
        status_code=status.HTTP_200_OK,
    )