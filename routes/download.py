"""
PrivaVault — Download route
Phase 6-7 | branch: feature/encryption

Responsibilities:
  - Verify JWT and re-check BCrypt password
  - Confirm document ownership
  - Fetch encrypted ciphertext from Azure Blob Storage
  - Unwrap the Fernet key using PBKDF2-derived wrapping key
  - Decrypt ciphertext and stream original file bytes to the client
  - Write DOWNLOAD audit log

Security boundaries:
  - Raw password is only present in RAM during the request.
  - The server never stores the raw Fernet key.
  - The user can only download documents they own.
"""

import io

import bcrypt  # pyrefly: ignore [missing-import]
from fastapi import APIRouter, Depends, Form, HTTPException, Request, status
from fastapi.responses import StreamingResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer  # pyrefly: ignore [missing-import]
from cryptography.fernet import Fernet  # pyrefly: ignore [missing-import]

from db.connection import get_db
from routes.auth import verify_token
from services.blob import download_from_blob
from services.encryption import decrypt_file

router = APIRouter()
security = HTTPBearer()


# ---------------------------------------------------------------------------
# POST /vault/download/{doc_id}
# ---------------------------------------------------------------------------
@router.post("/download/{doc_id}")
def download_document(
    doc_id: int,
    request: Request,
    password: str = Form(...),
    credentials: HTTPAuthorizationCredentials = Depends(security),
):
    """
    Downloads an encrypted document after verifying identity and ownership.

    The password is accepted as a standard request parameter so the endpoint
    can be called from Postman or a browser form without placing secrets in
    the URL. The response body is streamed as the decrypted file bytes.
    """
    user_id = verify_token(credentials.credentials)

    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            "SELECT password_hash, pbkdf2_salt FROM users WHERE user_id = %s",
            (user_id,)
        )
        user = cursor.fetchone()

        cursor.execute(
            """
            SELECT doc_id, user_id, original_filename, cloud_storage_url, encrypted_key_blob
            FROM documents
            WHERE doc_id = %s
            """,
            (doc_id,)
        )
        document = cursor.fetchone()
        cursor.close()

    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found")

    if not bcrypt.checkpw(password.encode("utf-8"), user["password_hash"].encode("utf-8")):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")

    if not document:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Document not found")

    if document["user_id"] != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="You do not own this document")

    try:
        fernet_key = decrypt_file(
            encrypted_key_blob=document["encrypted_key_blob"],
            password=password,
            pbkdf2_salt=user["pbkdf2_salt"],
        )
        ciphertext = bytearray(download_from_blob(document["cloud_storage_url"]))
        file_bytes = Fernet(fernet_key).decrypt(bytes(ciphertext))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Download pipeline failed: {e}"
        )
    finally:
        try:
            for index in range(len(ciphertext)):
                ciphertext[index] = 0
        except Exception:
            pass
        try:
            del fernet_key
        except Exception:
            pass

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

    headers = {
        "Content-Disposition": f'attachment; filename="{document["original_filename"]}"'
    }

    return StreamingResponse(
        io.BytesIO(file_bytes),
        media_type="application/octet-stream",
        headers=headers,
        status_code=status.HTTP_200_OK,
    )
