"""
PrivaVault — Encryption Service
Phase 6-7 | branch: feature/encryption

Responsibilities:
  - Encrypt raw file bytes with a fresh Fernet key per file
  - Derive a wrapping key from password + PBKDF2 salt using PBKDF2-HMAC-SHA256
  - Wrap the Fernet key with the derived wrapping key
  - Unwrap the Fernet key later during download
  - Wipe sensitive key material from RAM as much as Python allows

Important implementation notes:
  - The Fernet key is unique per file.
  - The wrapping key is derived from the user's password and stored PBKDF2 salt.
  - The wrapping key never leaves RAM.
  - The wrapped Fernet key is what gets persisted in documents.encrypted_key_blob.
"""

import base64
from typing import Tuple

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


PBKDF2_ITERATIONS = 390_000
PBKDF2_KEY_LENGTH = 32


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _normalize_salt(pbkdf2_salt: str | bytes) -> bytes:
    """
    Normalize the PBKDF2 salt into raw bytes.

    The app stores pbkdf2_salt as a hex string in the users table.
    This helper also accepts raw bytes for flexibility in tests.
    """
    if isinstance(pbkdf2_salt, bytes):
        return pbkdf2_salt

    salt_text = pbkdf2_salt.strip()
    try:
        return bytes.fromhex(salt_text)
    except ValueError:
        # Fallback for any future non-hex storage format.
        return salt_text.encode("utf-8")


def _derive_wrapping_key(password: str, pbkdf2_salt: str | bytes) -> bytearray:
    """
    Derive a Fernet-compatible wrapping key from the user's password.

    Returns the derived key as a mutable bytearray so callers can zero it
    after use. Fernet expects a urlsafe-base64-encoded 32-byte key.
    """
    salt_bytes = _normalize_salt(pbkdf2_salt)
    password_bytes = password.encode("utf-8")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=PBKDF2_KEY_LENGTH,
        salt=salt_bytes,
        iterations=PBKDF2_ITERATIONS,
    )
    raw_key = kdf.derive(password_bytes)
    wrapping_key = bytearray(base64.urlsafe_b64encode(raw_key))

    # Best-effort wipe of transient local variables.
    # Python cannot guarantee zeroing immutable bytes objects, but we do
    # zero the mutable representation we hand back to the caller.
    del password_bytes, raw_key, salt_bytes
    return wrapping_key


def _fernet_from_key(key_material: bytes | bytearray) -> Fernet:
    """Build a Fernet instance from urlsafe-base64 key material."""
    return Fernet(bytes(key_material))


def _wipe_bytearray(buffer: bytearray | None) -> None:
    """Overwrite a mutable buffer in place before dropping the reference."""
    if buffer is None:
        return
    for index in range(len(buffer)):
        buffer[index] = 0


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def encrypt_file(file_bytes: bytes, password: str, pbkdf2_salt: str | bytes) -> Tuple[bytes, bytes]:
    """
    Encrypt raw file bytes and wrap the file key.

    Args:
        file_bytes: Raw file bytes to encrypt.
        password: User's raw password from the active request.
        pbkdf2_salt: User's stored PBKDF2 salt from the users table.

    Returns:
        (ciphertext, encrypted_key_blob)

    Flow:
      1. Generate a fresh Fernet key unique to this file
      2. Encrypt raw file bytes with that key -> ciphertext
      3. Derive a wrapping key from password + PBKDF2 salt
      4. Encrypt the Fernet key with the wrapping key -> encrypted_key_blob
      5. Wipe mutable key material from RAM as best as possible
    """
    fernet_key = bytearray(Fernet.generate_key())
    wrapping_key = None

    try:
        file_fernet = _fernet_from_key(fernet_key)
        ciphertext = file_fernet.encrypt(file_bytes)

        wrapping_key = _derive_wrapping_key(password, pbkdf2_salt)
        key_wrapper = _fernet_from_key(wrapping_key)
        encrypted_key_blob = key_wrapper.encrypt(bytes(fernet_key))

        return ciphertext, encrypted_key_blob
    finally:
        _wipe_bytearray(fernet_key)
        _wipe_bytearray(wrapping_key)
        del fernet_key, wrapping_key


def decrypt_file(encrypted_key_blob: bytes, password: str, pbkdf2_salt: str | bytes) -> bytes:
    """
    Unwrap the Fernet key used to encrypt a file.

    Args:
        encrypted_key_blob: Wrapped Fernet key from documents.encrypted_key_blob.
        password: User's raw password from the active request.
        pbkdf2_salt: User's stored PBKDF2 salt from the users table.

    Returns:
        bytes: The decrypted Fernet key material suitable for Fernet(...).

    Flow:
      1. Re-derive the wrapping key from password + PBKDF2 salt
      2. Decrypt encrypted_key_blob -> original Fernet key
      3. Wipe the wrapping key from RAM
    """
    wrapping_key = None

    try:
        wrapping_key = _derive_wrapping_key(password, pbkdf2_salt)
        key_unwrapper = _fernet_from_key(wrapping_key)
        fernet_key = key_unwrapper.decrypt(encrypted_key_blob)
        return fernet_key
    finally:
        _wipe_bytearray(wrapping_key)
        del wrapping_key


print("[PrivaVault] Encryption service initialized.")
