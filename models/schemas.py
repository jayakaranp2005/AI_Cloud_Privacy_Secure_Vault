"""
PrivaVault — Pydantic Models & Schemas
Phase 1-2 | branch: feature/auth-upload

Centralized request/response models for all routes and services.
Keeps auth.py, upload.py, download.py, and services clean and focused on logic.

All models align with the database schema in db/schema.sql and the
architecture documented in README.md.

Import these into routes like:
    from models.schemas import RegisterRequest, LoginResponse
"""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field, validator


# ---------------------------------------------------------------------------
# AUTH MODELS (routes/auth.py)
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    """Payload for POST /auth/register"""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(
        ...,
        min_length=8,
        description="Minimum 8 characters. Hashed with BCrypt (cost=12) before storage."
    )


class LoginRequest(BaseModel):
    """Payload for POST /auth/login"""
    email: EmailStr = Field(..., description="Registered email address")
    password: str = Field(..., description="Raw password (verified against BCrypt hash)")


class LoginResponse(BaseModel):
    """Response from POST /auth/login"""
    access_token: str = Field(..., description="JWT token (payload: user_id + expiry)")
    token_type: str = Field(
        default="bearer",
        description="Always 'bearer' for HTTP Authorization header"
    )


class RegisterResponse(BaseModel):
    """Response from POST /auth/register"""
    message: str
    user_id: int = Field(..., description="Newly created user's ID")


# ---------------------------------------------------------------------------
# UPLOAD MODELS (routes/upload.py)
# ---------------------------------------------------------------------------
class UploadResponse(BaseModel):
    """Response from POST /vault/upload"""
    message: str = Field(default="Upload successful")
    doc_id: int = Field(..., description="Document ID in database")
    filename: str = Field(..., description="Original filename as uploaded")
    status: str = Field(
        default="processing",
        description="'processing' = dual streams running, 'ready' = both complete"
    )


class AISummaryResult(BaseModel):
    """
    Structured result from Gemini API (Phase 3-5).
    Returned by services/gemini.py and stored in documents.ai_summary.
    """
    summary: str = Field(..., description="2-sentence document summary from Gemini")
    tags: List[str] = Field(default_factory=list, description="Searchable tags from Gemini")


# ---------------------------------------------------------------------------
# DOCUMENT MODELS (used in list/detail responses)
# ---------------------------------------------------------------------------
class DocumentTag(BaseModel):
    """A single tag associated with a document"""
    tag_id: Optional[int] = None
    tag_name: str = Field(..., description="Search keyword (e.g., 'Government ID')")


class DocumentInfo(BaseModel):
    """Complete document metadata (used in list/detail responses)"""
    doc_id: int = Field(..., description="Global document ID")
    user_id: int = Field(..., description="Owner's user ID")
    original_filename: str = Field(..., description="Original filename as uploaded")
    cloud_storage_url: str = Field(..., description="URL to encrypted blob in Azure")
    ai_summary: Optional[str] = Field(None, description="Two-sentence summary from Gemini")
    upload_status: str = Field(
        ...,
        description="'processing', 'ready', or 'failed'"
    )
    uploaded_at: datetime = Field(..., description="Timestamp of upload")
    tags: List[DocumentTag] = Field(default_factory=list, description="Associated tags")


class DocumentListResponse(BaseModel):
    """Response from GET /vault/documents (list all user's docs)"""
    documents: List[DocumentInfo] = Field(..., description="Array of user's documents")
    total_count: int = Field(..., description="Total number of documents")


class DocumentDownloadResponse(BaseModel):
    """
    Metadata response from GET /vault/download/{doc_id}.
    The actual file bytes are sent via StreamingResponse, not in JSON.
    """
    filename: str = Field(..., description="Original filename")
    size_bytes: int = Field(..., description="File size in bytes")
    message: str = Field(default="Download successful")


# ---------------------------------------------------------------------------
# HEALTH CHECK MODELS
# ---------------------------------------------------------------------------
class HealthCheckResponse(BaseModel):
    """Response from GET /health"""
    status: str = Field(default="ok")
    service: str = Field(default="PrivaVault")


# ---------------------------------------------------------------------------
# ERROR RESPONSE MODELS
# (FastAPI auto-generates these, but good to document for clarity)
# ---------------------------------------------------------------------------
class ErrorResponse(BaseModel):
    """Generic error response"""
    detail: str = Field(..., description="Error message describing what went wrong")


# ---------------------------------------------------------------------------
# ANONYMIZER MODELS (Phase 3-5, services/anonymizer.py)
# ---------------------------------------------------------------------------
class PiiEntity(BaseModel):
    """Represents a single detected PII entity"""
    entity_type: str = Field(
        ...,
        description="Type of PII (e.g., 'PERSON', 'AADHAAR', 'PAN', 'PHONE_NUMBER')"
    )
    text: str = Field(..., description="Original detected text")
    start: int = Field(..., description="Character offset in original text")
    end: int = Field(..., description="Character offset in original text")
    score: float = Field(..., description="Confidence score (0.0-1.0) from Presidio")


class AnonymizationResult(BaseModel):
    """Result of Presidio anonymization (Phase 3-5)"""
    sanitized_text: str = Field(..., description="Text with PII replaced by placeholders")
    entities_detected: List[PiiEntity] = Field(
        default_factory=list,
        description="List of PII entities found before anonymization"
    )
    placeholder_mapping: dict = Field(
        default_factory=dict,
        description="Mapping of placeholder IDs to entity counts (for reference)"
    )


# ---------------------------------------------------------------------------
# GEMINI MODELS (Phase 3-5, services/gemini.py)
# ---------------------------------------------------------------------------
class GeminiRequest(BaseModel):
    """Request payload for Gemini API (internal to services/gemini.py)"""
    anonymized_text: str = Field(..., description="Already-anonymized text (no PII)")


class GeminiResponse(BaseModel):
    """Response structure expected from Gemini 2.5 Flash API"""
    summary: str = Field(..., description="2-sentence summary of document")
    tags: List[str] = Field(..., description="3-5 searchable category tags")

    @validator('tags')
    def validate_tags(cls, v):
        """Ensure tags list has 3-5 elements"""
        if not isinstance(v, list):
            raise ValueError("tags must be a list")
        if len(v) < 3 or len(v) > 5:
            raise ValueError("tags must have between 3 and 5 elements")
        return v


# ---------------------------------------------------------------------------
# ENCRYPTION MODELS (Phase 6-7, services/encryption.py)
# ---------------------------------------------------------------------------
class EncryptionMetadata(BaseModel):
    """Metadata for encrypted file (for internal use)"""
    fernet_key_hex: Optional[str] = Field(
        None,
        description="Hex-encoded Fernet key (never persisted, only in RAM)"
    )
    pbkdf2_salt: str = Field(..., description="PBKDF2 salt from users table")
    wrapping_key_hex: Optional[str] = Field(
        None,
        description="Hex-encoded wrapping key (never persisted, only in RAM)"
    )


# ---------------------------------------------------------------------------
# ACCESS LOG MODELS (Phase 6-7, audit trail)
# ---------------------------------------------------------------------------
class AccessLogEntry(BaseModel):
    """Single entry in access_logs table"""
    log_id: int
    user_id: int
    doc_id: Optional[int] = None  # NULL for REGISTER/LOGIN events
    action: str = Field(
        ...,
        description="Action type: 'REGISTER', 'LOGIN', 'UPLOAD', 'DOWNLOAD'"
    )
    ip_address: Optional[str] = None
    timestamp: datetime


# ---------------------------------------------------------------------------
# BATCH OPERATION MODELS (Future — Phase 4+)
# ---------------------------------------------------------------------------
class BatchTagRequest(BaseModel):
    """Add multiple tags to a document at once (future)"""
    doc_id: int
    tags: List[str] = Field(..., min_items=1, max_items=10)


class BatchDeleteRequest(BaseModel):
    """Delete multiple documents at once (future)"""
    doc_ids: List[int] = Field(..., min_items=1, max_items=100)
    reason: Optional[str] = None  # For audit logging


# ---------------------------------------------------------------------------
# SEARCH & FILTER MODELS (Future — Phase 4+)
# ---------------------------------------------------------------------------
class DocumentSearchQuery(BaseModel):
    """Search documents by tag or summary text (future)"""
    query: str = Field(..., min_length=1, max_length=255)
    tag_filter: Optional[str] = None
    limit: int = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)
