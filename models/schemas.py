"""
PrivaVault — Pydantic request/response models
Phase 1-2 | branch: feature/auth-upload

All data shapes for the entire API live here.
Routes import from this file instead of defining inline models.

Fixed from friend's version:
  - @validator → @field_validator (Pydantic v2 syntax)
  - min_items/max_items → min_length/max_length on List fields
  - Removed EncryptionMetadata (internal service values, not HTTP models)
"""

from datetime import datetime
from typing import Optional, List

from pydantic import BaseModel, EmailStr, Field, field_validator


# ---------------------------------------------------------------------------
# Auth models
# ---------------------------------------------------------------------------
class RegisterRequest(BaseModel):
    """Payload for POST /auth/register"""
    email: EmailStr = Field(..., description="User's email address")
    password: str = Field(
        ...,
        min_length=8,
        description="Minimum 8 characters. Hashed with BCrypt (cost=12) before storage."
    )

class RegisterResponse(BaseModel):
    """Response from POST /auth/register"""
    message: str
    user_id: int = Field(..., description="Newly created user's ID")


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


# ---------------------------------------------------------------------------
# Upload models
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
# Document models
# ---------------------------------------------------------------------------
class DocumentTag(BaseModel):
    """A single tag associated with a document"""
    tag_id: Optional[int] = None
    tag_name: str = Field(..., description="Search keyword (e.g., 'Government ID')")

class DocumentInfo(BaseModel):
    """Complete document metadata (used in list/detail responses)"""
    doc_id: int
    user_id: int
    original_filename: str
    cloud_storage_url: str
    ai_summary: Optional[str] = None
    upload_status: str
    uploaded_at: datetime
    tags: List[DocumentTag] = Field(default_factory=list)

class DocumentListResponse(BaseModel):
    """Response from GET /vault/documents"""
    documents: List[DocumentInfo]
    total_count: int


# ---------------------------------------------------------------------------
# Download models (Phase 6-7)
# ---------------------------------------------------------------------------
class DocumentDownloadResponse(BaseModel):
    """
    Metadata response from GET /vault/download/{doc_id}.
    Actual file bytes come via FastAPI StreamingResponse, not JSON.
    """
    filename: str
    size_bytes: int
    message: str = Field(default="Download successful")


# ---------------------------------------------------------------------------
# Anonymizer models (Phase 3-5, services/anonymizer.py)
# ---------------------------------------------------------------------------
class PiiEntity(BaseModel):
    """Represents a single detected PII entity"""
    entity_type: str = Field(..., description="'PERSON', 'AADHAAR', 'PAN', 'PHONE_NUMBER'")
    text: str
    start: int
    end: int
    score: float = Field(..., description="Confidence score 0.0–1.0 from Presidio")

class AnonymizationResult(BaseModel):
    """Result of Presidio anonymization (Phase 3-5)"""
    sanitized_text: str
    entities_detected: List[PiiEntity] = Field(default_factory=list)
    placeholder_mapping: dict = Field(default_factory=dict)


# ---------------------------------------------------------------------------
# Gemini models (Phase 3-5, services/gemini.py)
# ---------------------------------------------------------------------------
class GeminiResponse(BaseModel):
    """Response structure expected back from Gemini"""
    summary: str = Field(..., description="2-sentence summary of document")
    tags: List[str] = Field(..., description="3-5 searchable category tags")

    # Pydantic v2 validator syntax — @field_validator + @classmethod
    @field_validator("tags")
    @classmethod
    def validate_tags(cls, v):
        if not isinstance(v, list):
            raise ValueError("tags must be a list")
        if len(v) < 3 or len(v) > 5:
            raise ValueError("tags must have between 3 and 5 elements")
        return v


# ---------------------------------------------------------------------------
# Access log models
# ---------------------------------------------------------------------------
class AccessLogEntry(BaseModel):
    """Single entry in access_logs table"""
    log_id: int
    user_id: int
    doc_id: Optional[int] = None    # NULL for REGISTER/LOGIN events
    action: str = Field(..., description="'REGISTER' | 'LOGIN' | 'UPLOAD' | 'DOWNLOAD'")
    ip_address: Optional[str] = None
    timestamp: datetime


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------
class HealthCheckResponse(BaseModel):
    status: str = Field(default="ok")
    service: str = Field(default="PrivaVault")


# ---------------------------------------------------------------------------
# Batch / search models (future phases)
# ---------------------------------------------------------------------------
class BatchTagRequest(BaseModel):
    doc_id: int
    tags: List[str] = Field(..., min_length=1, max_length=10)  # v2: min_length/max_length

class BatchDeleteRequest(BaseModel):
    doc_ids: List[int] = Field(..., min_length=1, max_length=100)  # v2: min_length/max_length
    reason: Optional[str] = None

class DocumentSearchQuery(BaseModel):
    query: str = Field(..., min_length=1, max_length=255)
    tag_filter: Optional[str] = None
    limit: int = Field(default=20, le=100)
    offset: int = Field(default=0, ge=0)