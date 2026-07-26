"""
PrivaVault — Page-serving routes + document list API
Phase 8 | branch: feature/frontend

Responsibilities:
  - Serve HTML pages via Jinja2 templates (login, register, dashboard, upload)
  - GET /vault/documents — JSON endpoint for dashboard search
  - Cookie-based auth: read JWT from httpOnly cookie
"""

from fastapi import APIRouter, HTTPException, Query, Request, status
# pyrefly: ignore [missing-import]
from fastapi.responses import HTMLResponse, RedirectResponse
# pyrefly: ignore [missing-import]
from fastapi.templating import Jinja2Templates
from typing import List, Optional

from db.connection import get_db
from routes.auth import verify_token

router = APIRouter()
templates = Jinja2Templates(directory="templates")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _get_user_id_from_cookie(request: Request) -> Optional[int]:
    """
    Reads the access_token cookie and returns user_id if valid.
    Returns None if no cookie or token is invalid/expired.
    """
    token = request.cookies.get("access_token")
    if not token:
        return None
    try:
        return verify_token(token)
    except HTTPException:
        return None


def _get_user_email(request: Request, user_id: int) -> str:
    """Fetch user email by user_id."""
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute("SELECT email FROM users WHERE user_id = %s", (user_id,))
        row = cursor.fetchone()
        cursor.close()
    return row["email"] if row else "Unknown"


def _get_all_tags(request: Request, user_id: int) -> List[str]:
    """Fetch all unique tags for the user's documents."""
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)
        cursor.execute(
            """
            SELECT DISTINCT dt.tag_name
            FROM document_tags dt
            JOIN documents d ON dt.doc_id = d.doc_id
            WHERE d.user_id = %s
            ORDER BY dt.tag_name
            """,
            (user_id,)
        )
        tags = [row["tag_name"] for row in cursor.fetchall()]
        cursor.close()
    return tags


def _get_documents(request: Request, user_id: int, query: str = ""):
    """
    Fetch user's documents with tags from DB.
    query can be comma-separated tag names for multi-tag filtering.
    """
    with get_db(request.app.state.db_pool) as conn:
        cursor = conn.cursor(dictionary=True)

        # Parse comma-separated tags
        tag_list = [t.strip() for t in query.split(",") if t.strip()] if query else []

        if tag_list:
            # Filter documents that have ALL specified tags
            placeholders = ",".join(["%s"] * len(tag_list))
            cursor.execute(
                f"""
                SELECT d.doc_id, d.original_filename, d.ai_summary,
                       d.upload_status, d.uploaded_at
                FROM documents d
                JOIN document_tags dt ON d.doc_id = dt.doc_id
                WHERE d.user_id = %s AND dt.tag_name IN ({placeholders})
                GROUP BY d.doc_id
                HAVING COUNT(DISTINCT dt.tag_name) = %s
                ORDER BY d.uploaded_at DESC
                """,
                (user_id, *tag_list, len(tag_list))
            )
        else:
            cursor.execute(
                """
                SELECT doc_id, original_filename, ai_summary,
                       upload_status, uploaded_at
                FROM documents
                WHERE user_id = %s
                ORDER BY uploaded_at DESC
                """,
                (user_id,)
            )
        documents = cursor.fetchall()

        # Fetch tags for each document
        for doc in documents:
            cursor.execute(
                "SELECT tag_name FROM document_tags WHERE doc_id = %s",
                (doc["doc_id"],)
            )
            doc["tags"] = [row["tag_name"] for row in cursor.fetchall()]

        cursor.close()

    return documents


# ---------------------------------------------------------------------------
# Page routes
# ---------------------------------------------------------------------------
@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    """Render login page. Redirect to dashboard if already authenticated."""
    user_id = _get_user_id_from_cookie(request)
    if user_id:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "login.html")


@router.get("/register", response_class=HTMLResponse)
def register_page(request: Request):
    """Render registration page."""
    user_id = _get_user_id_from_cookie(request)
    if user_id:
        return RedirectResponse(url="/dashboard", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "register.html")


@router.get("/dashboard", response_class=HTMLResponse)
def dashboard_page(request: Request, q: str = Query(default="")):
    """
    Render dashboard with user's documents.
    Redirects to /login if not authenticated.
    """
    user_id = _get_user_id_from_cookie(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)

    email = _get_user_email(request, user_id)
    documents = _get_documents(request, user_id, query=q)
    all_tags = _get_all_tags(request, user_id)
    selected_tags = [t.strip() for t in q.split(",") if t.strip()] if q else []

    return templates.TemplateResponse(request, "dashboard.html", {
        "documents": documents,
        "user_email": email,
        "search_query": q,
        "all_tags": all_tags,
        "selected_tags": selected_tags,
    })


@router.get("/upload", response_class=HTMLResponse)
def upload_page(request: Request):
    """Render upload page. Requires authentication."""
    user_id = _get_user_id_from_cookie(request)
    if not user_id:
        return RedirectResponse(url="/login", status_code=status.HTTP_303_SEE_OTHER)
    return templates.TemplateResponse(request, "upload.html")


# ---------------------------------------------------------------------------
# JSON API — document list (for search)
# ---------------------------------------------------------------------------
@router.get("/vault/documents")
def list_documents(request: Request, q: str = Query(default="")):
    """
    Returns user's documents as JSON.
    Used by search bar fetch() on the dashboard.
    """
    user_id = _get_user_id_from_cookie(request)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )

    documents = _get_documents(request, user_id, query=q)
    return {"documents": documents, "total_count": len(documents)}


@router.get("/vault/tags")
def list_tags(request: Request):
    """
    Returns all unique tags for the authenticated user.
    Used by the tag autocomplete on the dashboard.
    """
    user_id = _get_user_id_from_cookie(request)
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Not authenticated"
        )
    tags = _get_all_tags(request, user_id)
    return {"tags": tags}
